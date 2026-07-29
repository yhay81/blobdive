use std::{
    error::Error,
    fs,
    io::{self, Cursor, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use flate2::{write::GzEncoder, Compression, GzBuilder};
use serde_json::Value;
use tempfile::TempDir;
use zip::{write::SimpleFileOptions, ZipWriter};

type TestResult = Result<(), Box<dyn Error>>;

fn binary() -> PathBuf {
    assert_cmd::cargo::cargo_bin!("blobdive").to_path_buf()
}

fn invoke(args: &[&str]) -> io::Result<Output> {
    Command::new(binary()).args(args).output()
}

fn success_json(args: &[&str]) -> Result<Value, Box<dyn Error>> {
    let output = invoke(args)?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "command failed with {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
        .into());
    }
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn assert_resource_error(output: &Output, reason: &str) -> TestResult {
    assert_eq!(output.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "resource_budget");
    assert!(error["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains(reason)));
    Ok(())
}

fn assert_zip_payload_rejected(source: &Path, expected_message: &str) -> TestResult {
    let result = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(source)?,
        "--depth",
        "1",
    ])?;
    let child = &result["root"]["children"][0];
    assert!(child["digest"].is_null());
    assert_eq!(child["truncation"]["reasons"][0], "adapter_failure");
    assert_eq!(child["findings"][0]["code"], "entry_read_failed");
    assert!(child["findings"][0]["message"]
        .as_str()
        .is_some_and(|message| message.contains(expected_message)));

    let child_ref = child["ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("rejected ZIP child ref missing"))?;
    let read = invoke(&["--format", "json", "read", path_text(source)?, child_ref])?;
    assert_eq!(read.status.code(), Some(1));
    let error: Value = serde_json::from_slice(&read.stderr)?;
    assert_eq!(error["error"]["kind"], "archive");
    assert!(error["error"]["message"]
        .as_str()
        .is_some_and(|message| message.contains(expected_message)));
    Ok(())
}

fn zip_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, data) in entries {
        writer.start_file(*name, options)?;
        writer.write_all(data)?;
    }
    Ok(writer.finish()?.into_inner())
}

fn patch_zip_u32(
    bytes: &mut [u8],
    signature: [u8; 4],
    field_offset: usize,
    value: u32,
) -> TestResult {
    let header_offset = bytes
        .windows(signature.len())
        .position(|candidate| candidate == signature)
        .ok_or_else(|| io::Error::other("ZIP header signature missing"))?;
    let field_start = header_offset.saturating_add(field_offset);
    let field = bytes
        .get_mut(field_start..field_start.saturating_add(4))
        .ok_or_else(|| io::Error::other("ZIP header field missing"))?;
    field.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn tar_bytes(name: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    tar_entries_bytes(&[(name, data)])
}

fn tar_entries_bytes(entries: &[(&str, &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, data) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(u64::try_from(data.len())?);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, *name, *data)?;
    }
    Ok(builder.into_inner()?)
}

fn gzip_bytes(name: &str, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let encoder = GzBuilder::new()
        .filename(name)
        .write(Vec::new(), Compression::default());
    finish_gzip(encoder, data)
}

fn finish_gzip(mut encoder: GzEncoder<Vec<u8>>, data: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn write_fixture(directory: &Path, name: &str, data: &[u8]) -> Result<PathBuf, Box<dyn Error>> {
    let path = directory.join(name);
    fs::write(&path, data)?;
    Ok(path)
}

struct NestedReferenceFixture {
    _temp: TempDir,
    source: PathBuf,
    inner_ref: String,
    payload_ref: String,
}

fn nested_reference_fixture() -> Result<NestedReferenceFixture, Box<dyn Error>> {
    let temp = TempDir::new()?;
    let inner = zip_bytes(&[("payload.txt", b"bounded reference payload")])?;
    let outer = zip_bytes(&[("inner.zip", &inner)])?;
    let source = write_fixture(temp.path(), "nested-budgets.zip", &outer)?;
    let inspected = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--depth",
        "2",
    ])?;
    let inner_ref = inspected["root"]["children"][0]["ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("inner ref missing"))?
        .to_owned();
    let payload_ref = inspected["root"]["children"][0]["children"][0]["ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("payload ref missing"))?
        .to_owned();
    Ok(NestedReferenceFixture {
        _temp: temp,
        source,
        inner_ref,
        payload_ref,
    })
}

#[test]
fn schemas_completions_and_usage_contract_are_stable() -> TestResult {
    for document in [
        "brief", "detect", "inspect", "list", "read", "adapters", "error",
    ] {
        let value = success_json(&["--format", "json", "schema", "--document", document])?;
        if document == "brief" {
            assert_eq!(value["schema_version"], "blobdive.brief.v1");
            assert_eq!(value["blobdive_version"], env!("CARGO_PKG_VERSION"));
        } else {
            assert!(value["$schema"].is_string());
        }
    }
    for shell in ["bash", "elvish", "fish", "powershell", "zsh"] {
        let output = invoke(&["completions", shell])?;
        assert!(output.status.success());
        assert!(!output.stdout.is_empty());
    }
    let usage = invoke(&["inspect"])?;
    assert_eq!(usage.status.code(), Some(2));
    Ok(())
}

#[test]
fn detection_ignores_extensions_and_source_limit_is_structured() -> TestResult {
    let temp = TempDir::new()?;
    let source = write_fixture(temp.path(), "not-a-database.bin", b"SQLite format 3\0rest")?;
    let result = success_json(&["--format", "json", "detect", path_text(&source)?])?;
    assert_eq!(result["detection"]["format"], "sqlite");
    assert_eq!(result["detection"]["confidence"], 1.0);

    let output = invoke(&[
        "--format",
        "json",
        "detect",
        path_text(&source)?,
        "--max-source-bytes",
        "4",
    ])?;
    assert_eq!(output.status.code(), Some(3));
    let error: Value = serde_json::from_slice(&output.stderr)?;
    assert_eq!(error["error"]["kind"], "source_budget");
    assert_eq!(error["error"]["exit_code"], 3);
    Ok(())
}

#[test]
fn zip_inspection_reports_unsafe_paths_without_materializing_them() -> TestResult {
    let temp = TempDir::new()?;
    let archive = zip_bytes(&[
        ("safe/manifest.txt", b"name=blobdive"),
        ("../escape.txt", b"must never materialize"),
    ])?;
    let source = write_fixture(temp.path(), "sample.data", &archive)?;
    let result = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--depth",
        "1",
    ])?;
    assert_eq!(result["root"]["format"], "zip");
    assert_eq!(result["root"]["children"].as_array().map(Vec::len), Some(2));
    assert_eq!(
        result["root"]["children"][1]["attributes"]["zip"]["unsafe_path"],
        true
    );
    assert_eq!(
        result["root"]["children"][1]["findings"][0]["code"],
        "unsafe_archive_path"
    );
    assert!(!temp.path().join("escape.txt").exists());
    Ok(())
}

#[test]
fn human_output_escapes_archive_control_characters() -> TestResult {
    let temp = TempDir::new()?;
    let archive = zip_bytes(&[("evil\n\u{1b}[31m.txt", b"content")])?;
    let source = write_fixture(temp.path(), "controls.zip", &archive)?;
    let output = invoke(&["inspect", path_text(&source)?])?;
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains(r"evil\n\u{1b}[31m.txt"));
    assert!(!stdout.contains('\u{1b}'));
    Ok(())
}

#[test]
fn entry_depth_timeout_and_output_budgets_are_explicit() -> TestResult {
    let temp = TempDir::new()?;
    let names = (0..40)
        .map(|index| format!("entry-{index:03}-with-a-deliberately-long-name.txt"))
        .collect::<Vec<_>>();
    let entries = names
        .iter()
        .map(|name| (name.as_str(), b"content".as_slice()))
        .collect::<Vec<_>>();
    let archive = zip_bytes(&entries)?;
    let source = write_fixture(temp.path(), "many.zip", &archive)?;

    let limited = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--max-entries",
        "3",
    ])?;
    assert_eq!(limited["usage"]["entries_visited"], 3);
    assert_eq!(limited["root"]["truncation"]["reasons"][0], "max_entries");

    let timed = invoke(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--timeout",
        "0ms",
    ])?;
    assert_eq!(timed.status.code(), Some(3));
    let timed_error: Value = serde_json::from_slice(&timed.stderr)?;
    assert_eq!(timed_error["error"]["kind"], "timeout");

    let output_limited = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--max-output-bytes",
        "5000",
    ])?;
    assert!(output_limited["root"]["truncation"]["reasons"]
        .as_array()
        .is_some_and(|reasons| reasons.iter().any(|reason| reason == "max_output_bytes")));
    assert!(
        output_limited["root"]["children"]
            .as_array()
            .map(Vec::len)
            .unwrap_or_default()
            < 40
    );
    Ok(())
}

#[test]
fn compression_ratio_preflight_blocks_zip_bombs() -> TestResult {
    let temp = TempDir::new()?;
    let expanded = vec![0_u8; 128 * 1024];
    let archive = zip_bytes(&[("zeros.bin", &expanded)])?;
    let source = write_fixture(temp.path(), "ratio.zip", &archive)?;
    let result = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--max-compression-ratio",
        "2",
    ])?;
    assert_eq!(result["usage"]["decompressed_bytes"], 0);
    assert_eq!(
        result["root"]["children"][0]["truncation"]["reasons"][0],
        "max_compression_ratio"
    );
    assert_eq!(
        result["root"]["children"][0]["findings"][0]["code"],
        "compression_ratio_exceeded"
    );
    Ok(())
}

#[test]
fn zip_payload_integrity_is_verified_before_digest_or_read() -> TestResult {
    let temp = TempDir::new()?;
    let payload = b"integrity payload".repeat(64);

    let mut bad_crc = zip_bytes(&[("payload.txt", &payload)])?;
    // Local-file and central-directory CRC-32 fields.
    patch_zip_u32(&mut bad_crc, *b"PK\x03\x04", 14, 0)?;
    patch_zip_u32(&mut bad_crc, *b"PK\x01\x02", 16, 0)?;
    let bad_crc_source = write_fixture(temp.path(), "bad-crc.zip", &bad_crc)?;
    assert_zip_payload_rejected(&bad_crc_source, "Invalid checksum")?;

    let mut underdeclared = zip_bytes(&[("payload.txt", &payload)])?;
    // Local-file and central-directory uncompressed-size fields.
    patch_zip_u32(&mut underdeclared, *b"PK\x03\x04", 22, 1)?;
    patch_zip_u32(&mut underdeclared, *b"PK\x01\x02", 24, 1)?;
    let underdeclared_source = write_fixture(temp.path(), "underdeclared.zip", &underdeclared)?;
    assert_zip_payload_rejected(&underdeclared_source, "declared uncompressed size")?;
    Ok(())
}

#[test]
fn gzip_payload_at_the_exact_decompression_limit_is_complete() -> TestResult {
    let temp = TempDir::new()?;
    let payload = vec![b'B'; 1024];
    let gzip = gzip_bytes("exact.txt", &payload)?;
    let source = write_fixture(temp.path(), "exact.gz", &gzip)?;
    let result = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--depth",
        "1",
        "--max-decompressed-bytes",
        "1024",
        "--max-compression-ratio",
        "1000",
    ])?;
    let child = &result["root"]["children"][0];
    assert_eq!(child["size"], 1024);
    assert!(child["digest"].is_string());
    assert_eq!(child["format"], "text");
    assert_eq!(child["truncation"]["truncated"], false);
    assert_eq!(result["usage"]["decompressed_bytes"], 1024);

    let child_ref = child["ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("exact-limit GZIP child ref missing"))?;
    let read = success_json(&[
        "--format",
        "json",
        "read",
        path_text(&source)?,
        child_ref,
        "--max-decompressed-bytes",
        "1024",
        "--max-compression-ratio",
        "1000",
    ])?;
    assert_eq!(read["returned_bytes"], 1024);
    assert_eq!(read["total_bytes"], 1024);
    assert_eq!(read["truncated"], false);
    assert!(read["content_sha256"].is_string());
    assert_eq!(
        BASE64.decode(read["data"].as_str().unwrap_or_default())?,
        payload
    );
    Ok(())
}

#[test]
fn nested_references_are_deterministic_readable_and_integrity_checked() -> TestResult {
    let temp = TempDir::new()?;
    let inner = zip_bytes(&[("manifest.txt", b"nested payload")])?;
    let outer = zip_bytes(&[("inner.zip", &inner)])?;
    let source = write_fixture(temp.path(), "nested.zip", &outer)?;
    let inspected = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--depth",
        "2",
    ])?;
    let child_ref = inspected["root"]["children"][0]["children"][0]["ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("nested ref missing"))?
        .to_owned();
    assert!(child_ref.ends_with("/zip/00000000/zip/00000000"));

    let read = success_json(&["--format", "json", "read", path_text(&source)?, &child_ref])?;
    assert_eq!(
        BASE64.decode(read["data"].as_str().unwrap_or_default())?,
        b"nested payload"
    );
    assert_eq!(read["truncated"], false);
    assert!(read["content_sha256"].is_string());
    assert_eq!(read["usage"]["entries_visited"], 2);

    fs::write(&source, b"changed after reference creation")?;
    let stale = invoke(&["--format", "json", "read", path_text(&source)?, &child_ref])?;
    assert_eq!(stale.status.code(), Some(5));
    let error: Value = serde_json::from_slice(&stale.stderr)?;
    assert_eq!(error["error"]["kind"], "integrity");
    Ok(())
}

#[test]
fn reference_resolution_enforces_depth_and_shared_entry_budgets() -> TestResult {
    let fixture = nested_reference_fixture()?;

    let direct_entry_limited = invoke(&[
        "--format",
        "json",
        "read",
        path_text(&fixture.source)?,
        &fixture.inner_ref,
        "--depth",
        "1",
        "--max-entries",
        "0",
    ])?;
    assert_resource_error(&direct_entry_limited, "max_entries")?;

    let depth_limited = invoke(&[
        "--format",
        "json",
        "read",
        path_text(&fixture.source)?,
        &fixture.payload_ref,
        "--depth",
        "1",
    ])?;
    assert_resource_error(&depth_limited, "max_depth")?;

    let entry_limited = invoke(&[
        "--format",
        "json",
        "read",
        path_text(&fixture.source)?,
        &fixture.payload_ref,
        "--depth",
        "2",
        "--max-entries",
        "1",
    ])?;
    assert_resource_error(&entry_limited, "max_entries")?;

    let read = success_json(&[
        "--format",
        "json",
        "read",
        path_text(&fixture.source)?,
        &fixture.payload_ref,
        "--depth",
        "2",
        "--max-entries",
        "2",
    ])?;
    assert_eq!(read["usage"]["entries_visited"], 2);
    assert_eq!(
        BASE64.decode(read["data"].as_str().unwrap_or_default())?,
        b"bounded reference payload"
    );
    Ok(())
}

#[test]
fn list_reference_uses_depth_and_remaining_entry_budgets() -> TestResult {
    let fixture = nested_reference_fixture()?;
    let list_depth_limited = invoke(&[
        "--format",
        "json",
        "list",
        path_text(&fixture.source)?,
        &fixture.inner_ref,
        "--depth",
        "0",
    ])?;
    assert_resource_error(&list_depth_limited, "max_depth")?;

    let listed = success_json(&[
        "--format",
        "json",
        "list",
        path_text(&fixture.source)?,
        &fixture.inner_ref,
        "--depth",
        "1",
        "--max-entries",
        "2",
    ])?;
    assert_eq!(listed["children"].as_array().map(Vec::len), Some(1));
    assert_eq!(listed["usage"]["entries_visited"], 2);
    Ok(())
}

#[test]
fn tar_reference_resolution_counts_every_scanned_entry() -> TestResult {
    let temp = TempDir::new()?;
    let archive = tar_entries_bytes(&[
        ("zero.txt", b"zero"),
        ("one.txt", b"one"),
        ("two.txt", b"two"),
    ])?;
    let source = write_fixture(temp.path(), "indexed.tar", &archive)?;
    let inspected = success_json(&[
        "--format",
        "json",
        "inspect",
        path_text(&source)?,
        "--depth",
        "1",
    ])?;
    let third_ref = inspected["root"]["children"][2]["ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("third TAR ref missing"))?;

    let limited = invoke(&[
        "--format",
        "json",
        "read",
        path_text(&source)?,
        third_ref,
        "--depth",
        "1",
        "--max-entries",
        "2",
    ])?;
    assert_resource_error(&limited, "max_entries")?;

    let read = success_json(&[
        "--format",
        "json",
        "read",
        path_text(&source)?,
        third_ref,
        "--depth",
        "1",
        "--max-entries",
        "3",
    ])?;
    assert_eq!(read["usage"]["entries_visited"], 3);
    assert_eq!(
        BASE64.decode(read["data"].as_str().unwrap_or_default())?,
        b"two"
    );
    Ok(())
}

#[test]
fn list_and_bounded_root_read_use_the_same_reference_contract() -> TestResult {
    let temp = TempDir::new()?;
    let archive = zip_bytes(&[("one.txt", b"one"), ("two.txt", b"two")])?;
    let source = write_fixture(temp.path(), "list.zip", &archive)?;
    let inspected = success_json(&["--format", "json", "inspect", path_text(&source)?])?;
    let root_ref = inspected["root"]["ref"]
        .as_str()
        .ok_or_else(|| io::Error::other("root ref missing"))?;

    let listed = success_json(&["--format", "json", "list", path_text(&source)?, root_ref])?;
    assert_eq!(listed["children"].as_array().map(Vec::len), Some(2));

    let read = success_json(&[
        "--format",
        "json",
        "read",
        path_text(&source)?,
        root_ref,
        "--max-bytes",
        "4",
    ])?;
    assert_eq!(read["returned_bytes"], 4);
    assert_eq!(read["truncated"], true);
    assert!(read["content_sha256"].is_null());
    Ok(())
}

#[test]
fn tar_and_gzip_adapters_recurse_without_extraction() -> TestResult {
    let temp = TempDir::new()?;
    let tar = tar_bytes("hello.txt", b"hello tar")?;
    let tar_source = write_fixture(temp.path(), "archive.bin", &tar)?;
    let tar_result = success_json(&["--format", "json", "inspect", path_text(&tar_source)?])?;
    assert_eq!(tar_result["root"]["format"], "tar");
    assert_eq!(tar_result["root"]["children"][0]["format"], "text");

    let gzip = gzip_bytes("payload.txt", b"hello gzip")?;
    let gzip_source = write_fixture(temp.path(), "compressed.bin", &gzip)?;
    let gzip_result = success_json(&["--format", "json", "inspect", path_text(&gzip_source)?])?;
    assert_eq!(gzip_result["root"]["format"], "gzip");
    assert_eq!(gzip_result["root"]["children"][0]["format"], "text");
    assert_eq!(
        gzip_result["root"]["children"][0]["display_name"],
        "payload.txt"
    );
    Ok(())
}

#[test]
fn malformed_archive_failure_is_contained_in_the_result() -> TestResult {
    let temp = TempDir::new()?;
    let source = write_fixture(temp.path(), "broken.zip", b"PK\x03\x04broken")?;
    let result = success_json(&["--format", "json", "inspect", path_text(&source)?])?;
    assert_eq!(result["root"]["format"], "zip");
    assert_eq!(result["root"]["findings"][0]["code"], "adapter_failure");
    assert_eq!(
        result["root"]["truncation"]["reasons"][0],
        "adapter_failure"
    );
    Ok(())
}

fn path_text(path: &Path) -> Result<&str, Box<dyn Error>> {
    path.to_str()
        .ok_or_else(|| io::Error::other("fixture path is not UTF-8").into())
}
