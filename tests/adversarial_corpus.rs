use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fs,
    io::{self, Cursor, Read, Write},
    path::{Path, PathBuf},
};

use blobdive::{
    engine::{inspect_source, read_reference, InspectOptions, ReadOptions},
    error::BlobError,
    model::{ArtifactNode, BudgetLimits, TruncationReason},
    reference::sha256_hex,
};
use serde::Deserialize;
use serde_json::Value;
use tempfile::TempDir;
use zip::{write::SimpleFileOptions, ZipWriter};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Corpus {
    schema_version: String,
    license: String,
    generator: String,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    id: String,
    category: String,
    operation: String,
    variant: usize,
    expected: Expected,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    code: String,
    materialized_paths: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metrics {
    schema_version: String,
    corpus_sha256: String,
    total_cases: usize,
    detected_cases: usize,
    detection_rate: f64,
    materialized_paths: usize,
    by_category: BTreeMap<String, CategoryMetrics>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CategoryMetrics {
    cases: usize,
    detected_cases: usize,
    detection_rate: f64,
    materialized_paths: usize,
}

#[derive(Debug, Default)]
struct ActualCategory {
    cases: usize,
    detected_cases: usize,
    materialized_paths: usize,
}

struct Outcome {
    code: String,
    materialized_paths: usize,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/adversarial/v0.1")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> TestResult<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn default_limits() -> BudgetLimits {
    BudgetLimits {
        max_depth: 16,
        max_entries: 200,
        max_source_bytes: 67_108_864,
        max_decompressed_bytes: 67_108_864,
        max_compression_ratio: 1_000_000,
        max_output_bytes: 16_777_216,
        timeout_ms: 10_000,
    }
}

fn inspect(path: &Path, limits: BudgetLimits) -> TestResult<blobdive::model::InspectResult> {
    Ok(inspect_source(path, &InspectOptions { limits })?)
}

fn zip_bytes(entries: &[(String, Vec<u8>)]) -> TestResult<Vec<u8>> {
    let cursor = Cursor::new(Vec::new());
    let mut writer = ZipWriter::new(cursor);
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    for (name, payload) in entries {
        writer.start_file(name, options)?;
        writer.write_all(payload)?;
    }
    Ok(writer.finish()?.into_inner())
}

fn crc32_update(crc: u32, byte: u8) -> u32 {
    let mut entry = (crc ^ u32::from(byte)) & 0xff;
    for _ in 0..8 {
        entry = if entry & 1 == 0 {
            entry >> 1
        } else {
            (entry >> 1) ^ 0xedb8_8320
        };
    }
    entry ^ (crc >> 8)
}

fn crc32(bytes: &[u8]) -> u32 {
    !bytes
        .iter()
        .fold(!0_u32, |crc, byte| crc32_update(crc, *byte))
}

struct ZipCrypto {
    key0: u32,
    key1: u32,
    key2: u32,
}

impl ZipCrypto {
    fn new(password: &[u8]) -> Self {
        let mut keys = Self {
            key0: 0x1234_5678,
            key1: 0x2345_6789,
            key2: 0x3456_7890,
        };
        for byte in password {
            keys.update(*byte);
        }
        keys
    }

    fn update(&mut self, byte: u8) {
        self.key0 = crc32_update(self.key0, byte);
        self.key1 = self
            .key1
            .wrapping_add(self.key0 & 0xff)
            .wrapping_mul(134_775_813)
            .wrapping_add(1);
        self.key2 = crc32_update(self.key2, self.key1.to_be_bytes()[0]);
    }

    fn encrypt(&mut self, byte: u8) -> u8 {
        let temporary = self.key2 | 2;
        let mask = (temporary.wrapping_mul(temporary ^ 1) >> 8).to_le_bytes()[0];
        let encrypted = byte ^ mask;
        self.update(byte);
        encrypted
    }
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn encrypted_zip(variant: usize) -> TestResult<Vec<u8>> {
    let variant_byte = u8::try_from(variant)?;
    let name = format!("encrypted-{variant:02}.txt").into_bytes();
    let payload = vec![b'A' + variant_byte; 64 + variant];
    let payload_crc = crc32(&payload);
    let mut crypto = ZipCrypto::new(format!("corpus-password-{variant:02}").as_bytes());
    let mut encryption_header = (0_u8..11)
        .map(|byte| byte.wrapping_add(variant_byte))
        .collect::<Vec<_>>();
    encryption_header.push(payload_crc.to_be_bytes()[0]);
    let encrypted_data = encryption_header
        .into_iter()
        .chain(payload.iter().copied())
        .map(|byte| crypto.encrypt(byte))
        .collect::<Vec<_>>();
    let compressed_size = u32::try_from(encrypted_data.len())?;
    let uncompressed_size = u32::try_from(payload.len())?;
    let name_length = u16::try_from(name.len())?;

    let mut archive = Vec::new();
    push_u32(&mut archive, 0x0403_4b50);
    push_u16(&mut archive, 20);
    push_u16(&mut archive, 1);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u32(&mut archive, payload_crc);
    push_u32(&mut archive, compressed_size);
    push_u32(&mut archive, uncompressed_size);
    push_u16(&mut archive, name_length);
    push_u16(&mut archive, 0);
    archive.extend_from_slice(&name);
    archive.extend_from_slice(&encrypted_data);

    let central_offset = u32::try_from(archive.len())?;
    push_u32(&mut archive, 0x0201_4b50);
    push_u16(&mut archive, 20);
    push_u16(&mut archive, 20);
    push_u16(&mut archive, 1);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u32(&mut archive, payload_crc);
    push_u32(&mut archive, compressed_size);
    push_u32(&mut archive, uncompressed_size);
    push_u16(&mut archive, name_length);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u32(&mut archive, 0);
    push_u32(&mut archive, 0);
    archive.extend_from_slice(&name);
    let central_size = u32::try_from(archive.len())?.saturating_sub(central_offset);

    push_u32(&mut archive, 0x0605_4b50);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 0);
    push_u16(&mut archive, 1);
    push_u16(&mut archive, 1);
    push_u32(&mut archive, central_size);
    push_u32(&mut archive, central_offset);
    push_u16(&mut archive, 0);
    Ok(archive)
}

fn write_tar_octal(field: &mut [u8], value: u64) -> TestResult {
    if field.is_empty() {
        return Err(io::Error::other("empty TAR octal field").into());
    }
    let digits_len = field.len() - 1;
    let digits = format!("{value:0digits_len$o}");
    if digits.len() != digits_len {
        return Err(io::Error::other("TAR octal field overflow").into());
    }
    field[..digits_len].copy_from_slice(digits.as_bytes());
    field[digits_len] = 0;
    Ok(())
}

fn copy_tar_field(field: &mut [u8], value: &[u8]) -> TestResult {
    if value.len() > field.len() {
        return Err(io::Error::other("TAR field overflow").into());
    }
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

fn raw_tar_entry(
    name: &[u8],
    entry_type: u8,
    link_name: Option<&[u8]>,
    payload: &[u8],
) -> TestResult<Vec<u8>> {
    let mut header = [0_u8; 512];
    copy_tar_field(&mut header[0..100], name)?;
    write_tar_octal(&mut header[100..108], 0o644)?;
    write_tar_octal(&mut header[108..116], 0)?;
    write_tar_octal(&mut header[116..124], 0)?;
    let size = if entry_type == b'0' {
        u64::try_from(payload.len())?
    } else {
        0
    };
    write_tar_octal(&mut header[124..136], size)?;
    write_tar_octal(&mut header[136..148], 0)?;
    header[148..156].fill(b' ');
    header[156] = entry_type;
    if let Some(link) = link_name {
        copy_tar_field(&mut header[157..257], link)?;
    }
    header[257..263].copy_from_slice(b"ustar\0");
    header[263..265].copy_from_slice(b"00");
    let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
    let checksum_text = format!("{checksum:06o}\0 ");
    header[148..156].copy_from_slice(checksum_text.as_bytes());

    let mut archive = header.to_vec();
    if entry_type == b'0' {
        archive.extend_from_slice(payload);
        let padding = (512 - payload.len() % 512) % 512;
        archive.resize(archive.len() + padding, 0);
    }
    archive.resize(archive.len() + 1024, 0);
    Ok(archive)
}

fn write_source(workspace: &Path, case: &Case, bytes: &[u8]) -> TestResult<PathBuf> {
    let path = workspace.join(format!("{}.bin", case.id));
    fs::write(&path, bytes)?;
    Ok(path)
}

fn snapshot(root: &Path) -> TestResult<BTreeSet<PathBuf>> {
    fn visit(root: &Path, directory: &Path, paths: &mut BTreeSet<PathBuf>) -> io::Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = entry?;
            let path = entry.path();
            let relative = path
                .strip_prefix(root)
                .map_err(io::Error::other)?
                .to_path_buf();
            paths.insert(relative);
            if entry.file_type()?.is_dir() {
                visit(root, &path, paths)?;
            }
        }
        Ok(())
    }

    let mut paths = BTreeSet::new();
    visit(root, root, &mut paths)?;
    Ok(paths)
}

fn finding_present(node: &ArtifactNode, code: &str) -> bool {
    node.findings.iter().any(|finding| finding.code == code)
        || node
            .children
            .iter()
            .any(|child| finding_present(child, code))
}

fn truncation_present(node: &ArtifactNode, reason: TruncationReason) -> bool {
    node.truncation.reasons.contains(&reason)
        || node
            .children
            .iter()
            .any(|child| truncation_present(child, reason))
}

fn traversal_name(case: &Case, sandbox: &Path) -> Vec<u8> {
    match case.variant {
        0 => b"../escape.txt".to_vec(),
        1 => b"safe/../../escape.txt".to_vec(),
        2 => sandbox
            .join("absolute-target.txt")
            .to_string_lossy()
            .into_owned()
            .into_bytes(),
        3 => b"\\absolute-windows.txt".to_vec(),
        4 => b"C:\\escape.txt".to_vec(),
        5 => b"D:/escape.txt".to_vec(),
        6 => b"safe/../escape.txt".to_vec(),
        7 => b"..\\escape.txt".to_vec(),
        8 => b"./../escape.txt".to_vec(),
        _ => b"Z:drive-relative.txt".to_vec(),
    }
}

fn run_traversal(case: &Case, workspace: &Path, sandbox: &Path) -> TestResult<String> {
    let archive = raw_tar_entry(
        &traversal_name(case, sandbox),
        b'0',
        None,
        b"must not materialize",
    )?;
    let source = write_source(workspace, case, &archive)?;
    let result = inspect(&source, default_limits())?;
    Ok(if finding_present(&result.root, "unsafe_archive_path") {
        "unsafe_archive_path"
    } else {
        "missing"
    }
    .to_owned())
}

fn run_unsafe_link(case: &Case, workspace: &Path) -> TestResult<String> {
    let symlink = case.variant % 2 == 0;
    let entry_type = if symlink { b'2' } else { b'1' };
    let target = if case.variant < 5 {
        format!("../outside-{:02}", case.variant)
    } else {
        format!("/absolute/target-{:02}", case.variant)
    };
    let archive = raw_tar_entry(
        format!("link-{:02}", case.variant).as_bytes(),
        entry_type,
        Some(target.as_bytes()),
        &[],
    )?;
    let source = write_source(workspace, case, &archive)?;
    let result = inspect(&source, default_limits())?;
    let child = result
        .root
        .children
        .first()
        .ok_or_else(|| io::Error::other("TAR link child missing"))?;
    let metadata = child
        .attributes
        .get("tar")
        .and_then(Value::as_object)
        .ok_or_else(|| io::Error::other("TAR link metadata missing"))?;
    let link_flag = if symlink {
        metadata.get("is_symlink")
    } else {
        metadata.get("is_hard_link")
    };
    let detected = link_flag == Some(&Value::Bool(true))
        && metadata
            .get("link_name_base64")
            .is_some_and(|value| !value.is_null())
        && child.digest.is_none()
        && child.children.is_empty();
    let reference_refused = matches!(
        read_reference(
            &source,
            &child.reference,
            &ReadOptions {
                limits: default_limits(),
                max_bytes: 65_536,
            },
        ),
        Err(BlobError::ReferenceNotFound)
    );
    Ok(if detected {
        if reference_refused {
            "link_metadata_only"
        } else {
            "missing"
        }
    } else {
        "missing"
    }
    .to_owned())
}

fn run_encryption(case: &Case, workspace: &Path) -> TestResult<String> {
    let archive_bytes = encrypted_zip(case.variant)?;
    let mut verification = zip::ZipArchive::new(Cursor::new(&archive_bytes))?;
    let metadata = verification.by_index_raw(0)?;
    assert!(
        metadata.encrypted(),
        "fixture must carry the encryption flag"
    );
    drop(metadata);
    let password = format!("corpus-password-{:02}", case.variant);
    let mut decrypted_entry = verification.by_index_decrypt(0, password.as_bytes())?;
    let mut decrypted = Vec::new();
    decrypted_entry.read_to_end(&mut decrypted)?;
    assert_eq!(
        decrypted,
        vec![b'A' + u8::try_from(case.variant)?; 64 + case.variant]
    );
    drop(decrypted_entry);

    let source = write_source(workspace, case, &archive_bytes)?;
    let result = inspect(&source, default_limits())?;
    let child = result
        .root
        .children
        .first()
        .ok_or_else(|| io::Error::other("encrypted ZIP child missing"))?;
    let encrypted = child
        .attributes
        .get("zip")
        .and_then(|value| value.get("encrypted"))
        == Some(&Value::Bool(true));
    let detected = encrypted
        && child
            .truncation
            .reasons
            .contains(&TruncationReason::Encrypted)
        && finding_present(child, "encrypted_entry")
        && child.digest.is_none();
    let reference_refused = matches!(
        read_reference(
            &source,
            &child.reference,
            &ReadOptions {
                limits: default_limits(),
                max_bytes: 65_536,
            },
        ),
        Err(BlobError::Unsupported(_))
    );
    Ok(if detected {
        if reference_refused {
            "encrypted_entry"
        } else {
            "missing"
        }
    } else {
        "missing"
    }
    .to_owned())
}

fn run_truncated(case: &Case, workspace: &Path) -> TestResult<String> {
    let mut archive = zip_bytes(&[(
        format!("payload-{:02}.txt", case.variant),
        vec![b'T'; 128 + case.variant],
    )])?;
    let cut = case.variant + 1;
    archive.truncate(archive.len().saturating_sub(cut));
    let source = write_source(workspace, case, &archive)?;
    let result = inspect(&source, default_limits())?;
    Ok(if finding_present(&result.root, "adapter_failure")
        && truncation_present(&result.root, TruncationReason::AdapterFailure)
    {
        "adapter_failure"
    } else {
        "missing"
    }
    .to_owned())
}

fn run_tampered_reference(case: &Case, workspace: &Path) -> TestResult<String> {
    let archive = zip_bytes(&[(
        format!("payload-{:02}.txt", case.variant),
        vec![b'R'; 128 + case.variant],
    )])?;
    let source = write_source(workspace, case, &archive)?;
    let result = inspect(&source, default_limits())?;
    let reference = result
        .root
        .children
        .first()
        .ok_or_else(|| io::Error::other("reference child missing"))?
        .reference
        .clone();
    let mut tampered = archive;
    let position = tampered
        .len()
        .checked_sub(case.variant + 1)
        .ok_or_else(|| io::Error::other("tamper position outside fixture"))?;
    tampered[position] ^= 0x5a;
    fs::write(&source, tampered)?;
    let error = read_reference(
        &source,
        &reference,
        &ReadOptions {
            limits: default_limits(),
            max_bytes: 65_536,
        },
    )
    .err()
    .ok_or_else(|| io::Error::other("tampered reference unexpectedly resolved"))?;
    Ok(if matches!(error, BlobError::Integrity) {
        "integrity"
    } else {
        "missing"
    }
    .to_owned())
}

fn run_excessive_depth(case: &Case, workspace: &Path) -> TestResult<String> {
    let levels = case.variant + 1;
    let mut payload = b"terminal payload".to_vec();
    for level in 0..levels {
        payload = zip_bytes(&[(format!("nested-{level:02}.zip"), payload)])?;
    }
    let source = write_source(workspace, case, &payload)?;
    let mut limits = default_limits();
    limits.max_depth = u8::try_from(levels - 1)?;
    let result = inspect(&source, limits)?;
    Ok(
        if truncation_present(&result.root, TruncationReason::MaxDepth) {
            "max_depth"
        } else {
            "missing"
        }
        .to_owned(),
    )
}

fn run_entry_count(case: &Case, workspace: &Path) -> TestResult<String> {
    let count = case.variant + 2;
    let entries = (0..count)
        .map(|index| (format!("entry-{index:02}.txt"), vec![b'E'; 8]))
        .collect::<Vec<_>>();
    let archive = zip_bytes(&entries)?;
    let source = write_source(workspace, case, &archive)?;
    let mut limits = default_limits();
    limits.max_entries = u64::try_from(count - 1)?;
    let result = inspect(&source, limits.clone())?;
    let detected = result
        .root
        .truncation
        .reasons
        .contains(&TruncationReason::MaxEntries)
        && result.usage.entries_visited == limits.max_entries;
    Ok(if detected { "max_entries" } else { "missing" }.to_owned())
}

fn run_expansion_ratio(case: &Case, workspace: &Path) -> TestResult<String> {
    let payload = vec![0_u8; 4096 * (case.variant + 1)];
    let archive = zip_bytes(&[(format!("zeros-{:02}.bin", case.variant), payload)])?;
    let source = write_source(workspace, case, &archive)?;
    let mut limits = default_limits();
    limits.max_compression_ratio = 1;
    let result = inspect(&source, limits)?;
    let detected = truncation_present(&result.root, TruncationReason::MaxCompressionRatio)
        && finding_present(&result.root, "compression_ratio_exceeded")
        && result.usage.decompressed_bytes == 0;
    Ok(if detected {
        "max_compression_ratio"
    } else {
        "missing"
    }
    .to_owned())
}

fn run_decompressed_bytes(case: &Case, workspace: &Path) -> TestResult<String> {
    let length = 2048 * (case.variant + 1);
    let payload = vec![b'D'; length];
    let archive = zip_bytes(&[(format!("bounded-{:02}.bin", case.variant), payload)])?;
    let source = write_source(workspace, case, &archive)?;
    let mut limits = default_limits();
    limits.max_decompressed_bytes = u64::try_from(length - case.variant - 1)?;
    let result = inspect(&source, limits)?;
    let detected = truncation_present(&result.root, TruncationReason::MaxDecompressedBytes)
        && result.usage.decompressed_bytes == 0;
    Ok(if detected {
        "max_decompressed_bytes"
    } else {
        "missing"
    }
    .to_owned())
}

fn execute_case(case: &Case) -> TestResult<Outcome> {
    let sandbox = TempDir::new()?;
    let workspace = sandbox.path().join("workspace");
    fs::create_dir(&workspace)?;
    let before = snapshot(sandbox.path())?;
    let code = match case.category.as_str() {
        "traversal_path" => {
            assert_eq!(case.operation, "inspect");
            run_traversal(case, &workspace, sandbox.path())?
        }
        "unsafe_link" => {
            assert_eq!(case.operation, "inspect");
            run_unsafe_link(case, &workspace)?
        }
        "encryption" => {
            assert_eq!(case.operation, "inspect");
            run_encryption(case, &workspace)?
        }
        "truncated_structure" => {
            assert_eq!(case.operation, "inspect");
            run_truncated(case, &workspace)?
        }
        "tampered_reference" => {
            assert_eq!(case.operation, "read");
            run_tampered_reference(case, &workspace)?
        }
        "excessive_depth" => {
            assert_eq!(case.operation, "inspect");
            run_excessive_depth(case, &workspace)?
        }
        "entry_count" => {
            assert_eq!(case.operation, "inspect");
            run_entry_count(case, &workspace)?
        }
        "expansion_ratio" => {
            assert_eq!(case.operation, "inspect");
            run_expansion_ratio(case, &workspace)?
        }
        "decompressed_bytes" => {
            assert_eq!(case.operation, "inspect");
            run_decompressed_bytes(case, &workspace)?
        }
        other => {
            return Err(io::Error::other(format!("unknown corpus category {other}")).into());
        }
    };
    let after = snapshot(sandbox.path())?;
    let materialized_paths = after.difference(&before).count().saturating_sub(1);
    Ok(Outcome {
        code,
        materialized_paths,
    })
}

fn ratio(numerator: usize, denominator: usize) -> TestResult<f64> {
    if denominator == 0 {
        return Ok(0.0);
    }
    Ok(f64::from(u32::try_from(numerator)?) / f64::from(u32::try_from(denominator)?))
}

fn approximately_equal(left: f64, right: f64) -> bool {
    (left - right).abs() <= f64::EPSILON
}

#[test]
fn published_adversarial_metrics_are_reproducible() -> TestResult {
    let root = corpus_root();
    let corpus_path = root.join("corpus.json");
    let corpus: Corpus = read_json(&corpus_path)?;
    let metrics: Metrics = read_json(&root.join("metrics.json"))?;
    let corpus_value: Value = serde_json::from_slice(&fs::read(&corpus_path)?)?;

    assert_eq!(corpus.schema_version, "blobdive.adversarial-corpus.v1");
    assert_eq!(corpus.license, "MIT");
    assert_eq!(corpus.generator, "generate_corpus.py");
    assert_eq!(metrics.schema_version, "blobdive.adversarial-metrics.v1");
    assert_eq!(
        metrics.corpus_sha256,
        sha256_hex(&serde_json::to_vec(&corpus_value)?)
    );

    let mut ids = BTreeSet::new();
    let mut by_category = BTreeMap::<String, ActualCategory>::new();
    let mut detected_cases = 0;
    let mut materialized_paths = 0;
    for case in &corpus.cases {
        assert!(ids.insert(case.id.as_str()), "duplicate case {}", case.id);
        assert!(case.variant < 10, "variant outside published range");
        let outcome = execute_case(case)?;
        let detected = outcome.code == case.expected.code;
        assert_eq!(
            outcome.materialized_paths, case.expected.materialized_paths,
            "sandbox write mismatch for {}",
            case.id
        );
        assert!(
            detected,
            "signal mismatch for {}: {}",
            case.id, outcome.code
        );

        detected_cases += usize::from(detected);
        materialized_paths += outcome.materialized_paths;
        let category = by_category.entry(case.category.clone()).or_default();
        category.cases += 1;
        category.detected_cases += usize::from(detected);
        category.materialized_paths += outcome.materialized_paths;
    }

    assert_eq!(metrics.total_cases, corpus.cases.len());
    assert_eq!(metrics.detected_cases, detected_cases);
    assert_eq!(metrics.materialized_paths, materialized_paths);
    assert!(approximately_equal(
        metrics.detection_rate,
        ratio(detected_cases, corpus.cases.len())?
    ));
    assert_eq!(metrics.by_category.len(), by_category.len());
    for (name, actual) in &by_category {
        let expected = metrics
            .by_category
            .get(name)
            .ok_or_else(|| io::Error::other(format!("missing metrics for {name}")))?;
        assert_eq!(expected.cases, actual.cases);
        assert_eq!(expected.detected_cases, actual.detected_cases);
        assert_eq!(expected.materialized_paths, actual.materialized_paths);
        assert!(approximately_equal(
            expected.detection_rate,
            ratio(actual.detected_cases, actual.cases)?
        ));
    }
    Ok(())
}
