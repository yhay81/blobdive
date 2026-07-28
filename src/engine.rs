use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Cursor, Read},
    path::Path,
    time::{Duration, Instant},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use flate2::read::GzDecoder;
use serde_json::json;

use crate::{
    budget::Budget,
    detect::detect,
    error::BlobError,
    model::{
        AdapterDescriptor, AdaptersResult, ArtifactFormat, ArtifactNode, BudgetLimits,
        DetectResult, Finding, FindingSeverity, InspectResult, ListResult, ReadResult, Truncation,
        TruncationReason,
    },
    reference::{
        child_reference, digest_label, parse_reference, root_reference, sha256_hex,
        ArtifactReference, ReferenceAdapter, ReferenceStep,
    },
};

#[derive(Debug, Clone)]
pub struct InspectOptions {
    pub limits: BudgetLimits,
}

#[derive(Debug, Clone)]
pub struct ReadOptions {
    pub limits: BudgetLimits,
    pub max_bytes: u64,
}

#[derive(Debug)]
struct AdapterOutcome {
    children: Vec<ArtifactNode>,
    findings: Vec<Finding>,
    truncation: Truncation,
}

impl AdapterOutcome {
    fn empty() -> Self {
        Self {
            children: Vec::new(),
            findings: Vec::new(),
            truncation: Truncation::default(),
        }
    }
}

enum ReadAttempt {
    Complete(Vec<u8>),
    Truncated(Vec<u8>, TruncationReason),
    Failed(String),
}

/// Detects a bounded regular file by content and returns its root digest.
///
/// # Errors
///
/// Returns an I/O, file-type, or source-budget error when the input cannot be
/// read completely inside `max_source_bytes`.
pub fn detect_source(
    source: &Path,
    max_source_bytes: u64,
    timeout_ms: u64,
) -> Result<DetectResult, BlobError> {
    let started = Instant::now();
    let deadline = deadline(started, timeout_ms);
    let bytes = read_source(source, max_source_bytes, deadline)?;
    ensure_before(deadline)?;
    let digest = digest_label(&bytes);
    ensure_before(deadline)?;
    Ok(DetectResult {
        schema_version: "blobdive.detect.v1".to_owned(),
        source: source.display().to_string(),
        size: usize_to_u64(bytes.len()),
        digest,
        detection: detect(&bytes),
    })
}

/// Inspects a bounded regular file without extracting or executing content.
///
/// # Errors
///
/// Returns an I/O, source-budget, archive serialization, or output-budget
/// error. Individual adapter failures are normally recorded in the result.
pub fn inspect_source(source: &Path, options: &InspectOptions) -> Result<InspectResult, BlobError> {
    let started = Instant::now();
    let deadline = deadline(started, options.limits.timeout_ms);
    let bytes = read_source(source, options.limits.max_source_bytes, deadline)?;
    ensure_before(deadline)?;
    let digest = sha256_hex(&bytes);
    ensure_before(deadline)?;
    let reference = root_reference(&digest);
    let display_name = source
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("<artifact>")
        .to_owned();
    let mut budget = Budget::new_at(options.limits.clone(), usize_to_u64(bytes.len()), started);
    let root = inspect_node(
        &bytes,
        &display_name,
        &reference,
        Some(format!("sha256:{digest}")),
        options.limits.max_depth,
        &mut budget,
    );
    let mut result = InspectResult {
        schema_version: "blobdive.inspect.v1".to_owned(),
        source: source.display().to_string(),
        root,
        limits: options.limits.clone(),
        usage: budget.usage(),
    };
    prune_inspect_to_output_budget(&mut result)?;
    Ok(result)
}

/// Resolves a deterministic reference and lists its direct archive children.
///
/// # Errors
///
/// Returns an error when the source cannot be read, its digest no longer
/// matches the reference, the reference cannot be resolved, or a hard resource
/// budget prevents resolution.
pub fn list_reference(
    source: &Path,
    reference: &str,
    options: &InspectOptions,
) -> Result<ListResult, BlobError> {
    let started = Instant::now();
    let deadline = deadline(started, options.limits.timeout_ms);
    let bytes = read_source(source, options.limits.max_source_bytes, deadline)?;
    ensure_before(deadline)?;
    let parsed = parse_reference(reference)?;
    verify_root_digest(&bytes, &parsed)?;
    ensure_before(deadline)?;
    let mut budget = Budget::new_at(options.limits.clone(), usize_to_u64(bytes.len()), started);
    let target = resolve_reference(bytes, &parsed, &mut budget)?;
    let mut target_node = inspect_node(
        &target,
        "<referenced artifact>",
        reference,
        Some(digest_label(&target)),
        1,
        &mut budget,
    );
    let mut result = ListResult {
        schema_version: "blobdive.list.v1".to_owned(),
        source: source.display().to_string(),
        reference: reference.to_owned(),
        children: std::mem::take(&mut target_node.children),
        truncation: target_node.truncation,
        limits: options.limits.clone(),
        usage: budget.usage(),
    };
    prune_list_to_output_budget(&mut result)?;
    Ok(result)
}

/// Resolves a deterministic reference and returns bounded base64 content.
///
/// # Errors
///
/// Returns an error when the source cannot be read, its digest no longer
/// matches the reference, the reference cannot be resolved, or a hard resource
/// or output budget prevents the response.
pub fn read_reference(
    source: &Path,
    reference: &str,
    options: &ReadOptions,
) -> Result<ReadResult, BlobError> {
    let started = Instant::now();
    let deadline = deadline(started, options.limits.timeout_ms);
    let bytes = read_source(source, options.limits.max_source_bytes, deadline)?;
    ensure_before(deadline)?;
    let parsed = parse_reference(reference)?;
    verify_root_digest(&bytes, &parsed)?;
    ensure_before(deadline)?;
    let mut budget = Budget::new_at(options.limits.clone(), usize_to_u64(bytes.len()), started);
    let target = resolve_reference(bytes, &parsed, &mut budget)?;
    let total_bytes = usize_to_u64(target.len());
    let returned_len = usize::try_from(options.max_bytes.min(total_bytes)).unwrap_or(usize::MAX);
    let returned = &target[..returned_len];
    let truncated = returned_len < target.len();
    let result = ReadResult {
        schema_version: "blobdive.read.v1".to_owned(),
        source: source.display().to_string(),
        reference: reference.to_owned(),
        encoding: "base64".to_owned(),
        data: BASE64.encode(returned),
        returned_bytes: usize_to_u64(returned.len()),
        total_bytes,
        truncated,
        returned_sha256: sha256_hex(returned),
        content_sha256: (!truncated).then(|| sha256_hex(&target)),
        limits: options.limits.clone(),
        usage: budget.usage(),
    };
    if serialized_len(&result)? > options.limits.max_output_bytes {
        return Err(BlobError::OutputBudget);
    }
    Ok(result)
}

#[must_use]
pub fn adapters() -> AdaptersResult {
    AdaptersResult {
        schema_version: "blobdive.adapters.v1".to_owned(),
        adapters: vec![
            AdapterDescriptor {
                name: "builtin.magic".to_owned(),
                mode: "detection".to_owned(),
                formats: [
                    "elf", "mach_o", "pe", "pdf", "sqlite", "png", "jpeg", "gif", "webp", "tiff",
                    "flac", "wav", "mp3", "mp4", "text", "unknown",
                ]
                .into_iter()
                .map(str::to_owned)
                .collect(),
                capabilities: vec!["detect".to_owned()],
                isolation: "in_process_bounded".to_owned(),
            },
            AdapterDescriptor {
                name: "builtin.zip".to_owned(),
                mode: "structural".to_owned(),
                formats: vec!["zip".to_owned()],
                capabilities: archive_capabilities(),
                isolation: "in_process_bounded".to_owned(),
            },
            AdapterDescriptor {
                name: "builtin.tar".to_owned(),
                mode: "structural".to_owned(),
                formats: vec!["tar".to_owned()],
                capabilities: archive_capabilities(),
                isolation: "in_process_bounded".to_owned(),
            },
            AdapterDescriptor {
                name: "builtin.gzip".to_owned(),
                mode: "structural".to_owned(),
                formats: vec!["gzip".to_owned()],
                capabilities: archive_capabilities(),
                isolation: "in_process_bounded".to_owned(),
            },
        ],
    }
}

fn archive_capabilities() -> Vec<String> {
    ["detect", "inspect", "list", "read"]
        .into_iter()
        .map(str::to_owned)
        .collect()
}

fn inspect_node(
    data: &[u8],
    display_name: &str,
    reference: &str,
    digest: Option<String>,
    depth_remaining: u8,
    budget: &mut Budget,
) -> ArtifactNode {
    budget.emit_node();
    let detection = detect(data);
    let mut node = ArtifactNode {
        reference: reference.to_owned(),
        display_name: display_name.to_owned(),
        format: detection.format,
        media_type: detection.media_type,
        size: Some(usize_to_u64(data.len())),
        digest,
        confidence: detection.confidence,
        source_adapter: detection.source_adapter,
        detection_evidence: detection.evidence,
        attributes: BTreeMap::new(),
        children: Vec::new(),
        findings: Vec::new(),
        truncation: Truncation::default(),
    };

    let structural = matches!(
        node.format,
        ArtifactFormat::Zip | ArtifactFormat::Tar | ArtifactFormat::Gzip
    );
    if structural && depth_remaining == 0 {
        node.truncation.add(TruncationReason::MaxDepth);
        return node;
    }
    if !structural {
        return node;
    }

    let outcome = match node.format {
        ArtifactFormat::Zip => inspect_zip(data, reference, depth_remaining - 1, budget),
        ArtifactFormat::Tar => inspect_tar(data, reference, depth_remaining - 1, budget),
        ArtifactFormat::Gzip => inspect_gzip(data, reference, depth_remaining - 1, budget),
        _ => AdapterOutcome::empty(),
    };
    node.children = outcome.children;
    node.findings.extend(outcome.findings);
    for reason in outcome.truncation.reasons {
        node.truncation.add(reason);
    }
    node
}

fn inspect_zip(
    data: &[u8],
    parent_reference: &str,
    child_depth: u8,
    budget: &mut Budget,
) -> AdapterOutcome {
    let mut outcome = AdapterOutcome::empty();
    let mut archive = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(archive) => archive,
        Err(error) => {
            outcome.findings.push(adapter_failure("zip", &error));
            outcome.truncation.add(TruncationReason::AdapterFailure);
            return outcome;
        }
    };

    for index in 0..archive.len() {
        if budget.time_exhausted() {
            outcome.truncation.add(TruncationReason::Timeout);
            break;
        }
        if !budget.visit_entry() {
            outcome.truncation.add(TruncationReason::MaxEntries);
            break;
        }
        let mut entry = match archive.by_index(index) {
            Ok(entry) => entry,
            Err(error) => {
                outcome.findings.push(adapter_failure("zip entry", &error));
                outcome.truncation.add(TruncationReason::AdapterFailure);
                continue;
            }
        };
        let raw_name = entry.name_raw().to_vec();
        let (display_name, normalized_path, unsafe_path) = analyze_archive_path(&raw_name);
        let entry_reference = child_reference(parent_reference, ReferenceAdapter::Zip, index);
        let size = entry.size();
        let compressed_size = entry.compressed_size();
        let is_dir = entry.is_dir();
        let encrypted = entry.encrypted();
        let metadata = json!({
            "archive_path": normalized_path,
            "raw_name_base64": BASE64.encode(&raw_name),
            "unsafe_path": unsafe_path,
            "is_directory": is_dir,
            "encrypted": encrypted,
            "compressed_size": compressed_size,
            "uncompressed_size": size,
            "compression_method": format!("{:?}", entry.compression()),
            "unix_mode": entry.unix_mode(),
            "entry_index": index,
        });

        let mut child = if is_dir {
            metadata_only_node(
                &entry_reference,
                &display_name,
                "inode/directory",
                size,
                budget,
            )
        } else if encrypted {
            encrypted_entry_node(&entry_reference, &display_name, size, budget)
        } else if let Some(reason) = budget.decompression_block_reason(compressed_size, size) {
            blocked_entry_node(
                &entry_reference,
                &display_name,
                size,
                reason,
                compressed_size,
                budget,
            )
        } else {
            entry_attempt_to_node(
                read_bounded(&mut entry, size, Some(size), budget),
                &entry_reference,
                &display_name,
                size,
                compressed_size,
                child_depth,
                budget,
            )
        };
        child.attributes.insert("zip".to_owned(), metadata);
        if unsafe_path {
            child.findings.push(unsafe_path_finding());
        }
        outcome.children.push(child);
    }
    outcome
}

fn inspect_tar(
    data: &[u8],
    parent_reference: &str,
    child_depth: u8,
    budget: &mut Budget,
) -> AdapterOutcome {
    let mut outcome = AdapterOutcome::empty();
    let mut archive = tar::Archive::new(Cursor::new(data));
    let entries = match archive.entries() {
        Ok(entries) => entries,
        Err(error) => {
            outcome.findings.push(adapter_failure("tar", &error));
            outcome.truncation.add(TruncationReason::AdapterFailure);
            return outcome;
        }
    };

    for (index, entry_result) in entries.enumerate() {
        if budget.time_exhausted() {
            outcome.truncation.add(TruncationReason::Timeout);
            break;
        }
        if !budget.visit_entry() {
            outcome.truncation.add(TruncationReason::MaxEntries);
            break;
        }
        let mut entry = match entry_result {
            Ok(entry) => entry,
            Err(error) => {
                outcome.findings.push(adapter_failure("tar entry", &error));
                outcome.truncation.add(TruncationReason::AdapterFailure);
                continue;
            }
        };
        let raw_name = entry.path_bytes().to_vec();
        let (display_name, normalized_path, unsafe_path) = analyze_archive_path(&raw_name);
        let entry_reference = child_reference(parent_reference, ReferenceAdapter::Tar, index);
        let size = entry.size();
        let entry_type = entry.header().entry_type();
        let is_file = entry_type.is_file();
        let is_dir = entry_type.is_dir();
        let link_name = entry.link_name_bytes().map(|name| BASE64.encode(name));
        let metadata = json!({
            "archive_path": normalized_path,
            "raw_name_base64": BASE64.encode(&raw_name),
            "unsafe_path": unsafe_path,
            "is_file": is_file,
            "is_directory": is_dir,
            "is_symlink": entry_type.is_symlink(),
            "is_hard_link": entry_type.is_hard_link(),
            "link_name_base64": link_name,
            "size": size,
            "entry_index": index,
        });

        let mut child = if is_dir {
            metadata_only_node(
                &entry_reference,
                &display_name,
                "inode/directory",
                size,
                budget,
            )
        } else if !is_file {
            metadata_only_node(
                &entry_reference,
                &display_name,
                "application/octet-stream",
                size,
                budget,
            )
        } else if let Some(reason) = budget.decompression_block_reason(size, size) {
            blocked_entry_node(&entry_reference, &display_name, size, reason, size, budget)
        } else {
            entry_attempt_to_node(
                read_bounded(&mut entry, size, Some(size), budget),
                &entry_reference,
                &display_name,
                size,
                size,
                child_depth,
                budget,
            )
        };
        child.attributes.insert("tar".to_owned(), metadata);
        if unsafe_path {
            child.findings.push(unsafe_path_finding());
        }
        outcome.children.push(child);
    }
    outcome
}

fn inspect_gzip(
    data: &[u8],
    parent_reference: &str,
    child_depth: u8,
    budget: &mut Budget,
) -> AdapterOutcome {
    let mut outcome = AdapterOutcome::empty();
    if budget.time_exhausted() {
        outcome.truncation.add(TruncationReason::Timeout);
        return outcome;
    }
    if !budget.visit_entry() {
        outcome.truncation.add(TruncationReason::MaxEntries);
        return outcome;
    }
    let entry_reference = child_reference(parent_reference, ReferenceAdapter::Gzip, 0);
    let mut decoder = GzDecoder::new(data);
    let raw_name = decoder
        .header()
        .and_then(|header| header.filename())
        .map_or_else(|| b"<gzip-payload>".to_vec(), <[u8]>::to_vec);
    let display_name = String::from_utf8_lossy(&raw_name).into_owned();
    let allowance = budget.decompression_allowance(usize_to_u64(data.len()));
    let mut child = entry_attempt_to_node(
        read_bounded(&mut decoder, allowance, None, budget),
        &entry_reference,
        &display_name,
        allowance,
        usize_to_u64(data.len()),
        child_depth,
        budget,
    );
    child.attributes.insert(
        "gzip".to_owned(),
        json!({
            "raw_name_base64": BASE64.encode(raw_name),
            "compressed_size": data.len(),
            "entry_index": 0,
        }),
    );
    outcome.children.push(child);
    outcome
}

fn entry_attempt_to_node(
    attempt: ReadAttempt,
    reference: &str,
    display_name: &str,
    size: u64,
    compressed_size: u64,
    child_depth: u8,
    budget: &mut Budget,
) -> ArtifactNode {
    match attempt {
        ReadAttempt::Complete(bytes) => {
            budget.claim_decompressed(usize_to_u64(bytes.len()));
            inspect_node(
                &bytes,
                display_name,
                reference,
                Some(digest_label(&bytes)),
                child_depth,
                budget,
            )
        }
        ReadAttempt::Truncated(bytes, reason) => {
            budget.claim_decompressed(usize_to_u64(bytes.len()));
            blocked_entry_node(
                reference,
                display_name,
                size,
                reason,
                compressed_size,
                budget,
            )
        }
        ReadAttempt::Failed(message) => {
            let mut child = metadata_only_node(
                reference,
                display_name,
                "application/octet-stream",
                size,
                budget,
            );
            child.truncation.add(TruncationReason::AdapterFailure);
            child.findings.push(Finding {
                code: "entry_read_failed".to_owned(),
                severity: FindingSeverity::Warning,
                message,
            });
            child
        }
    }
}

fn metadata_only_node(
    reference: &str,
    display_name: &str,
    media_type: &str,
    size: u64,
    budget: &mut Budget,
) -> ArtifactNode {
    budget.emit_node();
    ArtifactNode {
        reference: reference.to_owned(),
        display_name: display_name.to_owned(),
        format: ArtifactFormat::Unknown,
        media_type: media_type.to_owned(),
        size: Some(size),
        digest: None,
        confidence: 0.0,
        source_adapter: "archive.metadata".to_owned(),
        detection_evidence: Vec::new(),
        attributes: BTreeMap::new(),
        children: Vec::new(),
        findings: Vec::new(),
        truncation: Truncation::default(),
    }
}

fn encrypted_entry_node(
    reference: &str,
    display_name: &str,
    size: u64,
    budget: &mut Budget,
) -> ArtifactNode {
    let mut child = metadata_only_node(
        reference,
        display_name,
        "application/octet-stream",
        size,
        budget,
    );
    child.truncation.add(TruncationReason::Encrypted);
    child.findings.push(Finding {
        code: "encrypted_entry".to_owned(),
        severity: FindingSeverity::Info,
        message: "encrypted ZIP entries are reported but never decrypted".to_owned(),
    });
    child
}

fn blocked_entry_node(
    reference: &str,
    display_name: &str,
    size: u64,
    reason: TruncationReason,
    compressed_size: u64,
    budget: &mut Budget,
) -> ArtifactNode {
    let mut node = metadata_only_node(
        reference,
        display_name,
        "application/octet-stream",
        size,
        budget,
    );
    node.truncation.add(reason);
    if reason == TruncationReason::MaxCompressionRatio {
        node.findings.push(Finding {
            code: "compression_ratio_exceeded".to_owned(),
            severity: FindingSeverity::Suspicious,
            message: format!(
                "declared expansion {size} bytes from {} bytes exceeds the configured ratio",
                compressed_size.max(1)
            ),
        });
    }
    node
}

fn resolve_reference(
    mut current: Vec<u8>,
    reference: &ArtifactReference,
    budget: &mut Budget,
) -> Result<Vec<u8>, BlobError> {
    for step in &reference.steps {
        budget.ensure_time()?;
        current = extract_step(&current, *step, budget)?;
    }
    Ok(current)
}

fn extract_step(
    data: &[u8],
    step: ReferenceStep,
    budget: &mut Budget,
) -> Result<Vec<u8>, BlobError> {
    match step.adapter {
        ReferenceAdapter::Zip => extract_zip_step(data, step.index, budget),
        ReferenceAdapter::Tar => extract_tar_step(data, step.index, budget),
        ReferenceAdapter::Gzip => extract_gzip_step(data, step.index, budget),
    }
}

fn extract_zip_step(data: &[u8], index: usize, budget: &mut Budget) -> Result<Vec<u8>, BlobError> {
    if detect(data).format != ArtifactFormat::Zip {
        return Err(BlobError::ReferenceNotFound);
    }
    let mut archive = zip::ZipArchive::new(Cursor::new(data))?;
    let mut entry = archive
        .by_index(index)
        .map_err(|_| BlobError::ReferenceNotFound)?;
    if entry.is_dir() {
        return Err(BlobError::ReferenceNotFound);
    }
    if entry.encrypted() {
        return Err(BlobError::Unsupported(
            "encrypted ZIP entries are not decrypted".to_owned(),
        ));
    }
    let size = entry.size();
    let compressed_size = entry.compressed_size();
    if let Some(reason) = budget.decompression_block_reason(compressed_size, size) {
        return Err(BlobError::ResourceBudget(format!("{reason:?}")));
    }
    finish_extraction(read_bounded(&mut entry, size, Some(size), budget), budget)
}

fn extract_tar_step(data: &[u8], index: usize, budget: &mut Budget) -> Result<Vec<u8>, BlobError> {
    if detect(data).format != ArtifactFormat::Tar {
        return Err(BlobError::ReferenceNotFound);
    }
    let mut archive = tar::Archive::new(Cursor::new(data));
    let entries = archive.entries()?;
    for (candidate_index, entry) in entries.enumerate() {
        if candidate_index != index {
            continue;
        }
        let mut entry = entry?;
        if !entry.header().entry_type().is_file() {
            return Err(BlobError::ReferenceNotFound);
        }
        let size = entry.size();
        if let Some(reason) = budget.decompression_block_reason(size, size) {
            return Err(BlobError::ResourceBudget(format!("{reason:?}")));
        }
        return finish_extraction(read_bounded(&mut entry, size, Some(size), budget), budget);
    }
    Err(BlobError::ReferenceNotFound)
}

fn extract_gzip_step(data: &[u8], index: usize, budget: &mut Budget) -> Result<Vec<u8>, BlobError> {
    if index != 0 || detect(data).format != ArtifactFormat::Gzip {
        return Err(BlobError::ReferenceNotFound);
    }
    let allowance = budget.decompression_allowance(usize_to_u64(data.len()));
    let mut decoder = GzDecoder::new(data);
    finish_extraction(read_bounded(&mut decoder, allowance, None, budget), budget)
}

fn finish_extraction(attempt: ReadAttempt, budget: &mut Budget) -> Result<Vec<u8>, BlobError> {
    match attempt {
        ReadAttempt::Complete(bytes) => {
            budget.claim_decompressed(usize_to_u64(bytes.len()));
            Ok(bytes)
        }
        ReadAttempt::Truncated(_, TruncationReason::Timeout) => Err(BlobError::Timeout),
        ReadAttempt::Truncated(_, reason) => Err(BlobError::ResourceBudget(format!("{reason:?}"))),
        ReadAttempt::Failed(message) => Err(BlobError::Archive(message)),
    }
}

fn read_bounded(
    reader: &mut impl Read,
    allowance: u64,
    expected_size: Option<u64>,
    budget: &Budget,
) -> ReadAttempt {
    let capacity = usize::try_from(allowance.min(1024 * 1024)).unwrap_or(1024 * 1024);
    let mut bytes = Vec::with_capacity(capacity);
    let mut remaining = allowance;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while remaining > 0 {
        if budget.time_exhausted() {
            return ReadAttempt::Truncated(bytes, TruncationReason::Timeout);
        }
        let read_limit =
            usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        match reader.read(&mut buffer[..read_limit]) {
            Ok(0) => {
                if expected_size.is_some_and(|expected| expected != usize_to_u64(bytes.len())) {
                    return ReadAttempt::Failed(
                        "entry ended before its declared uncompressed size".to_owned(),
                    );
                }
                return ReadAttempt::Complete(bytes);
            }
            Ok(count) => {
                bytes.extend_from_slice(&buffer[..count]);
                remaining = remaining.saturating_sub(usize_to_u64(count));
                if expected_size.is_some_and(|expected| expected == usize_to_u64(bytes.len())) {
                    return ReadAttempt::Complete(bytes);
                }
            }
            Err(error) => return ReadAttempt::Failed(error.to_string()),
        }
    }
    let reason = if allowance >= budget.remaining_decompressed() {
        TruncationReason::MaxDecompressedBytes
    } else {
        TruncationReason::MaxCompressionRatio
    };
    ReadAttempt::Truncated(bytes, reason)
}

fn read_source(
    source: &Path,
    max_source_bytes: u64,
    deadline: Instant,
) -> Result<Vec<u8>, BlobError> {
    ensure_before(deadline)?;
    let metadata = fs::metadata(source)?;
    if !metadata.is_file() {
        return Err(BlobError::NotRegularFile);
    }
    if metadata.len() > max_source_bytes {
        return Err(BlobError::SourceBudget {
            size: metadata.len(),
            limit: max_source_bytes,
        });
    }
    let mut file = File::open(source)?;
    let capacity = usize::try_from(metadata.len()).unwrap_or(0);
    let mut bytes = Vec::with_capacity(capacity);
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    while usize_to_u64(bytes.len()) < metadata.len() {
        ensure_before(deadline)?;
        let remaining = metadata.len().saturating_sub(usize_to_u64(bytes.len()));
        let read_limit =
            usize::try_from(remaining.min(buffer.len() as u64)).unwrap_or(buffer.len());
        let count = file.read(&mut buffer[..read_limit])?;
        if count == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..count]);
    }
    let observed_metadata = file.metadata()?;
    if observed_metadata.len() > max_source_bytes {
        return Err(BlobError::SourceBudget {
            size: observed_metadata.len(),
            limit: max_source_bytes,
        });
    }
    if observed_metadata.len() != usize_to_u64(bytes.len())
        || metadata.modified().ok() != observed_metadata.modified().ok()
    {
        return Err(BlobError::SourceChanged);
    }
    ensure_before(deadline)?;
    Ok(bytes)
}

fn deadline(started: Instant, timeout_ms: u64) -> Instant {
    started
        .checked_add(Duration::from_millis(timeout_ms))
        .unwrap_or(started)
}

fn ensure_before(deadline: Instant) -> Result<(), BlobError> {
    if Instant::now() >= deadline {
        Err(BlobError::Timeout)
    } else {
        Ok(())
    }
}

fn verify_root_digest(data: &[u8], reference: &ArtifactReference) -> Result<(), BlobError> {
    if sha256_hex(data) == reference.root_digest {
        Ok(())
    } else {
        Err(BlobError::Integrity)
    }
}

fn analyze_archive_path(raw_name: &[u8]) -> (String, Option<String>, bool) {
    let display = String::from_utf8_lossy(raw_name).into_owned();
    let slash_normalized = display.replace('\\', "/");
    let starts_absolute = slash_normalized.starts_with('/')
        || slash_normalized
            .as_bytes()
            .get(1)
            .is_some_and(|byte| *byte == b':');
    let mut unsafe_path = starts_absolute || raw_name.contains(&0);
    let mut components = Vec::new();
    for component in slash_normalized.split('/') {
        match component {
            "" | "." => {}
            ".." => unsafe_path = true,
            safe => components.push(safe),
        }
    }
    let normalized = (!unsafe_path).then(|| components.join("/"));
    (display, normalized, unsafe_path)
}

fn unsafe_path_finding() -> Finding {
    Finding {
        code: "unsafe_archive_path".to_owned(),
        severity: FindingSeverity::Suspicious,
        message: "entry path is absolute, traverses a parent, has a drive prefix, or contains NUL"
            .to_owned(),
    }
}

fn adapter_failure(adapter: &str, error: &impl std::fmt::Display) -> Finding {
    Finding {
        code: "adapter_failure".to_owned(),
        severity: FindingSeverity::Warning,
        message: format!("{adapter} parser failed in isolation: {error}"),
    }
}

fn prune_inspect_to_output_budget(result: &mut InspectResult) -> Result<(), BlobError> {
    while serialized_len(result)? > result.limits.max_output_bytes {
        if !remove_last_descendant(&mut result.root) {
            return Err(BlobError::OutputBudget);
        }
        result.root.truncation.add(TruncationReason::MaxOutputBytes);
    }
    Ok(())
}

fn prune_list_to_output_budget(result: &mut ListResult) -> Result<(), BlobError> {
    while serialized_len(result)? > result.limits.max_output_bytes {
        if result.children.pop().is_none() {
            return Err(BlobError::OutputBudget);
        }
        result.truncation.add(TruncationReason::MaxOutputBytes);
    }
    Ok(())
}

fn remove_last_descendant(node: &mut ArtifactNode) -> bool {
    let Some(last) = node.children.last_mut() else {
        return false;
    };
    if remove_last_descendant(last) {
        true
    } else {
        node.children.pop();
        true
    }
}

fn serialized_len(value: &impl serde::Serialize) -> Result<u64, BlobError> {
    serde_json::to_vec_pretty(value)
        .map(|bytes| usize_to_u64(bytes.len()))
        .map_err(|error| BlobError::Archive(error.to_string()))
}

fn usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}
