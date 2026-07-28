use std::collections::BTreeMap;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactFormat {
    Zip,
    Tar,
    Gzip,
    Elf,
    MachO,
    Pe,
    Pdf,
    Sqlite,
    Png,
    Jpeg,
    Gif,
    Webp,
    Tiff,
    Flac,
    Wav,
    Mp3,
    Mp4,
    Text,
    Unknown,
}

impl ArtifactFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
            Self::Elf => "elf",
            Self::MachO => "mach_o",
            Self::Pe => "pe",
            Self::Pdf => "pdf",
            Self::Sqlite => "sqlite",
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Gif => "gif",
            Self::Webp => "webp",
            Self::Tiff => "tiff",
            Self::Flac => "flac",
            Self::Wav => "wav",
            Self::Mp3 => "mp3",
            Self::Mp4 => "mp4",
            Self::Text => "text",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DetectionEvidence {
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Detection {
    pub format: ArtifactFormat,
    pub media_type: String,
    pub confidence: f64,
    pub source_adapter: String,
    pub evidence: Vec<DetectionEvidence>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Warning,
    Suspicious,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Finding {
    pub code: String,
    pub severity: FindingSeverity,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TruncationReason {
    MaxDepth,
    MaxEntries,
    MaxSourceBytes,
    MaxDecompressedBytes,
    MaxCompressionRatio,
    MaxOutputBytes,
    Timeout,
    AdapterFailure,
    Encrypted,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Truncation {
    pub truncated: bool,
    pub reasons: Vec<TruncationReason>,
}

impl Truncation {
    pub fn add(&mut self, reason: TruncationReason) {
        self.truncated = true;
        if !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ArtifactNode {
    #[serde(rename = "ref")]
    pub reference: String,
    pub display_name: String,
    pub format: ArtifactFormat,
    pub media_type: String,
    pub size: Option<u64>,
    pub digest: Option<String>,
    pub confidence: f64,
    pub source_adapter: String,
    pub detection_evidence: Vec<DetectionEvidence>,
    pub attributes: BTreeMap<String, Value>,
    pub children: Vec<ArtifactNode>,
    pub findings: Vec<Finding>,
    pub truncation: Truncation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetLimits {
    pub max_depth: u8,
    pub max_entries: u64,
    pub max_source_bytes: u64,
    pub max_decompressed_bytes: u64,
    pub max_compression_ratio: u64,
    pub max_output_bytes: u64,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BudgetUsage {
    pub source_bytes: u64,
    pub decompressed_bytes: u64,
    pub entries_visited: u64,
    pub nodes_emitted: u64,
    pub elapsed_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct DetectResult {
    pub schema_version: String,
    pub source: String,
    pub size: u64,
    pub digest: String,
    pub detection: Detection,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InspectResult {
    pub schema_version: String,
    pub source: String,
    pub root: ArtifactNode,
    pub limits: BudgetLimits,
    pub usage: BudgetUsage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ListResult {
    pub schema_version: String,
    pub source: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub children: Vec<ArtifactNode>,
    pub truncation: Truncation,
    pub limits: BudgetLimits,
    pub usage: BudgetUsage,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ReadResult {
    pub schema_version: String,
    pub source: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub encoding: String,
    pub data: String,
    pub returned_bytes: u64,
    pub total_bytes: u64,
    pub truncated: bool,
    pub returned_sha256: String,
    pub content_sha256: Option<String>,
    pub limits: BudgetLimits,
    pub usage: BudgetUsage,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdapterDescriptor {
    pub name: String,
    pub mode: String,
    pub formats: Vec<String>,
    pub capabilities: Vec<String>,
    pub isolation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AdaptersResult {
    pub schema_version: String,
    pub adapters: Vec<AdapterDescriptor>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct BriefContract {
    pub schema_version: String,
    pub blobdive_version: String,
    pub commands: Vec<String>,
    pub output_formats: Vec<String>,
    pub reference_syntax: String,
    pub archive_adapters: Vec<String>,
    pub detection_only_formats: Vec<String>,
    pub budget_fields: Vec<String>,
    pub exit_codes: BTreeMap<String, String>,
    pub security: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorDetail {
    pub kind: String,
    pub message: String,
    pub exit_code: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ErrorEnvelope {
    pub schema_version: String,
    pub error: ErrorDetail,
}
