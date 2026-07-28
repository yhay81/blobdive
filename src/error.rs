use std::io;

use thiserror::Error;

use crate::model::{ErrorDetail, ErrorEnvelope};

#[derive(Debug, Error)]
pub enum BlobError {
    #[error("cannot read source: {0}")]
    Io(#[from] io::Error),
    #[error("source must be a regular file")]
    NotRegularFile,
    #[error("source exceeds max_source_bytes ({size} > {limit})")]
    SourceBudget { size: u64, limit: u64 },
    #[error("resource budget prevented the operation: {0}")]
    ResourceBudget(String),
    #[error("operation exceeded its wall-clock budget")]
    Timeout,
    #[error("invalid artifact reference: {0}")]
    InvalidReference(String),
    #[error("artifact reference does not identify an entry")]
    ReferenceNotFound,
    #[error("source digest does not match the artifact reference")]
    Integrity,
    #[error("source changed while it was being read")]
    SourceChanged,
    #[error("unsupported operation: {0}")]
    Unsupported(String),
    #[error("archive parser failed: {0}")]
    Archive(String),
    #[error("serialized result cannot fit within max_output_bytes")]
    OutputBudget,
}

impl BlobError {
    #[must_use]
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::SourceBudget { .. }
            | Self::ResourceBudget(_)
            | Self::Timeout
            | Self::OutputBudget => 3,
            Self::ReferenceNotFound => 4,
            Self::Integrity | Self::SourceChanged => 5,
            Self::Io(_)
            | Self::NotRegularFile
            | Self::InvalidReference(_)
            | Self::Unsupported(_)
            | Self::Archive(_) => 1,
        }
    }

    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) => "io",
            Self::NotRegularFile => "not_regular_file",
            Self::SourceBudget { .. } => "source_budget",
            Self::ResourceBudget(_) => "resource_budget",
            Self::Timeout => "timeout",
            Self::InvalidReference(_) => "invalid_reference",
            Self::ReferenceNotFound => "reference_not_found",
            Self::Integrity => "integrity",
            Self::SourceChanged => "source_changed",
            Self::Unsupported(_) => "unsupported",
            Self::Archive(_) => "archive",
            Self::OutputBudget => "output_budget",
        }
    }

    #[must_use]
    pub fn envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            schema_version: "blobdive.error.v1".to_owned(),
            error: ErrorDetail {
                kind: self.kind().to_owned(),
                message: self.to_string(),
                exit_code: self.exit_code(),
            },
        }
    }
}

impl From<zip::result::ZipError> for BlobError {
    fn from(value: zip::result::ZipError) -> Self {
        Self::Archive(value.to_string())
    }
}
