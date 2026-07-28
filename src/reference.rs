use sha2::{Digest, Sha256};

use crate::error::BlobError;

const PREFIX: &str = "artifact://sha256:";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactReference {
    pub root_digest: String,
    pub steps: Vec<ReferenceStep>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceAdapter {
    Zip,
    Tar,
    Gzip,
}

impl ReferenceAdapter {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceStep {
    pub adapter: ReferenceAdapter,
    pub index: usize,
}

#[must_use]
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[must_use]
pub fn digest_label(data: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(data))
}

#[must_use]
pub fn root_reference(root_digest: &str) -> String {
    format!("{PREFIX}{root_digest}!")
}

#[must_use]
pub fn child_reference(parent: &str, adapter: ReferenceAdapter, index: usize) -> String {
    format!("{parent}/{}/{index:08}", adapter.as_str())
}

/// Parses a deterministic root digest plus archive adapter/index steps.
///
/// # Errors
///
/// Returns [`BlobError::InvalidReference`] when the scheme, digest, or step
/// syntax is malformed.
pub fn parse_reference(value: &str) -> Result<ArtifactReference, BlobError> {
    let rest = value
        .strip_prefix(PREFIX)
        .ok_or_else(|| BlobError::InvalidReference("missing artifact://sha256: prefix".into()))?;
    let (digest, path) = rest
        .split_once('!')
        .ok_or_else(|| BlobError::InvalidReference("missing ! separator".into()))?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BlobError::InvalidReference(
            "root digest must be 64 hexadecimal characters".into(),
        ));
    }
    let mut steps = Vec::new();
    if !path.is_empty() {
        let components: Vec<_> = path
            .strip_prefix('/')
            .ok_or_else(|| BlobError::InvalidReference("entry path must begin with /".into()))?
            .split('/')
            .collect();
        if components.len() % 2 != 0 {
            return Err(BlobError::InvalidReference(
                "entry path must contain adapter/index pairs".into(),
            ));
        }
        for pair in components.chunks_exact(2) {
            let adapter = match pair[0] {
                "zip" => ReferenceAdapter::Zip,
                "tar" => ReferenceAdapter::Tar,
                "gzip" => ReferenceAdapter::Gzip,
                other => {
                    return Err(BlobError::InvalidReference(format!(
                        "unknown adapter {other}"
                    )))
                }
            };
            let index = pair[1]
                .parse::<usize>()
                .map_err(|_| BlobError::InvalidReference("entry index is not decimal".into()))?;
            steps.push(ReferenceStep { adapter, index });
        }
    }
    Ok(ArtifactReference {
        root_digest: digest.to_ascii_lowercase(),
        steps,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_round_trip_adapter_steps() -> Result<(), BlobError> {
        let digest = "ab".repeat(32);
        let root = root_reference(&digest);
        let child = child_reference(&root, ReferenceAdapter::Zip, 3);
        let nested = child_reference(&child, ReferenceAdapter::Gzip, 0);
        let parsed = parse_reference(&nested)?;
        assert_eq!(parsed.root_digest, digest);
        assert_eq!(
            parsed.steps,
            vec![
                ReferenceStep {
                    adapter: ReferenceAdapter::Zip,
                    index: 3
                },
                ReferenceStep {
                    adapter: ReferenceAdapter::Gzip,
                    index: 0
                }
            ]
        );
        Ok(())
    }
}
