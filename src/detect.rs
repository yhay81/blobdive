use crate::model::{ArtifactFormat, Detection, DetectionEvidence};

#[must_use]
#[allow(clippy::too_many_lines)]
pub fn detect(data: &[u8]) -> Detection {
    let (format, media_type, confidence, evidence) = if data.starts_with(b"PK\x03\x04")
        || data.starts_with(b"PK\x05\x06")
        || data.starts_with(b"PK\x07\x08")
    {
        (
            ArtifactFormat::Zip,
            "application/zip",
            1.0,
            "ZIP local/central-directory signature",
        )
    } else if data.starts_with(&[0x1f, 0x8b, 0x08]) {
        (
            ArtifactFormat::Gzip,
            "application/gzip",
            1.0,
            "gzip signature and deflate method",
        )
    } else if looks_like_tar(data) {
        (
            ArtifactFormat::Tar,
            "application/x-tar",
            0.99,
            "valid tar header checksum",
        )
    } else if data.starts_with(b"\x7fELF") {
        (
            ArtifactFormat::Elf,
            "application/x-elf",
            1.0,
            "ELF signature",
        )
    } else if is_mach_o(data) {
        (
            ArtifactFormat::MachO,
            "application/x-mach-binary",
            1.0,
            "Mach-O or universal-binary signature",
        )
    } else if data.starts_with(b"MZ") {
        (
            ArtifactFormat::Pe,
            "application/vnd.microsoft.portable-executable",
            0.9,
            "DOS MZ signature; PE header is not deeply validated",
        )
    } else if data.starts_with(b"%PDF-") {
        (ArtifactFormat::Pdf, "application/pdf", 1.0, "PDF header")
    } else if data.starts_with(b"SQLite format 3\0") {
        (
            ArtifactFormat::Sqlite,
            "application/vnd.sqlite3",
            1.0,
            "SQLite 3 header",
        )
    } else if data.starts_with(b"\x89PNG\r\n\x1a\n") {
        (ArtifactFormat::Png, "image/png", 1.0, "PNG signature")
    } else if data.starts_with(&[0xff, 0xd8, 0xff]) {
        (ArtifactFormat::Jpeg, "image/jpeg", 0.99, "JPEG SOI marker")
    } else if data.starts_with(b"GIF87a") || data.starts_with(b"GIF89a") {
        (ArtifactFormat::Gif, "image/gif", 1.0, "GIF header")
    } else if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WEBP" {
        (ArtifactFormat::Webp, "image/webp", 1.0, "RIFF WEBP header")
    } else if data.starts_with(b"II*\0") || data.starts_with(b"MM\0*") {
        (ArtifactFormat::Tiff, "image/tiff", 1.0, "TIFF header")
    } else if data.starts_with(b"fLaC") {
        (ArtifactFormat::Flac, "audio/flac", 1.0, "FLAC header")
    } else if data.len() >= 12 && &data[..4] == b"RIFF" && &data[8..12] == b"WAVE" {
        (ArtifactFormat::Wav, "audio/wav", 1.0, "RIFF WAVE header")
    } else if data.starts_with(b"ID3")
        || data
            .windows(2)
            .next()
            .is_some_and(|head| head[0] == 0xff && head[1] & 0xe0 == 0xe0)
    {
        (
            ArtifactFormat::Mp3,
            "audio/mpeg",
            0.85,
            "ID3 tag or MPEG audio frame sync",
        )
    } else if data.len() >= 12 && &data[4..8] == b"ftyp" {
        (ArtifactFormat::Mp4, "video/mp4", 0.95, "ISO BMFF ftyp box")
    } else if looks_like_text(data) {
        (
            ArtifactFormat::Text,
            "text/plain",
            0.8,
            "valid UTF-8 sample without NUL bytes",
        )
    } else {
        (
            ArtifactFormat::Unknown,
            "application/octet-stream",
            0.0,
            "no supported signature matched",
        )
    };

    Detection {
        format,
        media_type: media_type.to_owned(),
        confidence,
        source_adapter: if matches!(
            format,
            ArtifactFormat::Zip | ArtifactFormat::Tar | ArtifactFormat::Gzip
        ) {
            format!("builtin.{}", format.as_str())
        } else {
            "builtin.magic".to_owned()
        },
        evidence: vec![DetectionEvidence {
            kind: "magic".to_owned(),
            detail: evidence.to_owned(),
        }],
    }
}

fn is_mach_o(data: &[u8]) -> bool {
    const MAGICS: [[u8; 4]; 8] = [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
        [0xca, 0xfe, 0xba, 0xbf],
        [0xbf, 0xba, 0xfe, 0xca],
    ];
    data.get(..4)
        .is_some_and(|head| MAGICS.iter().any(|magic| head == magic))
}

fn looks_like_text(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(8192)];
    !sample.is_empty()
        && std::str::from_utf8(sample).is_ok_and(|text| {
            text.chars()
                .all(|character| !character.is_control() || matches!(character, '\n' | '\r' | '\t'))
        })
}

fn looks_like_tar(data: &[u8]) -> bool {
    let Some(header) = data.get(..512) else {
        return false;
    };
    let stored = parse_tar_octal(&header[148..156]);
    let Some(stored) = stored else {
        return false;
    };
    let calculated: u64 = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum();
    stored == calculated
}

fn parse_tar_octal(bytes: &[u8]) -> Option<u64> {
    let value = bytes
        .iter()
        .copied()
        .skip_while(|byte| *byte == 0 || *byte == b' ')
        .take_while(|byte| (b'0'..=b'7').contains(byte))
        .fold(0_u64, |current, byte| {
            current.saturating_mul(8) + u64::from(byte - b'0')
        });
    (value > 0).then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_uses_magic_not_extension() {
        assert_eq!(detect(b"PK\x03\x04payload").format, ArtifactFormat::Zip);
        assert_eq!(
            detect(b"SQLite format 3\0rest").format,
            ArtifactFormat::Sqlite
        );
        assert_eq!(detect(b"plain utf-8").format, ArtifactFormat::Text);
        assert_eq!(detect(b"").format, ArtifactFormat::Unknown);
        assert_eq!(detect(&[0x01, 0x02]).format, ArtifactFormat::Unknown);
    }
}
