use blobdive::detect::detect;
use serde::Deserialize;
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

type TestResult = Result<(), Box<dyn Error>>;

#[derive(Deserialize)]
struct Corpus {
    schema_version: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    id: String,
    class: String,
    payload: Payload,
    expected: Expected,
}

#[derive(Deserialize)]
struct Payload {
    encoding: String,
    data: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct Expected {
    format: String,
    media_type: String,
    confidence: f64,
    source_adapter: String,
}

#[derive(Deserialize)]
struct Metrics {
    schema_version: String,
    total_cases: usize,
    correct_cases: usize,
    overall_accuracy: f64,
    supported_archive: SupportedMetrics,
    negative: NegativeMetrics,
}

#[derive(Deserialize)]
struct SupportedMetrics {
    positive_cases: usize,
    true_positives: usize,
    false_positives: usize,
    false_negatives: usize,
    precision: f64,
    recall: f64,
}

#[derive(Deserialize)]
struct NegativeMetrics {
    cases: usize,
    true_negatives: usize,
    false_positives: usize,
    specificity: f64,
}

fn corpus_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/detection/v0.1")
}

fn read_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T, Box<dyn Error>> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "odd hex length").into());
    }
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            u8::from_str_radix(text, 16)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}

fn materialize(payload: &Payload) -> Result<Vec<u8>, Box<dyn Error>> {
    match payload.encoding.as_str() {
        "hex" => decode_hex(
            payload
                .data
                .as_deref()
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing hex data"))?,
        ),
        "gnu_tar_header" => {
            let mut header = tar::Header::new_gnu();
            header.set_path(
                payload.name.as_deref().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "missing TAR name")
                })?,
            )?;
            header.set_size(0);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_cksum();
            Ok(header.as_bytes().to_vec())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported payload encoding {other}"),
        )
        .into()),
    }
}

fn ratio(numerator: usize, denominator: usize) -> Result<f64, std::num::TryFromIntError> {
    if denominator == 0 {
        Ok(0.0)
    } else {
        Ok(f64::from(u32::try_from(numerator)?) / f64::from(u32::try_from(denominator)?))
    }
}

fn approximately_equal(left: f64, right: f64) -> bool {
    (left - right).abs() <= f64::EPSILON
}

#[test]
fn published_detection_metrics_are_reproducible() -> TestResult {
    let root = corpus_root();
    let corpus: Corpus = read_json(&root.join("corpus.json"))?;
    let expected_metrics: Metrics = read_json(&root.join("metrics.json"))?;
    assert_eq!(corpus.schema_version, "blobdive.detection-corpus.v1");
    assert_eq!(
        expected_metrics.schema_version,
        "blobdive.detection-metrics.v1"
    );

    let supported_formats = BTreeSet::from(["gzip", "tar", "zip"]);
    let mut ids = BTreeSet::new();
    let mut correct = 0;
    let mut supported_positive = 0;
    let mut supported_true_positive = 0;
    let mut supported_false_positive = 0;
    let mut negative_cases = 0;
    let mut negative_true = 0;

    for case in &corpus.cases {
        assert!(ids.insert(case.id.as_str()), "duplicate case {}", case.id);
        let actual = detect(&materialize(&case.payload)?);
        let format = actual.format.as_str();
        let matches = format == case.expected.format
            && actual.media_type == case.expected.media_type
            && approximately_equal(actual.confidence, case.expected.confidence)
            && actual.source_adapter == case.expected.source_adapter;
        correct += usize::from(matches);

        if case.class == "supported_archive" {
            supported_positive += 1;
            supported_true_positive += usize::from(matches);
        } else if supported_formats.contains(format) {
            supported_false_positive += 1;
        }
        if case.class == "negative" {
            negative_cases += 1;
            negative_true += usize::from(format == "unknown");
        }
    }

    let supported_false_negative = supported_positive - supported_true_positive;
    let total = corpus.cases.len();
    assert_eq!(expected_metrics.total_cases, total);
    assert_eq!(expected_metrics.correct_cases, correct);
    assert!(approximately_equal(
        expected_metrics.overall_accuracy,
        ratio(correct, total)?
    ));
    assert_eq!(
        expected_metrics.supported_archive.positive_cases,
        supported_positive
    );
    assert_eq!(
        expected_metrics.supported_archive.true_positives,
        supported_true_positive
    );
    assert_eq!(
        expected_metrics.supported_archive.false_positives,
        supported_false_positive
    );
    assert_eq!(
        expected_metrics.supported_archive.false_negatives,
        supported_false_negative
    );
    assert!(approximately_equal(
        expected_metrics.supported_archive.precision,
        ratio(
            supported_true_positive,
            supported_true_positive + supported_false_positive
        )?
    ));
    assert!(approximately_equal(
        expected_metrics.supported_archive.recall,
        ratio(supported_true_positive, supported_positive)?
    ));
    assert_eq!(expected_metrics.negative.cases, negative_cases);
    assert_eq!(expected_metrics.negative.true_negatives, negative_true);
    assert_eq!(
        expected_metrics.negative.false_positives,
        negative_cases - negative_true
    );
    assert!(approximately_equal(
        expected_metrics.negative.specificity,
        ratio(negative_true, negative_cases)?
    ));
    Ok(())
}
