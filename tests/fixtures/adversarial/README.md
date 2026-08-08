# Adversarial archive corpus

`v0.1/corpus.json` publishes 90 deterministic labels for the nine hostile-input
classes required by the BlobDive v1.0 quality gate:

- traversal paths;
- unsafe symbolic and hard links;
- encrypted ZIP entries;
- truncated archive structures;
- digest-bound reference tampering;
- excessive recursion depth;
- archive entry-count exhaustion;
- excessive expansion ratios; and
- decompressed-byte exhaustion.

There are ten cases in each class. The labels are generated independently of
BlobDive by `v0.1/generate_corpus.py`; the Rust scorer materializes each fixture
in a temporary sandbox and passes it through the production `inspect` or `read`
path. No public network access or checked-in binary fixture is required.

`v0.1/metrics.json` records the canonical corpus digest, per-class detection
counts, overall detection rate, and sandbox write count. CI requires 100%
detection in every class and zero materialized paths.

Reproduce the evidence with:

```console
python3 tests/fixtures/adversarial/v0.1/generate_corpus.py --check
cargo test --test adversarial_corpus --locked
```

The corpus metadata and generator are licensed under the repository MIT
license. Synthetic fixtures contain no third-party payloads.
