# Changelog

All notable changes are documented here. BlobDive follows Semantic Versioning
for CLI and machine-contract compatibility.

## [Unreleased]

### Added

- Added platform-specific, checksum- and provenance-verified native
  installation, update, and removal guidance.
- Added weekly installation smoke tests on Linux x86_64, macOS Apple Silicon
  and Intel, and Windows x86_64 using the published instructions.
- Enforced the published v1.0 10,000-entry latency and 100,000-entry bounded
  memory thresholds from 20-sample benchmark evidence on Ubuntu 24.04.

### Fixed

- Required archive entry EOF before assigning a digest, so ZIP payload CRC
  failures and underdeclared sizes fail closed while valid GZIP payloads that
  exactly meet a decompression limit remain complete.
- Read every member of a concatenated GZIP stream under shared budgets and
  fail closed when any member has an invalid checksum.
- Rejected performance evidence with a non-canonical commit identity,
  incomplete runner metadata, a non-raw sample marker, or reused sample paths.
- Enforced depth and shared entry budgets while resolving `list` and `read`
  references, including sequential entries scanned during TAR lookup, before
  opening an over-budget child.

## [0.3.0] - 2026-07-29

### Compatibility

- Preserved the public v0.2 CLI, document, reference, and adapter contracts.
  The digest-pinned v0.1 corpus and supported-platform tests continue to pass.

### Added

- Published downloadable SLSA provenance bundles beside every native archive
  and covered those bundles with `SHA256SUMS`.
- Added a privacy-conscious adoption report form that captures evaluation,
  repeat-use, limitations, evidence, and public-listing permission.
- Added a monthly maintainer-continuity drill that recovers the public Git
  mirror and verifies signed tags, release checksums, build/SBOM attestations,
  and the released native binary without repository write access.
- Added pull-request dependency review and weekly OpenSSF Scorecard analysis,
  with every action pinned to an immutable commit SHA.
- Enabled CodeQL default setup and restricted release and dependency-audit
  credentials to the minimum permissions required by each job.
- Added artifact-detection and nested-reference fuzzing with reproducible local
  `cargo-fuzz` execution, five-minute pull-request checks, and weekly
  ClusterFuzzLite AddressSanitizer batches.

## [0.2.0] - 2026-07-29

### Compatibility

- Preserved the public v0.1 CLI, document, reference, and adapter contracts.
  The v0.2 reader accepts the digest-pinned v0.1 contract corpus and
  root-anchored references unchanged; no migration is required.

### Added

- Public 28-case synthetic v0.1 detection corpus with reproducible metrics for
  all supported signatures, alternate signatures, and adversarial near-misses.
- Deterministic 10,000-entry full-scan and 100,000-entry bounded benchmark
  workloads with weekly raw JSON measurement artifacts.

### Changed

- Empty input and control-character-only UTF-8 are now classified as `unknown`
  instead of `text`.
- Updated the README status after the public 0.1.0 release.
- Defined measurable v1.0 compatibility, corpus accuracy, isolation, security,
  performance, delivery, maintenance, contribution, and repeat-adoption gates.

## [0.1.0] - 2026-07-28

### Added

- Rust CLI with detect, inspect, list, read, adapters, schema, and completions
  commands.
- Structural ZIP, TAR, and GZIP adapters plus common-format magic detection.
- Deterministic SHA-256-rooted references and integrity-checked resolution.
- Global depth, entry, source, decompression, ratio, output, and cooperative
  timeout budgets.
- Unsafe path, encryption, compression-ratio, malformed-entry, and truncation
  evidence without extraction.
- Versioned JSON/NDJSON contracts, JSON Schemas, stable exit-code classes, and
  cross-platform tests.
- OSS governance, security, support, contribution, and signed release policy.

[Unreleased]: https://github.com/yhay81/blobdive/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/yhay81/blobdive/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/yhay81/blobdive/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yhay81/blobdive/releases/tag/v0.1.0
