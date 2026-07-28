# Changelog

All notable changes are documented here. BlobDive follows Semantic Versioning
for CLI and machine-contract compatibility.

## [Unreleased]

### Added

- Added a privacy-conscious adoption report form that captures evaluation,
  repeat-use, limitations, evidence, and public-listing permission.
- Added a monthly maintainer-continuity drill that recovers the public Git
  mirror and verifies signed tags, release checksums, build/SBOM attestations,
  and the released native binary without repository write access.

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

[Unreleased]: https://github.com/yhay81/blobdive/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/yhay81/blobdive/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/yhay81/blobdive/releases/tag/v0.1.0
