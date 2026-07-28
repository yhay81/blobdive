# Security policy

## Supported versions

BlobDive is pre-1.0. Security fixes are applied to the latest tagged release.
Older pre-1.0 releases are unsupported after a newer release is available.

| Version | Supported |
| --- | --- |
| Latest tagged release | Yes |
| Older pre-1.0 releases | No |
| Unreleased development builds | Best effort |

## Reporting a vulnerability

Use
[GitHub private vulnerability reporting](https://github.com/yhay81/blobdive/security/advisories/new).
Do not open a public issue for extraction/materialization, traversal, link
following, unintended execution, decompression or output budget escape,
parser denial of service, reference confusion, integrity bypass, or sensitive
content disclosure.

Include the BlobDive version, operating system, exact redacted command,
structured result/error, configured budgets, and the smallest synthetic
artifact that reproduces the issue. Do not attach real malicious or private
files before coordinating with the maintainer.

Acknowledgement is targeted within 7 days. The maintainer will validate the
report, coordinate disclosure, add a regression fixture, and publish a GitHub
Security Advisory when appropriate. These are volunteer-project targets, not
a service-level agreement.

## Trust and containment boundaries

- BlobDive opens caller-selected local regular files read-only and never
  materializes archive entries.
- Detection is evidence, not malware classification.
- Root inputs are held in memory up to `max_source_bytes`.
- ZIP/TAR/GZIP dependencies run in-process. Byte checks are enforced at
  BlobDive read boundaries; the cooperative timeout cannot interrupt one
  dependency call.
- Archive names, metadata, and explicitly read content can be sensitive.
  Results are not redacted or encrypted.
- Unsafe paths and links are reported as metadata and never passed to
  filesystem write APIs.
- Deterministic references are not capabilities or authorization tokens. They
  expose a root digest and entry positions.
- `list`/`read` fail if the supplied root digest changed. Same-size concurrent
  rewrites during a command remain outside the full 0.1 guarantee.
- Run hostile inputs inside an external OS/container sandbox with unprivileged
  credentials and independent CPU, memory, and wall-clock limits.

More detail is in [docs/SAFETY.md](docs/SAFETY.md).

## Release and dependency policy

Dependabot monitors Rust and GitHub Actions dependencies. CI checks
`Cargo.lock` against RustSec advisories. Tagged releases use signed annotated
tags and include checksums, CycloneDX SBOMs, and GitHub/Sigstore attestations.
See [RELEASING.md](RELEASING.md).

Pull requests are checked with GitHub Dependency Review and fail when they
introduce a dependency with a known moderate-or-higher-severity vulnerability.
A weekly OpenSSF Scorecard analysis publishes authenticated results and uploads
SARIF findings to GitHub code scanning.
