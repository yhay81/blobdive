# Roadmap

## 0.1 — archive-first protocol

- ZIP/TAR/GZIP structural inspection
- extension-independent common-format detection
- deterministic root-anchored references
- bounded list/read and recursive traversal
- JSON/NDJSON, schemas, completions, cross-platform release artifacts

## 0.2 — corpus and format depth

- public detection/adversarial fixture corpus with accuracy metrics
- richer executable and package-container metadata
- input streaming design that preserves deterministic references
- better Unicode/raw-name presentation
- benchmark output bytes and latency against composed specialist tools

## 0.3 — parser isolation

- worker-process protocol with OS-enforced memory and wall-clock limits
- crash and hang containment fixtures
- capability declarations for external backends
- PDF, SQLite, image, and media metadata only after isolation gates

## v1.0 quality criteria

BlobDive reaches v1.0 only when every gate below has published, reproducible
evidence. Adding more parsers, downloads, or stars does not substitute for
correct classification, enforced bounds, or real downstream use.

### Product and compatibility

- CLI, JSON, NDJSON, schema, error, reference, and adapter-capability contracts
  remain compatible across at least two released pre-1.0 minor versions.
- Golden documents and root-anchored references from every supported contract
  version are accepted by the current reader or have a tested migration command
  and guide.
- Every claimed format has a precise detection, traversal, metadata, read, and
  unsupported-feature boundary; ambiguous input remains `unknown` rather than
  being guessed.
- New complex or native parsers are enabled only after the parser-isolation
  protocol contains their crashes, hangs, memory, and wall-clock use.

### Correctness and security

- The published labeled corpus has 100% precision and recall for every format
  and nested-container class claimed `supported`; weaker results downgrade the
  capability claim.
- The adversarial corpus has 100% detection of traversal paths, unsafe links,
  encryption, truncated structures, tampered references, excessive depth,
  entry counts, expansion ratios, and decompressed-byte budgets.
- No inspect, list, or read operation writes extracted content or follows a
  reference outside its digest-bound source and declared root.
- Continuous fuzzing or an equivalent reproducible malformed-input campaign
  runs for 30 days before v1.0 with no unresolved crash, hang, or unbounded
  allocation.
- An independent security review covers parser boundaries, path normalization,
  symlinks, archive bombs, recursive accounting, timeouts, reference integrity,
  diagnostic disclosure, and any worker sandbox; all critical and high findings
  are resolved.
- No known critical or high-severity vulnerability is open at release time.

### Performance and bounds

- Detect plus top-level inspect of the published 10,000-entry corpus completes
  below 2 seconds p95 on the documented GitHub-hosted runner.
- The published 100,000-entry bounded fixture keeps peak resident memory below
  256 MiB and terminates with explicit completeness or limit evidence.
- Source reads, decompressed bytes, depth, entries, ratio, output, wall-clock
  time, and diagnostic data never exceed configured bounds without a structured
  limit result.
- Benchmark inputs, licenses, runner image, raw measurements, and regression
  thresholds are versioned with the repository.

### Delivery and maintenance

- Required CI remains green on Linux, macOS, and Windows for 30 consecutive
  days before the v1.0 tag.
- Releases originate only from protected `main` and signed annotated tags; all
  native archives have verified checksums, GitHub-hosted provenance, and a
  CycloneDX SBOM attestation.
- The release and parser-incident runbooks are exercised by two maintainers, or
  governance records the single-maintainer continuity risk and a tested
  recovery procedure.
- Security reports are acknowledged within 3 business days and receive an
  initial assessment within 7.

### Adoption evidence

- At least three independent users, teams, or downstream integrations are
  recorded in [ADOPTERS.md](ADOPTERS.md) with the artifact decision BlobDive
  improved.
- At least two adopters report repeat use separated by 30 days.
- At least one public workflow uses bounded evidence or a safe refusal to drive
  a review, quarantine, routing, or extraction decision.
- At least one non-maintainer issue, discussion, corpus sample, documentation
  change, test, adapter, or code contribution is resolved and credited.

Maintainer-authored fixtures, automated downloads, stars, and synthetic
accounts cannot satisfy adoption gates.

Third-party plugins remain out of scope until isolation and schema negotiation
are proven.
