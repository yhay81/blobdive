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

## 1.0 gates

- documented schema compatibility history
- supported-format corpus with regression metrics
- no known budget/extraction violations
- reproducible signed releases and verified provenance/SBOM
- at least three opt-in downstream integrations or adopters
- sustainable issue response, security, and maintainer rotation practices

Third-party plugins remain out of scope until isolation and schema negotiation
are proven.
