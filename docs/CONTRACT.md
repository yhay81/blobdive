# Machine contract

## Versioning

Top-level JSON envelopes use identifiers such as:

- `blobdive.detect.v1`
- `blobdive.inspect.v1`
- `blobdive.list.v1`
- `blobdive.read.v1`
- `blobdive.adapters.v1`
- `blobdive.error.v1`

Within a `v1` envelope, fields may be added but existing field meanings and
enum values are not silently changed. Removing/renaming a field or changing a
semantic guarantee requires a new envelope version and migration notes.

## Formats

`--format json` emits one pretty JSON document. `--format ndjson` emits the
same envelope on one line. Structured failures are written to stderr in the
selected format. Invalid Clap usage remains exit code 2 with standard usage
text.

Human output is not a compatibility API.

## Detection baseline

The [v0.1 detection corpus](../tests/fixtures/detection/README.md) freezes
extension-independent minimal signatures and negative near-misses. Text
detection requires a nonempty UTF-8 sample and rejects control characters other
than tab, carriage return, and newline. The checked-in scorer recomputes all
published counts, supported-archive precision and recall, and negative-case
specificity.

## Artifact nodes

Each node contains:

- deterministic `ref`;
- display name, detected format, media type, confidence, and evidence;
- observed or declared size and optional digest;
- adapter-scoped attributes;
- ordered children;
- findings;
- `{truncated, reasons}`.

`digest` exists only when BlobDive completely read that node. Archive metadata
nodes blocked by a budget, encryption, entry type, or parser failure have no
digest.

## Truncation versus errors

Inspection returns success when a trustworthy partial graph exists. Reasons
such as `max_depth`, `max_entries`, `max_decompressed_bytes`,
`max_compression_ratio`, `max_output_bytes`, `timeout`, `encrypted`, and
`adapter_failure` are explicit.

A hard error is returned when BlobDive cannot establish or resolve the root,
when a referenced source fails integrity verification, or when the minimum
envelope cannot fit.

## Read semantics

Read data is base64. `returned_sha256` covers exactly the decoded `data`.
`content_sha256` is present only if `truncated` is false. A root reference reads
the root file; a child reference reads the fully resolved uncompressed entry.

## Exit codes

- 0: success
- 1: operational/unsupported/archive/reference-syntax failure
- 2: usage error
- 3: hard resource or time budget
- 4: reference entry not found
- 5: source mutation or digest integrity mismatch

Complete generated schemas are available through `blobdive schema`.
