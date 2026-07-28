# BlobDive

Bounded, read-only inspection of nested software artifacts.

> Status: BlobDive 0.1.0 is released. Detection, recursive ZIP/TAR/GZIP
> inspection, deterministic references, bounded reads, schemas, and
> cross-platform tests are available.

BlobDive answers “what is inside this file?” without extracting entries,
executing content, trusting filename extensions, or producing unbounded output.

```bash
blobdive --format json detect release.bin
blobdive --format json inspect release.zip --depth 2 --max-entries 200
```

An inspection returns a typed tree and stable references:

```json
{
  "schema_version": "blobdive.inspect.v1",
  "root": {
    "ref": "artifact://sha256:…!",
    "format": "zip",
    "children": [
      {
        "ref": "artifact://sha256:…!/zip/00000000",
        "display_name": "manifest.json",
        "format": "text"
      }
    ]
  }
}
```

## Why

Inspecting an unfamiliar artifact usually means guessing among `file`, archive
tools, binary analyzers, media probes, and format-specific libraries. Their
contracts do not compose, archive extraction can materialize unsafe paths, and
recursive input can exhaust memory or output budgets.

BlobDive provides one local protocol with:

- content-signature detection independent of extensions;
- a common, versioned artifact envelope;
- recursive archive traversal with explicit depth and entry limits;
- decompression byte and compression-ratio limits;
- deterministic references anchored to the root SHA-256;
- base64 reads that never write archive entries to disk;
- structured truncation, findings, usage, and errors;
- JSON, NDJSON, JSON Schemas, and shell completions.

## Install

Download a native archive from
[GitHub Releases](https://github.com/yhay81/blobdive/releases), or install from
source with Rust 1.85 or newer:

```bash
cargo install --path . --locked
```

Generate completion scripts with `blobdive completions bash` (also `zsh`,
`fish`, `powershell`, and `elvish`).

## Detect and inspect

`detect` reads a complete regular file inside `--max-source-bytes`, computes
its SHA-256, and reports detection evidence:

```bash
blobdive --format json detect artifact.dat \
  --max-source-bytes 67108864 \
  --timeout 10s
```

Detection behavior is scored against the public
[v0.1 synthetic corpus](tests/fixtures/detection/README.md). The baseline
covers every v0.1 format and adversarial empty, control-character, NUL, invalid,
and near-miss inputs; it is explicitly not a substitute for the broader
real-world corpus required by the v1.0 gate.

Performance observations use deterministic 10,000-entry complete and
100,000-entry bounded ZIP workloads. The
[benchmark methodology](benchmarks/README.md) documents the environment,
measurements, and the distinction between the current raw baseline and future
v1.0 regression thresholds.

`inspect` recursively opens supported containers:

```bash
blobdive --format json inspect artifact.dat \
  --depth 2 \
  --max-entries 200 \
  --max-source-bytes 67108864 \
  --max-decompressed-bytes 67108864 \
  --max-compression-ratio 100 \
  --max-output-bytes 2097152 \
  --timeout 10s
```

Depth 0 reports the root only. Depth 1 reports direct children. Entry,
decompression, and elapsed-time counters are shared across the complete
recursive operation. Output-budget exhaustion removes trailing descendants and
records `max_output_bytes`; it never emits invalid JSON.

## List and read references

References use archive entry indexes, not archive paths. They are deterministic
for identical root bytes and remain opaque to callers:

```bash
inspection=$(blobdive --format json inspect release.zip --depth 2)
root_ref=$(printf '%s' "$inspection" | jq -r .root.ref)
child_ref=$(printf '%s' "$inspection" | jq -r '.root.children[0].ref')

blobdive --format json list release.zip "$root_ref"
blobdive --format json read release.zip "$child_ref" --max-bytes 65536
```

`list` and `read` require the original source path. BlobDive re-hashes it and
returns exit code 5 if it no longer matches the reference. The CLI keeps no
artifact cache or path registry. `read` returns base64 plus the digest of the
returned bytes; `content_sha256` is present only when the complete referenced
content was returned.

## Format support

| Format | Detection | Structure/list/read |
| --- | :---: | :---: |
| ZIP (stored and deflate) | yes | yes |
| TAR | yes | yes |
| GZIP | yes | yes |
| ELF, Mach-O, PE | yes | no |
| PDF, SQLite | yes | no |
| PNG, JPEG, GIF, WebP, TIFF | yes | no |
| FLAC, WAV, MP3, MP4 | yes | no |
| UTF-8 text and unknown bytes | yes | no |

Run `blobdive --format json adapters` for the machine-readable capability
list. Unsupported compression, encrypted ZIP entries, links, unsafe paths, and
malformed child entries are reported; BlobDive does not silently extract,
decrypt, follow, or execute them.

## Machine contract

Every data command supports `--format human|json|ndjson`. NDJSON emits one
compact result envelope per invocation. Inspect full schemas with:

```bash
blobdive --format json schema --document brief
blobdive --format json schema --document inspect
blobdive --format json schema --document error
```

Stable exit-code classes are:

| Code | Meaning |
| ---: | --- |
| 0 | Success, including a result with explicit truncation/findings |
| 1 | I/O, unsupported operation, invalid reference syntax, or archive error |
| 2 | Invalid CLI usage |
| 3 | A hard source, resource, output, or time budget prevented a result |
| 4 | Reference entry not found |
| 5 | Source changed or no longer matches the reference digest |

See [docs/CONTRACT.md](docs/CONTRACT.md) for compatibility rules.

## Security boundaries

- Inputs and archive entries are never written, extracted, decrypted, or
  executed. The original source file is opened read-only.
- ZIP/TAR/GZIP parsers run in-process in 0.1. Byte limits are hard at BlobDive
  read boundaries, but the timeout is cooperative and cannot preempt a single
  library call. Process-level parser isolation is a roadmap item.
- The complete root file is held in memory up to the caller-selected
  `max_source_bytes`. Raising limits raises memory and parser exposure.
- Unsafe names are preserved as base64 and flagged. Normalized paths are
  informational and are never used for filesystem writes.
- Detection identifies a format; it never claims that an artifact is benign.
- Concurrent source modification is unsupported. Size/mtime changes during a
  read and digest mismatches between commands fail closed.
- Human and machine output can reveal filenames and content selected by
  `read`. Treat results as sensitive when inputs are sensitive.

Read [SECURITY.md](SECURITY.md) and [docs/SAFETY.md](docs/SAFETY.md) before
processing adversarial artifacts.

## Development

```bash
cargo fmt --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
cargo +1.85.0 check --all-targets --locked
```

Contribution, support, governance, and release policies are in
[CONTRIBUTING.md](CONTRIBUTING.md), [SUPPORT.md](SUPPORT.md),
[GOVERNANCE.md](GOVERNANCE.md), and [RELEASING.md](RELEASING.md).

## License

MIT
