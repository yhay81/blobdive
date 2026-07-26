# BlobDive

Bounded, recursive inspection of software and media artifacts.

> Status: concept stage. The initial product is read-only.

BlobDive identifies a file, opens its internal structure safely, and returns a common graph of nested entries, metadata, dependencies, signatures, and findings. Agents can inspect only the fields and depth they need.

```bash
blobdive inspect app.zip --depth 3 --fields type,entries,signatures
blobdive inspect binary --fields arch,imports,exports
blobdive inspect report.pdf --fields pages,outline,attachments
blobdive read ref_01J... --limit 100
```

## Why

Understanding an unknown artifact currently requires choosing among `file`, archive tools, `ffprobe`, `pdfinfo`, binary analyzers, package tools, and format-specific libraries. Their output contracts do not compose.

BlobDive provides one read-only discovery surface while preserving format-specific detail behind typed references.

## Product principles

- Read-only core.
- Bounded depth, entries, bytes, and output.
- No implicit extraction or execution.
- Nested content represented as a typed graph.
- Format adapters are isolated and testable.
- Unknown data remains inspectable without pretending certainty.

## Initial scope

Archives, common package formats, ELF/Mach-O/PE binaries, PDF, SQLite, images, audio, and video.

See [CONCEPT.md](CONCEPT.md) for the adapter model and proposed MVP.

## License

MIT
