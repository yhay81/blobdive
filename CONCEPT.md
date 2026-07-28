# BlobDive concept and scope

## Thesis

BlobDive gives humans and software agents one bounded, recursive interface for
understanding unfamiliar software artifacts.

## Problem

Format-specific inspection tools have unrelated output contracts. Extraction
can overwrite paths or follow unsafe names, compressed inputs can expand
dramatically, nested content loses provenance, and parser failures are often
reported as unstructured text.

The primary job is:

> Identify an artifact, inspect its structure, and traverse only relevant
> children under explicit budgets.

## Product principles

1. Inspection never extracts, modifies, decrypts, or executes content.
2. Every traversed child has a deterministic reference and root provenance.
3. Source bytes, decompressed bytes, depth, entries, output, ratio, and elapsed
   time are bounded.
4. Detection reports evidence and confidence.
5. Truncation and unsupported features are data, not prose-only warnings.
6. One compact envelope covers every supported format.
7. Claims never exceed what the implementation and tests demonstrate.

## Implemented 0.1 surface

```text
blobdive detect <source>
blobdive inspect <source>
blobdive list <source> <artifact-ref>
blobdive read <source> <artifact-ref>
blobdive adapters
blobdive schema
blobdive completions
```

The archive-first MVP provides structural adapters for ZIP, TAR, and GZIP.
Magic detection also identifies common executable, document, database, image,
audio, video, text, and unknown inputs. Detection-only formats do not pretend
to expose structure.

References are anchored to the complete root SHA-256 and encode adapter entry
indexes. The source remains caller-owned and must be supplied again for
`list`/`read`; BlobDive keeps no hidden cache.

## Explicit 0.1 boundaries

- Local regular files only; standard input and remote URLs are deferred.
- ZIP support is limited to stored and deflate compression compiled into the
  binary.
- No artifact is materialized on disk.
- No malware classification or claim that content is safe.
- No rich ELF/Mach-O/PE, PDF, SQLite, image, audio, or video metadata yet.
- No third-party plugins.
- Built-in parsers are memory- and byte-bounded but in-process. The wall-clock
  limit is cooperative, not an operating-system kill deadline.

## Expansion gates

A new structural adapter must add:

1. signature evidence independent of filename extension;
2. a versioned attribute namespace;
3. unsafe-path/link/encryption semantics where applicable;
4. adversarial entry, byte, ratio, time, and output fixtures;
5. deterministic reference resolution;
6. documented parser and platform boundaries.

Process isolation must precede formats with materially larger parser attack
surfaces or external backends. Third-party plugins remain deferred until
capability declarations, isolation, and schema compatibility are specified.

## Success measures

- Zero observed budget or extraction violations in adversarial fixtures.
- Detection accuracy on a public extension-independent corpus.
- Stable schema compatibility across minor releases.
- Median commands and output bytes needed to answer nested-artifact questions.
- Downstream tools consuming the common envelope.
- Opt-in adopters and external adapter contributions.
