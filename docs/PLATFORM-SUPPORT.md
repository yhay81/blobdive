# Platform support

BlobDive release archives and tests target:

| Platform | Target |
| --- | --- |
| Linux x86-64 | `linux-x86_64` |
| macOS Intel | `macos-x86_64` |
| macOS Apple Silicon | `macos-aarch64` |
| Windows x86-64 | `windows-x86_64` |

The Rust source supports Rust 1.85 and newer.

Core behavior is platform-neutral: regular-file reads, SHA-256 references,
archive entry ordering, base64 raw names, and JSON contracts are identical.
Display names can differ only where the caller supplies a platform-specific
source filename.

Symbolic links passed as the root source are followed by the operating system
and then required to resolve to a regular file. Archive links are metadata only
and are never followed.

Case sensitivity, path separators, and reserved device names do not affect
entry safety because archive names are never materialized. Both `/` and `\`
are treated as separators for conservative unsafe-name reporting.
