# Support

## Where to ask

- Use [GitHub Discussions](https://github.com/yhay81/blobdive/discussions) for
  installation, format, budget, reference, and integration questions.
- Use a structured
  [GitHub issue](https://github.com/yhay81/blobdive/issues/new/choose) for
  reproducible bugs or scoped feature requests.
- Follow [SECURITY.md](SECURITY.md) for vulnerabilities.

BlobDive is maintained by volunteers. Reports with a minimal synthetic
artifact, exact version, operating system, command, budgets, and redacted
structured output are easiest to investigate.

Never post malware, secrets, private documents, or unredacted `read` output.

## Supported environment

The latest tagged pre-1.0 release supports Linux x86-64, macOS Intel and Apple
Silicon, Windows x86-64, and Rust 1.85 or newer when building from source.

Collect:

```bash
blobdive --version
blobdive --format json schema --document brief
blobdive --format json adapters
```

Also report the root format and size, nested depth, entry count, compression
methods, and whether the behavior changes under smaller budgets.

## Scope

Support does not cover malware classification, safe handling without an
external sandbox, unlimited inputs, rich metadata for detection-only formats,
decryption, artifact repair, remote URLs, standard input, or third-party
plugins.
