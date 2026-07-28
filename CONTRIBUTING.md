# Contributing to BlobDive

Contributions of adapters, adversarial fixtures, detection evidence,
documentation, benchmarks, integrations, and reproducible bug reports are
welcome.

## Before opening an issue

- Use GitHub Discussions for usage questions and early design exploration.
- Search existing issues and reduce parser behavior to a synthetic artifact.
- Report security-sensitive behavior privately through
  [SECURITY.md](SECURITY.md).
- Do not attach malware, secrets, private documents, or copyrighted fixture
  corpora without explicit permission.

## Development setup

BlobDive requires Rust 1.85 or newer.

```bash
git clone https://github.com/yhay81/blobdive.git
cd blobdive
cargo test --all-targets --locked
```

## Making a change

1. Open an issue first for a new structural adapter, schema/reference change,
   security-boundary change, external backend, or dependency-policy change.
2. Preserve the no-extraction/no-execution core and root-digest reference
   verification.
3. Keep adapter attributes versionable and format-specific.
4. Add a normal fixture plus the relevant malformed, path, link, encryption,
   expansion, entry, output, depth, or timeout case.
5. Prefer small generated fixtures committed as code over opaque binaries.
6. Update schemas, safety limits, format support, roadmap, and changelog for
   public behavior.
7. Run:

   ```bash
   cargo fmt --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --all-targets --locked
   cargo +1.85.0 check --all-targets --locked
   cargo package --locked --allow-dirty
   ```

## Public contracts

Commands and flags, reference syntax, JSON/NDJSON envelopes, schema
identifiers, exit codes, format/truncation/finding enums, digest semantics,
entry order, and documented budget guarantees are public interfaces. Breaking
changes require migration notes and a versioned contract.

## Pull requests

Explain the user problem, smallest complete scope, parser trust implications,
exact budgets, platform behavior, verification, and failure paths. By
contributing, you agree that your contribution is licensed under MIT and
follows the [Code of Conduct](CODE_OF_CONDUCT.md).
