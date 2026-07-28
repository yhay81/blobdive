# Fuzzing BlobDive

BlobDive continuously fuzzes two untrusted, allocation-sensitive boundaries
with AddressSanitizer. The `artifact_input` target exercises byte-signature and
tar-header detection for arbitrary bytes, then exercises deterministic nested
artifact-reference parsing when the same input is UTF-8.

Install a current nightly toolchain and the pinned local runner, then run:

```bash
cargo install cargo-fuzz --version 0.13.2 --locked
mkdir -p fuzz/corpus/artifact_input
cp fuzz/seeds/* fuzz/corpus/artifact_input/
cargo +nightly fuzz run artifact_input
```

Pull requests receive a five-minute ClusterFuzzLite code-change run. A
15-minute batch run executes weekly on `main`, seeded by representative text
and nested-reference inputs, and publishes machine-readable findings to GitHub
code scanning.
Each code-changing `main` update also saves a comparison build so later pull
requests can distinguish newly introduced crashes. The accumulated corpus is
pruned after every weekly batch.

Minimized artifact inputs may still contain private material. Keep them private
until reviewed, add a deterministic regression test, and use
[SECURITY.md](SECURITY.md) for security-relevant findings.
