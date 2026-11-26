# Fuzzing BlobDive

BlobDive provides a fuzz target for two untrusted, allocation-sensitive boundaries
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

Automatic hosted fuzzing is paused. The ClusterFuzzLite workflow definitions
are retained for future use. Their five-minute code-change and fifteen-minute
batch campaigns exceed the current one-minute hosted job limit. Use the local
runner above for longer runs.

Minimized artifact inputs may still contain private material. Keep them private
until reviewed, add a deterministic regression test, and use
[SECURITY.md](SECURITY.md) for security-relevant findings.
