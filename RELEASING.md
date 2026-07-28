# Releasing BlobDive

Only a release manager named in [GOVERNANCE.md](GOVERNANCE.md) may release.

1. Confirm the version is unpublished and `CHANGELOG.md`, `Cargo.toml`, and
   `Cargo.lock` agree.
2. Confirm the release commit is on `main`, the worktree is clean, and all
   required checks pass.
3. Run:

   ```bash
   cargo fmt --check
   cargo clippy --all-targets --locked -- -D warnings
   cargo test --all-targets --locked
   cargo +1.85.0 check --all-targets --locked
   cargo package --locked --allow-dirty
   cargo build --release --locked
   target/release/blobdive --format json schema --document brief
   ```

4. Dogfood release-binary detection, nested inspection/read/list, unsafe-name
   reporting, ratio rejection, stale-reference integrity, and output pruning.
   Confirm no archive entry was materialized.
5. Confirm Linux, macOS, Windows, Rust 1.85, RustSec, schemas, documentation
   links, package contents, and repeated adversarial fixtures in hosted CI.
6. Create and push a signed annotated tag:

   ```bash
   git tag -s v0.2.0 -m "BlobDive 0.2.0"
   git push origin v0.2.0
   ```

7. The release workflow creates four native archives, completions, a CycloneDX
   SBOM, `SHA256SUMS`, a GitHub release, and GitHub/Sigstore build-provenance
   and SBOM attestations. Each archive includes a downloadable
   `.intoto.jsonl` provenance bundle for local verification.
8. Download all assets into a clean directory. Verify checksums and both
   attestation predicates:

   ```bash
   sha256sum --check SHA256SUMS
   gh attestation verify blobdive-v0.2.0-linux-x86_64.tar.gz \
     --repo yhay81/blobdive
   gh attestation verify blobdive-v0.2.0-linux-x86_64.tar.gz \
     --repo yhay81/blobdive \
     --bundle blobdive-v0.2.0-linux-x86_64.tar.gz.intoto.jsonl \
     --signer-workflow yhay81/blobdive/.github/workflows/release.yml
   gh attestation verify blobdive-v0.2.0-linux-x86_64.tar.gz \
     --repo yhay81/blobdive \
     --predicate-type https://cyclonedx.org/bom
   ```

9. Inspect every archive layout. On each native platform run `--version`,
   completion generation, brief schema emission, and a nested ZIP lifecycle.
10. Release notes must link installation, checksums, SBOM/provenance
    verification, changelog, platform guarantees, safety limits, and private
    security reporting.

Publishing to crates.io remains manual until registry ownership and credentials
are configured:

```bash
cargo publish --locked
```

Never move or reuse a published tag or version. Follow a failed release with a
documented patch release.
