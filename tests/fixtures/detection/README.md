# Detection corpus

`v0.1/corpus.json` defines 28 deterministic, extension-independent detection
cases. Minimal byte payloads use lowercase hexadecimal; the TAR case uses a
fully specified empty GNU-header recipe so the 512-byte checksum fixture
remains readable and reproducible.

The corpus covers every v0.1 detection class, alternate ZIP/GIF/MP3 signatures,
Unicode text, invalid bytes, empty input, control characters, NUL-bearing text,
and near-miss ZIP and PNG signatures. These synthetic fixtures are authored for
BlobDive and distributed under the repository's MIT license.

`metrics.json` records the expected raw counts and ratios. The integration
scorer recomputes every value. This is a deterministic baseline, not the
diverse real-world corpus required for v1.0.
