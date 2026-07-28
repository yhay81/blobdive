# Safety model

## Guarantees

- Sources are opened without write access.
- Entries are never extracted or passed to an operating-system path API.
- Artifact bytes are never executed.
- Links and encrypted entries are never followed or decrypted.
- Entry identifiers use archive indexes, not names.
- Raw names are preserved as base64 and risky names are flagged.
- Source, decompression, entry, recursion, output, ratio, and cooperative time
  limits are applied across one invocation.
- References fail closed after root-byte changes.

Tests exercise parent traversal names, compressed expansion, malformed ZIP,
nested references, stale references, entry/output/time limits, and no
materialization.

## Non-guarantees

- Format detection is not malware detection or a safety verdict.
- In-process parser dependencies may contain defects.
- The timeout cannot preempt a dependency call already in progress.
- CPU use inside one compression/parser call is not a separately enforced
  budget in 0.1.
- Caller-raised limits intentionally permit larger memory and parser exposure.
- A same-size concurrent rewrite may evade metadata-change detection during one
  command. Subsequent reference resolution still verifies the root digest.
- Display-name normalization is informational, not a safe extraction policy.

For hostile inputs, run BlobDive as an unprivileged user inside an
OS/container sandbox with filesystem, memory, CPU, and time limits. Do not
grant network access merely to inspect local files.

## Findings

`suspicious` findings indicate properties such as unsafe archive names or a
ratio over the configured limit. They are evidence for review, not a
classification that content is malicious.
