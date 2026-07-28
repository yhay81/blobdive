# Architecture

BlobDive is a stateless Rust CLI. It reads one caller-selected regular file,
builds an in-memory view inside a source-byte limit, and emits one result.

## Components

- `detect` performs deterministic magic checks and TAR header-checksum
  validation.
- `reference` creates and parses root-digest plus adapter/index references.
- `budget` owns one operation-wide deadline and counters for all nested
  adapters.
- `engine` reads sources, verifies references, traverses archives, contains
  child parser failures, and prunes output to the serialized byte limit.
- `cli` maps commands to versioned models, JSON Schemas, human output, and
  stable error classes.

No daemon, cache, registry, temporary extraction directory, or network service
is involved.

## Traversal

1. Open the source read-only and reject non-regular files.
2. Check its metadata size against `max_source_bytes`.
3. Read exactly the observed size under the operation deadline.
4. Reject size/mtime changes observed during that read.
5. Compute the root SHA-256 and deterministic root reference.
6. Detect the root by bytes, not extension.
7. For structural formats, visit entries in archive order.
8. Check entry count, declared expansion, remaining decompression bytes,
   compression ratio, depth, and deadline before reading content.
9. Recurse only after a complete bounded child read.
10. Serialize and remove trailing descendants until the response fits the
    output limit.

Counters are global to the invocation. A nested archive cannot reset a budget.

## Reference model

```text
artifact://sha256:<64 lowercase hex>![/<adapter>/<8-digit entry index>]...
```

Indexes are stable for identical bytes and avoid using attacker-controlled
paths as identifiers. Raw names are retained as base64; display names are
lossy UTF-8 and must never be interpreted as filesystem authority.

`list` and `read` re-hash the supplied root. Resolution fails before child
access if the digest differs.

## Failure containment

Malformed root containers and child read failures are normally recorded as
`adapter_failure` findings on the affected node while the overall inspection
remains valid. Hard failures are reserved for cases where no trustworthy
result can be returned: source I/O/budget failures, invalid or stale
references, resolution failure, or an envelope too small for even the root.

Adapter code is safe Rust but in-process in 0.1. Cooperative byte/deadline
checks surround reads; they cannot interrupt one call already executing inside
a dependency.
