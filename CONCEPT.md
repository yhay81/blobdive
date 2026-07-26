# ArtiProbe concept

## One-line thesis

ArtiProbe gives humans and software agents one bounded, recursive interface for
understanding unfamiliar software and media artifacts.

## Problem

Agents routinely encounter archives, packages, executables, PDFs, databases,
images, audio, and video. Today they must guess a sequence of format-specific
tools, learn different output contracts, and manually connect nested content.
That wastes tokens and creates safety problems:

- archive extraction can overwrite files or follow unsafe paths;
- compressed inputs can expand without a bound;
- text output is inconsistent and often enormous;
- nested artifacts lose provenance;
- a failed parser can terminate the entire investigation.

## Target users and jobs

- Coding and security agents inspecting build outputs and attachments.
- Maintainers triaging unfamiliar repository artifacts.
- Release and supply-chain tooling.
- Automation that needs metadata without full extraction.

The primary job is: **identify an artifact, inspect its structure, and traverse
only the relevant children under explicit budgets.**

## Product principles

1. Inspection does not extract or modify by default.
2. Every child has a stable reference and provenance.
3. Depth, entries, bytes, time, and decompression ratio are bounded.
4. Type detection reports evidence and confidence.
5. Truncation and unsupported features are data, not prose warnings.
6. Adapters fail in isolation.
7. One compact envelope covers every format.

## Proposed command contract

```text
artiprobe schema --brief --format json
artiprobe detect release.bin --format json
artiprobe inspect release.zip --depth 2 --max-entries 200 --format json
artiprobe list 'artifact://<digest>!/path/to/child' --format json
artiprobe read 'artifact://<digest>!/manifest.json' --max-bytes 65536
artiprobe adapters --format json
```

References are opaque identifiers, not filesystem paths. A caller can pass a
reference back to ArtiProbe without learning adapter-specific syntax.

## Common artifact envelope

Every inspected node has:

```json
{
  "ref": "artifact://...",
  "type": "application/...",
  "size": 1234,
  "digest": "sha256:...",
  "attributes": {},
  "children": [],
  "truncated": false,
  "confidence": 0.99,
  "source_adapter": "..."
}
```

Additional fields record detection evidence, warnings, parser version, parent
relationship, and which budget stopped traversal. Format-specific metadata lives
under versioned `attributes` namespaces.

## Safety and resource model

Every operation accepts budgets for:

- recursive depth;
- entries and nodes;
- bytes read and bytes returned;
- wall-clock and CPU time;
- decompressed bytes and compression ratio;
- per-adapter memory.

Archive paths are normalized and never materialized during inspection. Symlinks,
device entries, encrypted content, overlapping ranges, and suspicious expansion
are reported explicitly. Risky parsers should run in isolated worker processes.

## Initial adapters

Version 0.1 will prioritize:

- tar, zip, gzip, and common package containers;
- ELF, Mach-O, and PE executables;
- PDF structure and metadata;
- SQLite schema and bounded table summaries;
- common image metadata;
- audio and video stream metadata through a constrained backend.

Adapters are selected from detection evidence rather than filename extension.

## Initial scope

- Local files and standard input.
- Detection, metadata inspection, child listing, and bounded reads.
- Recursive typed artifact graphs.
- Versioned JSON and NDJSON output.
- Content digests and deterministic references.
- Crash-isolated built-in adapters.

## Non-goals

- Malware detection or a claim that an artifact is safe.
- Modifying, converting, or repairing artifacts.
- Unbounded extraction.
- Rendering full office documents.
- Replacing specialist reverse-engineering tools.
- Downloading remote URLs by default.

## Differentiation and defensibility

The opportunity is a universal artifact protocol, not a shallow wrapper around
`file`. High-quality detection, safe traversal, common provenance, and a growing
adapter corpus create compounding value. Other tools can build on the graph
without teaching agents a new CLI for each format.

## Success measures

- Format and nested-container coverage in a public corpus.
- Detection accuracy independent of extensions.
- Zero budget violations in adversarial fixtures.
- Parser crash containment rate.
- Median tokens and commands needed to answer artifact questions.
- Number of downstream tools consuming the common envelope.

## Key risks and open questions

- Parser attack surface grows with format coverage.
- Metadata schemas can become an unstable union of adapter quirks.
- Some formats require expensive or stateful parsing.
- Digesting large artifacts conflicts with low-latency inspection.
- A plugin system expands adoption but also the trust boundary.

The project should delay third-party in-process plugins until isolation,
capability declarations, and schema compatibility are well specified.
