# BlobDive performance baseline

This directory defines and enforces BlobDive's reproducible v1.0 performance
thresholds on pull requests and in the weekly scheduled benchmark.

## Workloads

`generate_zip.py` uses only the Python standard library. It creates stored ZIP
archives with fixed timestamps, permissions, names, and payloads:

- `stored_zip_10k`: 10,000 entries, used for detection and a complete
  depth-one inspection;
- `stored_zip_100k`: 100,000 entries, inspected at depth one with a 200-entry
  limit to exercise central-directory parsing and bounded result production.

The fixtures and generator are synthetic project artifacts covered by the
repository's MIT license. Each sample performs untimed build and fixture setup.
The workflow discards one warm-up and captures 20 samples in this fixed order:
10,000-entry detection, 10,000-entry complete inspection, then 100,000-entry
bounded inspection.

The harness records wall-clock time and maximum resident memory from GNU
`time`, output bytes, fixture bytes, BlobDive's internal usage counters,
truncation evidence, runner identity, and the exact Git commit. Fixture archives
are generated per run and are never committed or uploaded.

## Enforced thresholds

The versioned policy in `thresholds.json` enforces:

- detect plus complete top-level inspect of the 10,000-entry corpus below
  2 seconds p95;
- peak RSS no greater than 256 MiB for every bounded 100,000-entry sample.

Twenty samples make nearest-rank p95 the second-slowest observation. Once
`baseline-ubuntu24.json` is present, metrics must also remain within the
stricter of the absolute limit and the versioned noise allowance: 1.5 times
baseline or baseline plus 100 ms for time and 16 MiB for memory.

## Run

The supported measurement environment is the `ubuntu-24.04` x86_64
GitHub-hosted runner selected by `.github/workflows/benchmark.yml`. Run one raw
sample on a compatible Linux machine with:

```bash
benchmarks/run.sh benchmark-results.json
jq . benchmark-results.json
```

Run evaluator tests with:

```bash
python3 -m unittest benchmarks/test_evaluate.py
```

GNU `time`, GNU `stat`, `timeout`, `jq`, Python 3, Git, Cargo, and the locked
Rust dependency graph are required. The script builds release mode before
measurement; build time is excluded.

The workflow uploads all 20 raw samples and the aggregate evaluation for 90
days, including raw samples from a failed threshold evaluation. The checked-in
baseline is refreshed only from a successful protected-runner evaluation.
