# BlobDive performance baseline

This directory defines the reproducible, observation-only baseline used to
calibrate BlobDive's v1.0 performance thresholds. It does not yet make timing
or memory a required pull-request check.

## Workloads

`generate_zip.py` uses only the Python standard library. It creates stored ZIP
archives with fixed timestamps, permissions, names, and payloads:

- `stored_zip_10k`: 10,000 entries, used for detection and a complete
  depth-one inspection;
- `stored_zip_100k`: 100,000 entries, inspected at depth one with a 200-entry
  limit to exercise central-directory parsing and bounded result production.

The fixtures and generator are synthetic project artifacts covered by the
repository's MIT license. Measurements run once, without warm-up, in this fixed
order: 10,000-entry detection, 10,000-entry complete inspection, then
100,000-entry bounded inspection.

The harness records wall-clock time and maximum resident memory from GNU
`time`, output bytes, fixture bytes, BlobDive's internal usage counters,
truncation evidence, runner identity, and the exact Git commit. Fixture archives
are generated per run and are never committed or uploaded.

## Run

The supported measurement environment is the `ubuntu-latest` GitHub-hosted
runner pinned by `.github/workflows/benchmark.yml`. Run it manually with the
**Benchmark** workflow, or on a compatible Linux machine:

```bash
benchmarks/run.sh benchmark-results.json
jq . benchmark-results.json
```

GNU `time`, GNU `stat`, `timeout`, `jq`, Python 3, Git, Cargo, and the locked
Rust dependency graph are required. The script builds release mode before
measurement; build time is excluded.

The workflow uploads the raw JSON for 90 days. Scheduled runs provide trend
data, but GitHub-hosted runners are shared infrastructure, so a single run is
not treated as a regression. Before enabling v1.0 gates, publish the runner
image, warm-up policy, sample count, p95 calculation, baseline window, and a
noise-aware regression rule together with the raw measurements.
