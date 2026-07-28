#!/usr/bin/env bash
set -euo pipefail

export LC_ALL=C

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
result_path="${1:-${root_dir}/benchmark-results.json}"
binary="${root_dir}/target/release/blobdive"
generator="${root_dir}/benchmarks/generate_zip.py"

for dependency in cargo git jq python3 stat timeout uname; do
  command -v "${dependency}" >/dev/null || {
    printf 'missing benchmark dependency: %s\n' "${dependency}" >&2
    exit 1
  }
done

if ! /usr/bin/time --version 2>&1 | grep -qi 'GNU time'; then
  printf 'benchmarks/run.sh requires GNU /usr/bin/time (the Ubuntu runner provides it)\n' >&2
  exit 1
fi

temp_dir="$(mktemp -d)"
trap 'rm -rf "${temp_dir}"' EXIT

fixture_10k="${temp_dir}/stored-10000.zip"
fixture_100k="${temp_dir}/stored-100000.zip"

cd "${root_dir}"
cargo build --release --locked
python3 "${generator}" --entries 10000 --output "${fixture_10k}"
python3 "${generator}" --entries 100000 --output "${fixture_100k}"

measure() {
  local metrics_path="$1"
  local output_path="$2"
  shift 2

  /usr/bin/time \
    -f '{"wall_seconds": %e, "max_rss_kib": %M, "exit_code": %x}' \
    -o "${metrics_path}" \
    timeout --signal=KILL 45s "$@" >"${output_path}"
  jq -e . "${metrics_path}" >/dev/null
  jq -e . "${output_path}" >/dev/null
}

detect_metrics="${temp_dir}/detect-10k.metrics.json"
detect_output="${temp_dir}/detect-10k.output.json"
inspect_10k_metrics="${temp_dir}/inspect-10k-full.metrics.json"
inspect_10k_output="${temp_dir}/inspect-10k-full.output.json"
inspect_100k_metrics="${temp_dir}/inspect-100k-bounded.metrics.json"
inspect_100k_output="${temp_dir}/inspect-100k-bounded.output.json"

measure "${detect_metrics}" "${detect_output}" \
  "${binary}" --format json detect "${fixture_10k}" \
  --max-source-bytes 67108864 --timeout 30s

measure "${inspect_10k_metrics}" "${inspect_10k_output}" \
  "${binary}" --format json inspect "${fixture_10k}" \
  --depth 1 \
  --max-entries 10000 \
  --max-source-bytes 67108864 \
  --max-decompressed-bytes 67108864 \
  --max-compression-ratio 100 \
  --max-output-bytes 134217728 \
  --timeout 30s

measure "${inspect_100k_metrics}" "${inspect_100k_output}" \
  "${binary}" --format json inspect "${fixture_100k}" \
  --depth 1 \
  --max-entries 200 \
  --max-source-bytes 67108864 \
  --max-decompressed-bytes 67108864 \
  --max-compression-ratio 100 \
  --max-output-bytes 16777216 \
  --timeout 30s

mkdir -p "$(dirname "${result_path}")"
jq -n \
  --arg generated_at "$(date -u +'%Y-%m-%dT%H:%M:%SZ')" \
  --arg git_sha "$(git rev-parse HEAD)" \
  --arg runner_os "${RUNNER_OS:-Linux}" \
  --arg runner_arch "$(uname -m)" \
  --arg runner_image "${ImageOS:-unknown}" \
  --arg runner_image_version "${ImageVersion:-unknown}" \
  --argjson fixture_10k_bytes "$(stat -c '%s' "${fixture_10k}")" \
  --argjson fixture_100k_bytes "$(stat -c '%s' "${fixture_100k}")" \
  --argjson detect_output_bytes "$(stat -c '%s' "${detect_output}")" \
  --argjson inspect_10k_output_bytes "$(stat -c '%s' "${inspect_10k_output}")" \
  --argjson inspect_100k_output_bytes "$(stat -c '%s' "${inspect_100k_output}")" \
  --slurpfile detect_metrics "${detect_metrics}" \
  --slurpfile detect_output "${detect_output}" \
  --slurpfile inspect_10k_metrics "${inspect_10k_metrics}" \
  --slurpfile inspect_10k_output "${inspect_10k_output}" \
  --slurpfile inspect_100k_metrics "${inspect_100k_metrics}" \
  --slurpfile inspect_100k_output "${inspect_100k_output}" \
  '{
    schema_version: "blobdive.benchmark.v1",
    generated_at: $generated_at,
    git_sha: $git_sha,
    runner: {
      os: $runner_os,
      arch: $runner_arch,
      image: $runner_image,
      image_version: $runner_image_version
    },
    fixtures: [
      {
        id: "stored_zip_10k",
        generator: "benchmarks/generate_zip.py",
        entries: 10000,
        size_bytes: $fixture_10k_bytes
      },
      {
        id: "stored_zip_100k",
        generator: "benchmarks/generate_zip.py",
        entries: 100000,
        size_bytes: $fixture_100k_bytes
      }
    ],
    measurements: [
      {
        id: "detect_10k",
        fixture: "stored_zip_10k",
        process: $detect_metrics[0],
        output_bytes: $detect_output_bytes,
        result: {
          schema_version: $detect_output[0].schema_version,
          detection: $detect_output[0].detection,
          size: $detect_output[0].size
        }
      },
      {
        id: "inspect_10k_full",
        fixture: "stored_zip_10k",
        process: $inspect_10k_metrics[0],
        output_bytes: $inspect_10k_output_bytes,
        result: {
          schema_version: $inspect_10k_output[0].schema_version,
          usage: $inspect_10k_output[0].usage,
          children_emitted: ($inspect_10k_output[0].root.children | length),
          truncation: $inspect_10k_output[0].root.truncation
        }
      },
      {
        id: "inspect_100k_bounded",
        fixture: "stored_zip_100k",
        process: $inspect_100k_metrics[0],
        output_bytes: $inspect_100k_output_bytes,
        result: {
          schema_version: $inspect_100k_output[0].schema_version,
          usage: $inspect_100k_output[0].usage,
          children_emitted: ($inspect_100k_output[0].root.children | length),
          truncation: $inspect_100k_output[0].root.truncation
        }
      }
    ],
    derived: {
      detect_plus_inspect_10k_wall_seconds:
        ($detect_metrics[0].wall_seconds + $inspect_10k_metrics[0].wall_seconds),
      inspect_100k_bounded_peak_rss_mib:
        ($inspect_100k_metrics[0].max_rss_kib / 1024)
    },
    threshold_status: "observation_only"
  }' >"${result_path}"

jq -e '
  .schema_version == "blobdive.benchmark.v1"
  and (.measurements | length == 3)
  and all(
    .measurements[];
    .process.exit_code == 0
      and .process.wall_seconds >= 0
      and .process.max_rss_kib > 0
      and .output_bytes > 0
  )
  and any(
    .measurements[];
    .id == "inspect_10k_full"
      and .result.children_emitted == 10000
      and (.result.truncation.reasons | length == 0)
  )
  and any(
    .measurements[];
    .id == "inspect_100k_bounded"
      and .result.usage.entries_visited == 200
      and (.result.truncation.reasons | index("max_entries") != null)
  )
' "${result_path}" >/dev/null

printf 'wrote %s\n' "${result_path}"
