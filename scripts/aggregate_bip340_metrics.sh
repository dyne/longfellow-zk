#!/usr/bin/env bash

set -Eeuo pipefail

usage() {
  printf 'usage: %s RELEASE_DIR OUT_DIR [TAG] [REPO]\n' "$0" >&2
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  }
}

csv_escape() {
  local value=${1:-}
  value=${value//\"/\"\"}
  if [[ "$value" == *","* || "$value" == *$'\n'* || "$value" == *"\""* ]]; then
    printf '"%s"' "$value"
  else
    printf '%s' "$value"
  fi
}

if [[ $# -lt 2 || $# -gt 4 ]]; then
  usage
  exit 2
fi

release_dir=$1
out_dir=$2
tag=${3:-}
repo=${4:-}

[[ -d "$release_dir" ]] || {
  printf 'release directory not found: %s\n' "$release_dir" >&2
  exit 1
}

require_cmd awk
require_cmd find
require_cmd gnuplot

mkdir -p "$out_dir"

metrics_csv="$out_dir/longfellow-zk_bip340_metrics.csv"
plot_data="$out_dir/bip340_metrics_plot.dat"
plot_png="$out_dir/longfellow-zk_bip340_metrics.png"
release_body="$out_dir/bip340_metrics_release.md"

printf 'artifact,source_file,target,circuit,phase,ms,compressed_bytes,public_inputs,total_inputs,quad_terms,crt_block_enc\n' > "$metrics_csv"

found=0
while IFS= read -r -d '' file; do
  rel=${file#"$release_dir"/}
  artifact=${rel%%/*}
  [[ "$artifact" != "$rel" ]] || artifact=${artifact%%_*}
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    printf '%s,%s,%s\n' \
      "$(csv_escape "$artifact")" \
      "$(csv_escape "$rel")" \
      "$line" >> "$metrics_csv"
  done < <(tail -n +2 "$file")
  found=1
done < <(find "$release_dir" -name '*_bip340_metrics.csv' -type f -print0 | sort -z)

if [[ "$found" -ne 1 ]]; then
  printf 'no BIP340 metrics CSV files found under %s\n' "$release_dir" >&2
  exit 1
fi

awk -F, '
  NR > 1 {
    label = $1 "\\n" $5
    print label, $6
  }
' "$metrics_csv" > "$plot_data"

gnuplot <<GNUPLOT
set terminal pngcairo size 1200,700 enhanced font "Arial,11"
set output "$plot_png"
set title "BIP340 proving path timings"
set ylabel "milliseconds"
set xlabel "artifact / phase"
set style data histograms
set style fill solid 0.75 border -1
set boxwidth 0.8
set grid ytics
set key off
set xtics rotate by -35 right
set datafile separator whitespace
plot "$plot_data" using 2:xtic(1) lc rgb "#2f6f9f"
GNUPLOT

if [[ -n "$tag" && -n "$repo" ]]; then
  image_url="https://github.com/${repo}/releases/download/${tag}/longfellow-zk_bip340_metrics.png"
  csv_url="https://github.com/${repo}/releases/download/${tag}/longfellow-zk_bip340_metrics.csv"
else
  image_url="longfellow-zk_bip340_metrics.png"
  csv_url="longfellow-zk_bip340_metrics.csv"
fi

cat > "$release_body" <<EOF
## BIP340 Metrics

![BIP340 proving path timings](${image_url})

Machine-readable metrics CSV: [longfellow-zk_bip340_metrics.csv](${csv_url})

The CSV is tidy data: each row is one target/phase observation with elapsed milliseconds, compressed artifact bytes, and circuit sizing metadata.
EOF

printf 'wrote %s\n' "$metrics_csv"
printf 'wrote %s\n' "$plot_png"
printf 'wrote %s\n' "$release_body"
