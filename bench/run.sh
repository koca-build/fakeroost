#!/usr/bin/env bash
# Reproduces issue #7: the single-threaded supervisor serializes stat() across
# the whole traced tree, so throughput hits a fixed ceiling and effective
# parallelism collapses no matter how many cores the workload is given.
#
# Runs the stat-loop helper native and under fakeroost, sweeping the worker
# count up to the core count, and prints a rate table + speedup curve.
#
#   bench/run.sh [n_calls_native] [n_calls_fakeroost]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

n_stat_native="${1:-500000}"  # per-worker, native: large for stable timing
n_stat_fake="${2:-20000}"     # per-worker, fakeroost: small so the matrix finishes
cores="$(nproc)"
helper_manifest="$root/bench/stat-loop/Cargo.toml"
helper="$root/bench/stat-loop/target/release/stat-loop"
target="$root/target/release/fakeroost"

workers=()
w=1
while (( w <= cores )); do workers+=("$w"); w=$(( w * 2 )); done
if [[ "${workers[-1]}" != "$cores" ]]; then workers+=("$cores"); fi

if [[ ! -x "$helper" ]] || [[ "$helper_manifest" -nt "$helper" ]]; then
    echo "# building stat-loop helper..." >&2
    cargo build --release --manifest-path "$helper_manifest"
fi
if [[ ! -x "$target" ]]; then
    echo "# building fakeroost..." >&2
    cargo build --release
fi

# A directory of distinct files so a native run actually parallelizes.
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
for ((i = 0; i < 512; i++)); do echo "$i" > "$workdir/f$i"; done

rate() { # <label> <workers>  -> prints rate
    if [[ "$1" == "native" ]]; then
        "$helper" "$n_stat_native" "$2" "$workdir" 2>&1 >/dev/null
    else
        "$target" "$helper" "$n_stat_fake" "$2" "$workdir" 2>&1 >/dev/null
    fi | sed -n 's/.*rate=\([0-9.]*\).*/\1/p'
}

fmt() { printf "%9s %16s %18s\n" "$@"; }

declare -a Rn Rf
base_n="" base_f=""
for i in "${!workers[@]}"; do
    nw="${workers[$i]}"
    Rn[$i]="$(rate native "$nw")"
    Rf[$i]="$(rate fakeroost "$nw")"
    [[ -z "$base_n" ]] && base_n="${Rn[$i]}"
    [[ -z "$base_f" ]] && base_f="${Rf[$i]}"
done

echo "# fakeroost serialization benchmark (issue #7)"
echo "# n_calls_per_worker: native=$n_stat_native fakeroost=$n_stat_fake  cores=$cores"
echo "#"
fmt "workers" "rate_native/s" "rate_fakeroost/s"
for i in "${!workers[@]}"; do fmt "${workers[$i]}" "${Rn[$i]}" "${Rf[$i]}"; done

echo "#"
echo "# effective parallelism (rate_w / rate_w1):"
fmt "workers" "native_x" "fakeroost_x"
for i in "${!workers[@]}"; do
    sn="$(awk -v a="${Rn[$i]}" -v b="$base_n" 'BEGIN{printf "%.1f", a/b}')"
    sf="$(awk -v a="${Rf[$i]}" -v b="$base_f" 'BEGIN{printf "%.2f", a/b}')"
    fmt "${workers[$i]}" "$sn" "$sf"
done
