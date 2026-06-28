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
    case "$1" in
        native)    "$helper"            "$n_stat_native" "$2" "$workdir" 2>&1 >/dev/null ;;
        fakeroost) "$target"            "$helper" "$n_stat_fake" "$2" "$workdir" 2>&1 >/dev/null ;;
        fakeroot)  fakeroot -- "$helper" "$n_stat_fake" "$2" "$workdir" 2>&1 >/dev/null ;;
    esac | sed -n 's/.*rate=\([0-9.]*\).*/\1/p'
}

fmt() { printf "$1"; shift; printf '%s' ""; printf '%16s' "$@"; printf '\n'; }

# Original C fakeroot, when installed — an extra real-world baseline.
have_fakeroot=0
if command -v fakeroot >/dev/null 2>&1; then
    have_fakeroot=1
else
    echo "# (fakeroot not installed; skipping that column)" >&2
fi

fetch() { # <label> <workers>  -> rate (empty if label is fakeroot and unavailable)
    if [[ "$1" == fakeroot && "$have_fakeroot" -eq 0 ]]; then printf ''; return; fi
    rate "$1" "$2"
}

declare -a Rn Rf Rk
base_n="" base_f="" base_k=""
for i in "${!workers[@]}"; do
    nw="${workers[$i]}"
    Rn[$i]="$(rate native "$nw")"
    Rf[$i]="$(rate fakeroost "$nw")"
    Rk[$i]="$(fetch fakeroot "$nw")"
    [[ -z "$base_n" ]] && base_n="${Rn[$i]}"
    [[ -z "$base_f" ]] && base_f="${Rf[$i]}"
    [[ -z "$base_k" ]] && base_k="${Rk[$i]}"
done

col_fakeroot=''
if [[ "$have_fakeroot" -eq 1 ]]; then col_fakeroot='rate_fakeroot/s'; fi

echo "# fakeroost serialization benchmark (issue #7)"
echo "# n_calls_per_worker: native=$n_stat_native fakeroost/fakeroot=$n_stat_fake  cores=$cores"
echo "#"
printf '%9s %16s %18s' 'workers' 'rate_native/s' 'rate_fakeroost/s'
if [[ "$have_fakeroot" -eq 1 ]]; then printf ' %16s' 'rate_fakeroot/s'; fi
printf '\n'
for i in "${!workers[@]}"; do
    printf '%9s %16s %18s' "${workers[$i]}" "${Rn[$i]}" "${Rf[$i]}"
    if [[ "$have_fakeroot" -eq 1 ]]; then printf ' %16s' "${Rk[$i]}"; fi
    printf '\n'
done

echo "#"
echo "# effective parallelism (rate_w / rate_w1):"
printf '%9s %16s %18s' 'workers' 'native_x' 'fakeroost_x'
if [[ "$have_fakeroot" -eq 1 ]]; then printf ' %16s' 'fakeroot_x'; fi
printf '\n'
for i in "${!workers[@]}"; do
    sn="$(awk -v a="${Rn[$i]}" -v b="$base_n" 'BEGIN{printf "%.1f", a/b}')"
    sf="$(awk -v a="${Rf[$i]}" -v b="$base_f" 'BEGIN{printf "%.2f", a/b}')"
    printf '%9s %16s %18s' "${workers[$i]}" "$sn" "$sf"
    if [[ "$have_fakeroot" -eq 1 ]]; then
        sk="$(awk -v a="${Rk[$i]}" -v b="$base_k" 'BEGIN{printf "%.2f", a/b}')"
        printf ' %16s' "$sk"
    fi
    printf '\n'
done
