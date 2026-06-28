#!/usr/bin/env bash
# Reproduces issue #7 at workload scale: a parallel `make` of many independent
# tiny compiles. Each compile forks/execs `cc` and stats the libc headers, so
# the whole traced tree hammers the single supervisor thread.
#
#   bench/run-make.sh [n_files]
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

target="$root/target/release/fakeroost"
[[ -x "$target" ]] || cargo build --release

n_files="${1:-400}"
cores="$(nproc)"

jobs=(1)
j=4
while (( j <= cores )); do jobs+=("$j"); j=$(( j * 4 )); done
if [[ "${jobs[-1]}" != "$cores" ]]; then jobs+=("$cores"); fi

# Self-contained scratch dir (cleaned on exit).
workdir="$(mktemp -d)"
trap 'rm -rf "$workdir"' EXIT
mkdir -p "$workdir/src"

gen() {
    rm -f "$workdir"/src/*.c "$workdir"/src/*.o
    for ((i = 0; i < n_files; i++)); do
        # Several system headers each, so every compile triggers a real
        # header/stat storm (the workload that bites under fakeroot).
        cat > "$workdir/src/t$i.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
int work(void) {
    char b[64];
    struct stat st;
    fstat(0, &st);
    snprintf(b, sizeof b, "%d", (int)st.st_size);
    return strlen(b) + errno + (int)time(0);
}
EOF
    done
}

wall() { # <command...> -> elapsed seconds, robust to sub-shell stderr quirks
    local t0 t1
    t0=$(date +%s.%N)
    "$@" >/dev/null 2>&1
    t1=$(date +%s.%N)
    awk -v a="$t0" -v b="$t1" 'BEGIN{printf "%.2f", b-a}'
}

fmt() { printf "%9s %14s %18s\n" "$@"; }

echo "# fakeroost parallel-build benchmark (issue #7)"
echo "# n_files=$n_files  cores=$cores  cc=$(command -v cc)"
echo "#"
fmt "jobs" "wall_native/s" "wall_fakeroost/s"

for j in "${jobs[@]}"; do
    gen
    tn="$(wall make -j"$j" -f "$root/bench/Makefile" -C "$workdir" N="$n_files" all)"
    gen
    tf="$(wall "$target" make -j"$j" -f "$root/bench/Makefile" -C "$workdir" N="$n_files" all)"
    fmt "$j" "$tn" "$tf"
done
