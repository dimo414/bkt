#!/usr/bin/env bash
#
# Basic benchmark script to observe the overhead introduced by bkt. This can be
# useful for validating that a given command will benefit from caching (namely
# if the underlying command is significantly slower than the caching overhead).
# It can also be used to test the performance of different cache directory
# locations, such as a directory backed by a tmpfs file system.
#
# Usage:
#   benchmark.sh [[--bkt=PATH] [--iters=NUM] --] [bkt_args ... --] cmd [args ...]
#
# Examples:
#   benchmark.sh expensive_command args
#   benchmark.sh --iters=20 -- quicker_command args
#   benchmark.sh --bkt=target/release/bkt -- expensive_command args
#   benchmark.sh --bkt=target/debug/bkt -- --cwd -- expensive_command args

set -u

time_quiet() {
  ( TIMEFORMAT=%R; time "$@" &> /dev/null ) 2>&1
}

avg_floats() {
  # Maybe this whole script should just be written in Python...
  # Or just implement it in main.rs?
  python -c 'import sys; print(sum((float(arg) for arg in sys.argv[1:]))/(len(sys.argv)-1))' "$@"
}

exit_with_message() {
  local code=$1; shift
  printf '%s\n' "$@" >&2
  exit "$code"
}

# flag defaults
bkt=bkt
iters=5
bkt_args=()
cmd=()

# Read benchmark flags
while [[ "$1" == --* ]]; do
  arg="$1" flag="${1%=*}" value=
  if [[ "$arg" == *=* ]]; then
    value="${1#*=}"
  fi
  shift
  case "$flag" in
    --bkt)    bkt=$value ;;
    --iters)  iters=$value ;;
    --)       break ;;
    --*)      exit_with_message 2 "Unknown flag '${flag}'" ;;
    *)        break ;;
  esac
done

# Read command and bkt flags
while (( $# > 0 )); do
  if [[ "$1" == -- ]]; then
    bkt_args=("${cmd[@]}")
    shift
    cmd=("$@")
    break
  fi
  cmd+=("$1")
  shift
done

# validation
(( ${#cmd[@]} > 0 )) || exit_with_message 1 "Must provide a command to benchmark"

full_bkt=$(command -v "$bkt") || exit_with_message 1 \
  "${bkt} not found; pass --bkt to specify bkt's location"

for bkt_arg in "${bkt_args[@]}"; do
  if [[ "$bkt_arg" == --scope* ]]; then
    exit_with_message 1 "--scope is used by the benchmark script, do not use"
  fi
done

# Execute benchmark
printf "Benchmarking:\n\t%s\nwith:\n\t%s\n" \
  "${cmd[*]}" \
  "${full_bkt} ${bkt_args[*]}"

# Ensure the cache dir exists and the bkt args are valid
"$full_bkt" "${bkt_args[@]}" -- true || exit_with_message 1 "Invoking bkt failed"

printf -v scope '%s-%(%s)T' "$$"
raw_times=() cold_times=() warm_times=()
for (( i=0; i<iters; i++ )); do
  raw_times+=("$(time_quiet "${cmd[@]}")")
  cold_times+=("$(time_quiet "$full_bkt" "${bkt_args[@]}" "--scope=${scope}-${i}" -- "${cmd[@]}")")
  warm_times+=("$(time_quiet "$full_bkt" "${bkt_args[@]}" "--scope=${scope}-${i}" -- "${cmd[@]}")")
done

printf "Averages over %d iteration(s):\nOriginal:\t%ss\nCache Miss:\t%ss\nCache Hit:\t%ss\n" \
  "$iters" \
  "$(avg_floats "${raw_times[@]}")" \
  "$(avg_floats "${cold_times[@]}")" \
  "$(avg_floats "${warm_times[@]}")"