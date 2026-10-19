#!/usr/bin/env bash
# Runs the lemmas of device.spthy one process at a time, each under a CPU
# set, a nice level and a wall-clock limit, and writes one log per lemma
# plus a results table. Nothing here needs root or system packages.
#
#   ./run.sh                      # the base model, every lemma
#   ./run.sh -D=BOUND_PROOFS      # the bound-proof variant
#   ./run.sh -D=ORACLE_MUTANT     # the K4-removed mutant
#   LEMMAS="a b" ./run.sh         # only these lemmas
#
# Tools: TAMARIN and MAUDE_DIR point at the user-space installs (README).
set -uo pipefail
cd "$(dirname "$0")"

TAMARIN=${TAMARIN:-$HOME/.local/opt/tamarin-1.12.0/tamarin-prover}
MAUDE_DIR=${MAUDE_DIR:-$HOME/.local/opt/maude-3.5.1}
export PATH="$MAUDE_DIR:$PATH"

CORES=${CORES:-4-7}        # taskset list: at most four cores on a shared node
NICE=${NICE:-10}
THREADS=${THREADS:-4}      # GHC RTS threads, matched to CORES
TIMEOUT=${TIMEOUT:-15m}    # per lemma
EXTRA=${EXTRA:-}           # e.g. --auto-sources, --bound=20

variant=base
flags=()
for arg in "$@"; do
  flags+=("$arg")
  case "$arg" in -D=*) variant=${arg#-D=} ;; esac
done

outdir=results/$variant
mkdir -p "$outdir"
table=$outdir/summary.tsv
: > "$table"

# Lemma names, in file order. A lemma inside an #ifdef that is not active is
# simply reported "not in this variant" by Tamarin's summary.
lemmas=${LEMMAS:-$(grep -oE '^lemma [A-Za-z0-9_]+' device.spthy | awk '{print $2}')}

for lemma in $lemmas; do
  log=$outdir/$lemma.log
  start=$(date +%s)
  # shellcheck disable=SC2086
  taskset -c "$CORES" nice -n "$NICE" timeout "$TIMEOUT" \
    "$TAMARIN" --prove="$lemma" "${flags[@]}" $EXTRA device.spthy +RTS -N"$THREADS" -RTS \
    > "$log" 2>&1
  rc=$?
  secs=$(( $(date +%s) - start ))
  line=$(grep -E "^\s*$lemma \((all-traces|exists-trace)\):" "$log" | head -1)
  if [ $rc -eq 124 ]; then
    verdict="not terminated (timeout $TIMEOUT)"
  elif [ -z "$line" ]; then
    verdict="no verdict (exit $rc; see log)"
  else
    verdict=$(echo "$line" | sed -E 's/^\s*[A-Za-z0-9_]+ \((all-traces|exists-trace)\): //')
  fi
  printf '%s\t%s\t%ss\n' "$lemma" "$verdict" "$secs" | tee -a "$table"
done
