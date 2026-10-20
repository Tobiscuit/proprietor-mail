#!/usr/bin/env bash
# Runs the lemmas of device.spthy one process at a time, each inside its own
# transient systemd user scope with a memory cap, pinned to four cores, at a
# nice level, under a wall-clock limit, and with GHC's own heap cap as a
# second fence. One log per lemma plus a results table. Nothing here needs
# root or system packages, and the scope is stopped after every lemma so no
# prover or Maude process outlives its run.
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
HEAP=${HEAP:-5G}           # GHC RTS -M: the prover aborts instead of swapping
MEMMAX=${MEMMAX:-6G}       # cgroup cap for the whole scope (prover + Maude)
TIMEOUT=${TIMEOUT:-15m}    # per lemma
ORACLE=${ORACLE:-$PWD/oracle.py}   # goal ordering (README: why); ORACLE= to use Tamarin's default heuristic
EXTRA=${EXTRA:-}           # further flags, e.g. --bound=20
if [ -n "$ORACLE" ]; then EXTRA="--heuristic=O --oraclename=$ORACLE $EXTRA"; fi

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

# A transient scope when the user systemd instance is reachable; plain
# otherwise (then only taskset, nice, timeout and the GHC heap cap apply).
# Probed once, with a unit name of its own.
if systemd-run --user --scope --quiet -p MemoryMax="$MEMMAX" --unit="tamarin-002-probe-$$" -- true 2>/dev/null; then
  SCOPED=yes
else
  SCOPED=no
  echo "note: no systemd user scope; running without a cgroup memory cap (GHC heap cap $HEAP still applies)" >&2
fi
scoped() {
  local unit=$1; shift
  if [ "$SCOPED" = yes ]; then
    systemd-run --user --scope --quiet -p MemoryMax="$MEMMAX" --unit="$unit" -- "$@"
  else
    "$@"
  fi
}

# Lemma names, in file order. A lemma inside an #ifdef that is not active is
# simply reported "not in this variant" by Tamarin's summary.
lemmas=${LEMMAS:-$(grep -oE '^lemma [A-Za-z0-9_]+' device.spthy | awk '{print $2}')}

for lemma in $lemmas; do
  log=$outdir/$lemma.log
  unit="tamarin-002-$variant-$lemma-$$"
  start=$(date +%s)
  # shellcheck disable=SC2086
  scoped "$unit" taskset -c "$CORES" nice -n "$NICE" timeout -k 10s "$TIMEOUT" \
    "$TAMARIN" --prove="$lemma" --derivcheck-timeout=0 "${flags[@]}" $EXTRA device.spthy +RTS -N"$THREADS" -M"$HEAP" -RTS \
    > "$log" 2>&1
  rc=$?
  systemctl --user stop "$unit.scope" 2>/dev/null || true
  secs=$(( $(date +%s) - start ))
  line=$(grep -E "^\s*$lemma \((all-traces|exists-trace)\):" "$log" | head -1)
  if [ $rc -eq 124 ] || [ $rc -eq 137 ]; then
    verdict="not terminated (timeout $TIMEOUT)"
  elif grep -q "heap overflow\|Heap exhausted" "$log"; then
    verdict="not terminated (heap cap $HEAP)"
  elif [ -z "$line" ]; then
    verdict="no verdict (exit $rc; see log)"
  else
    verdict=$(echo "$line" | sed -E 's/^\s*[A-Za-z0-9_]+ \((all-traces|exists-trace)\): //')
  fi
  printf '%s\t%s\t%ss\n' "$lemma" "$verdict" "$secs" | tee -a "$table"
done
