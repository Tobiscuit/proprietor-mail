# Spec 002 — Tamarin model: how to rerun, and what it found

Three files, read in this order:

1. `ir.md` — the protocol in plain words, with every proof target and the
   verdict we expected *before* running anything. The operator reviews this
   one for meaning (its §9 is the checklist).
2. `device.spthy` — the Tamarin theory generated from the IR; each rule names
   its IR step and the contract section it comes from.
3. this file — the tool versions, the commands, and the verdicts.

## Tools (user space only, no system packages)

| Tool | Version | Where | From |
|---|---|---|---|
| Tamarin Prover | 1.12.0 (release 2026-03-07) | `~/.local/opt/tamarin-1.12.0/tamarin-prover` | GitHub release asset `tamarin-prover-1.12.0-linux64-ubuntu.tar.gz` |
| Maude | 3.5.1 | `~/.local/opt/maude-3.5.1/maude` | GitHub release asset `Maude-3.5.1-linux-x86_64.zip` (extracted with Python's `zipfile`; the node has no `unzip`) |

`tamarin-prover test` passes all 55 unification cases; its one complaint is
the missing `dot`, which only the interactive GUI uses. Neither tool is on
the login `PATH`; `run.sh` adds Maude for its own process only.

To install the same way:

```sh
mkdir -p ~/.local/opt/tamarin-1.12.0 ~/.local/opt/maude-3.5.1
cd ~/.local/opt/tamarin-1.12.0 && gh release download 1.12.0 --repo tamarin-prover/tamarin-prover \
  --pattern 'tamarin-prover-1.12.0-linux64-ubuntu.tar.gz' && tar xzf tamarin-prover-1.12.0-linux64-ubuntu.tar.gz
cd ~/.local/opt/maude-3.5.1 && gh release download Maude3.5.1 --repo maude-lang/Maude \
  --pattern 'Maude-3.5.1-linux-x86_64.zip' && python3 -c "import zipfile; zipfile.ZipFile('Maude-3.5.1-linux-x86_64.zip').extractall('.')" && chmod +x maude
```

## Running

`run.sh` runs one lemma per process, each pinned to four cores (`taskset -c
4-7`), at `nice -n 10`, with a wall-clock limit per lemma (`TIMEOUT`,
default 15 minutes) and four GHC threads. Logs go to `results/<variant>/`,
one per lemma, plus `summary.tsv`.

```sh
cd formal/002
EXTRA=--auto-sources ./run.sh                     # the base model
EXTRA=--auto-sources ./run.sh -D=BOUND_PROOFS     # factor proofs bound to the request
EXTRA=--auto-sources ./run.sh -D=ORACLE_MUTANT    # K4 removed (message keys under the challenge info)
```

`--auto-sources` is needed: the chain walk and the seals leave partial
deconstructions, and Tamarin generates and proves a sources lemma
(`AUTO_typing`) before the others. A single lemma:

```sh
PATH=~/.local/opt/maude-3.5.1:$PATH taskset -c 4-7 nice -n 10 timeout 15m \
  ~/.local/opt/tamarin-1.12.0/tamarin-prover --auto-sources --prove=kept_device_no_rollback \
  device.spthy +RTS -N4 -RTS
```

Well-formedness: all three variants pass every check (`tamarin-prover
device.spthy` prints `All wellformedness checks were successful`).

## Results

RESULTS_TABLE

## Reading a verdict

- **verified** — Tamarin proved the lemma for every trace (unbounded
  sessions, devices, rotations), under the model's assumptions (ir.md §6, §8).
- **falsified** — Tamarin found a trace; the plain-words summary is the
  attack. The log holds the full trace (the rule instances, in order).
- **not terminated** — the search did not finish in the time limit; the log
  says how far it got. What was tried is listed per lemma.

An "expected" column that matches the verdict is the point of the method:
the IR said what should happen before the tool ran. A mismatch is either a
modelling mistake or a real surprise, and is discussed under the table.
