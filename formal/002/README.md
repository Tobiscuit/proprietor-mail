# Spec 002 — Tamarin model: how to rerun, and what it found

Four files, read in this order:

1. `ir.md` — the protocol in plain words, with every proof target and the
   verdict we expected *before* running anything. The operator reviews this
   one for meaning (its §9 is the checklist).
2. `device.spthy` — the Tamarin theory generated from the IR; each rule names
   its IR step and the contract section it comes from.
3. `oracle.py` — the goal-ordering heuristic the runs use (why: below).
4. this file — the tool versions, the commands, and the verdicts.

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

`run.sh` runs one lemma per process, each inside its own transient systemd
user scope with a memory cap (`MemoryMax=6G`), pinned to four cores
(`taskset -c 4-7`), at `nice -n 10`, under a wall-clock limit per lemma
(`TIMEOUT`, default 15 minutes), with four GHC threads and GHC's own heap cap
(`-M5G`) as a second fence; the scope is stopped after every lemma so no
prover or Maude process outlives its run. Logs go to `results/<variant>/`,
one per lemma, plus `summary.tsv`. Only one prover runs at a time.

```sh
cd formal/002
./run.sh                     # the base model
./run.sh -D=BOUND_PROOFS     # factor proofs bound to the request (the proposed fix)
./run.sh -D=ORACLE_MUTANT    # K4 removed (message keys under the challenge info)
LEMMAS="kept_device_no_rollback" TIMEOUT=30m ./run.sh   # one lemma, longer
```

A single lemma by hand (the runner adds the same flags):

```sh
PATH=~/.local/opt/maude-3.5.1:$PATH taskset -c 4-7 nice -n 10 timeout 15m \
  ~/.local/opt/tamarin-1.12.0/tamarin-prover --prove=kept_device_no_rollback \
  --heuristic=O --oraclename=$PWD/oracle.py --derivcheck-timeout=60 \
  device.spthy +RTS -N4 -M5G -RTS
```

Well-formedness: all three variants pass every check (`tamarin-prover
--derivcheck-timeout=60 device.spthy` prints `All wellformedness checks were
successful`; the longer derivation-check timeout matters on a loaded node,
where the 5-second default once reported a spurious failure). The model has
no partial deconstructions, so no sources lemma is needed.

## Making the search terminate: what was tried, in order

The first model (commit 7b91ea1) was a direct transcription. Its searches did
not terminate, and each step below was taken only after measuring where the
time went; ir.md §4 ("choices made for the prover") records each one as a
modelling decision for the operator to confirm. In order:

1. *Untyped model*: `--auto-sources` generated a 19-case sources lemma that
   did not prove in 15 minutes. Typing every key, id and secret as a fresh
   name left **zero** partial deconstructions.
2. *Linear page and record facts with self-loops* (a page answers a challenge
   and is reproduced; a record is read and reproduced). Pages became
   persistent facts; the record, the walks and a prepared rotation got a
   fresh id in first position. Tamarin now reports `Kept`, `MailActive`,
   `WalkD`, `WalkS` as injective looping facts.
3. *Attacker-chosen factor key for factor challenges* was a modelling flaw
   (it voided D25); the verifier now seals factor challenges to the key it
   registered at enrollment.
4. *Case order.* Tamarin tries the cases of a goal in alphabetical order of
   the rules that could have produced it, and it picked loop rules before
   base rules (`C1 ← MailActive ← C1 ← …`). Rules are named `A00…A28` in
   the order they should be tried; attacker injection rules are `Z…`.
5. *Goal order.* Even so, the first goal attacked was "the attacker knows
   this fresh name", which had ~212 precomputed cases, each opening a deep
   subtree while the rest of the trace was unconstrained. `oracle.py` puts
   protocol facts first and knowledge of fresh names last.
6. *Fewer fresh names in outputs*: the nonce, the token, the factor id and
   the ids inside encrypted payloads were dropped (ir.md §4 says why each is
   redundant). Every one was a case in every such goal.
7. *Channels.* Honest answers, requests and records travel on named facts
   that honest senders also publish; `Z…` rules let the attacker inject any
   content it knows. Same attacker power, honest source examined first.

Depth-bounded runs (`--bound=N`) and the printed proof trees were the
instruments: a goal with hundreds of `case` lines in the tree at the depth
where the time explodes is the goal to reorder or remove.

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
