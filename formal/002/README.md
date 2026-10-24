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
  --heuristic=O --oraclename=$PWD/oracle.py --derivcheck-timeout=0 \
  device.spthy +RTS -N4 -M5G -RTS
```

Well-formedness: all three variants pass every check with
`tamarin-prover --derivcheck-timeout=0 device.spthy` (`All wellformedness
checks were successful`). The `0` switches off one lint, the *message
derivation check*, on purpose: it flags a rule whose `In` or state-fact
pattern has a variable the attacker could not derive, and every mailbox key
in this model is matched as `mkey(~x)` (ir.md §4), which that lint reports
for 18 rules (`A04, A05, A10–A15, A18–A26, A28`). With the lint on, those
are its only findings. The model has no partial deconstructions, so no
sources lemma is needed.

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
8. *Answers routed, not learned.* The printed proof of a session-existence
   lemma showed the solver obtaining the challenge answer by decrypting the
   challenge with a compromised key rather than through the honest answer
   rule: an honest answer that is also published lets the attacker rebuild
   the challenge ciphertext from the answer it just learned, a circle the
   solver unrolls. Answers now travel only on their channel (the attacker
   still routes, replays or re-pairs them, which is all a relay can do with
   the bytes). The results table says what this bought.
9. *Reusable secrecy lemmas first.* The remaining stall was the goal "the
   attacker knows this honest mailbox key": each successor seal offers a way
   to learn `K_i` from `K_{i+1}`, an unbounded regress. `mailbox_key_secret`,
   `factor_secret` and `dek_secret_honest_key` moved to the front, proven by
   induction and marked `[reuse]`, so later proofs close such branches at
   once (Tamarin's standard remedy).
10. *Sort confusion, the actual cause.* Even `factor_secret` — the factor
    secret never leaves the owner and the KDF has no inverse — did not
    terminate, with or without the reuse lemmas and under every heuristic.
    Its depth-4 proof tree showed why: the goal "the attacker knows `~fs`"
    was sourced from the *device seal*, which carries the page's key `~sk`,
    because two fresh-sort variables can unify and the solver had to
    consider a page holding the factor secret as its key — refutable only
    through the circular chain argument it never finishes. The device-session
    signature check (an `Eq(verify…)` restriction) and the re-tagged record
    loop (`T3 → T3`) were removed in the same revision. The fix attempt:
    mailbox private keys become `mkey(~x)`, so a key can never unify with a
    secret, an id or an answer.

Depth-bounded runs (`--bound=N`) and the printed proof trees were the
instruments: a goal with hundreds of `case` lines in the tree at the depth
where the time explodes is the goal to reorder or remove.

## Results

Runs on 2026-10-20, Tamarin 1.12.0, one lemma per process, 4 cores, 6 GB
cap, the caps named per row. "Expected" is ir.md §7's pre-run call. The
sweep was bounded by the operator to what terminates within the caps; what
did not is listed with what was tried, not pushed past the caps.

### Verified (on the committed `device.spthy`)

| Lemma | Verdict | Time | Expected | Means |
|---|---|---|---|---|
| `factor_secret` | **verified** (5 steps) | 10 s | hold | The factor secret and the factor private key never reach the attacker: Mail never learns a factor's secret (ir.md §7 (vi)). |
| `sanity_device_session` | **verified** (6 steps) | 68 s | trace exists | The honest flow "enroll, keep a device, challenge, the device answers with its signature, Mail opens a device session" runs in the model. |

Also found while the model was being tuned (on the same rules, earlier file
revisions; not re-run on the committed text): existence traces for
enrollment, device registration, a challenge, a factor answer, a session, a
rotation and a seal to a device, each in 4–26 s.

### Not terminated within the cap

| Lemma | Cap | What was tried | Why it is hard |
|---|---|---|---|
| `mailbox_key_secret` | 5 min (also 6, 15) | default heuristic; existence- and proof-tuned oracle; `[use_induction, reuse]`; with and without the other reuse lemmas; untyped, typed and key-constructor models | The proof is an induction over the unbounded chain of successor seals (K_i opens from K_{i+1}); the solver has not closed it within the cap. |
| `dek_secret_honest_key` | 5 min | as above | Same induction, one layer deeper (a message key under a key on the chain). |
| `sanity_rotation_applied_and_sealed` | 5–6 min (also 15) | default; BFS, SEQDFS, consecutive heuristic; depth bounds; pinned trace shape; oracle; every model revision | The honest trace is ~11 rule instances through two challenge/answer exchanges and a pointer move; the existence search still fans out below the session goal. |
| `sanity_kept_device_resumes_after_rotation`, `sanity_stateless_unlocks_after_rotation`, `stateless_rollback_possible` | not run on the final text | — | Longer than the lemma above; not attempted after it failed to terminate. |
| every remaining security lemma (post-removal secrecy ×4, chain agreement ×3, rollback, recipient integrity ×2, agreement ×3) | not run on the final text | the first revision's sweep hit the sources-lemma wall before reaching them | Each depends on the two secrecy inductions above. |

The `BOUND_PROOFS` and `ORACLE_MUTANT` variants are well-formed and were
not run.

### Findings from building the model — not machine-checked

Each is a trace written by hand while the IR was being drafted (ir.md §7
says where); Tamarin has neither confirmed nor refuted it.

1. **Fork from a leaked old key.** A device removed and later compromised
   leaks `K_i`; the attacker forges a successor seal `K_i → K_att` and seals
   `K_att` to the factor key. A recovery-key unlock is anchored at `K0`
   forever, so the walk `K_att → K_i → … → K0` passes; kept devices still at
   `≤ K_i` accept it too. Lemma `chain_agreement_stateless_after_removed_compromise`.
2. **Planted recipient from a stolen unlocked device.** With `K_old` the
   thief computes `bindkey(K_old)` and, through a hostile store, lists a
   device record with a genuine tag; the owner's own removal rotation seals
   the new key to it. Lemmas `*_compromise_before_removal`.
3. **Finding C is stronger than the review said.** Mail checks only `from`
   and the shapes of a rotation (`src/mailbox/devices.ts`, `removeDevice`),
   so the relay can apply a rotation to its *own* key with the owner's
   relayed factor proof and session; inbound mail then goes to the attacker's
   key until the owner's next unlock notices. Expected to hold only with the
   challenge bound to `h(request)` (`BOUND_PROOFS`). Lemma
   `post_removal_secrecy_applied_rotation_no_compromise`.
4. **`lastKeyId` is overwritten unconditionally** (`resume.ts` step 5,
   `session.ts` unlockWithFactor); two tabs shown different honest keys can
   move a device's anchor back one step. The model assumes compare-and-swap.

And one observation about the threat model: D25's factor check rests
entirely on Mail's stored factor public keys being honest. A store that can
rewrite them answers its own factor proofs; the model had to assume those
records honest (ir.md P4b) for any proof statement to mean anything.

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

## Round 3 (2026-10-22 to 24): the model of ir.md §10, and what Tamarin said

`device.spthy` is now the round 3 theory (round 2's is commit 0e82dc2).
Runs: Tamarin 1.12.0 and Maude 3.5.1 as above, one lemma per process, each
in its own memory box (`boxed`, 8 GB), four cores, a 3-minute cap per lemma
(4 minutes for some first attempts), the oracle in `oracle.py`. The
summaries are `results/<variant>/summary.tsv`; the logs are not committed.

### What changed while building it (each recorded in ir.md §10.5)

- **The three functions of a factor's secret are private symbols** (`fkey`,
  `fsk`, `kek`): with them public the prover spent its time letting the
  attacker "apply" them to names it never learns.
- **A request is named by a fresh id**, and a factor challenge carries the
  digest of `<kind, mailbox, id>` (for a registration also the device id);
  what the request says is bound by the factor's own signature (the
  transition, the admission), which Mail checks too. A digest over the keys
  themselves made the precomputation of sources diverge.
- **Mail's session check on a rotation is not modelled** (it only removes
  attacker options); with it the precomputation did not finish.
- **The accept step re-reads** the anchor's wrap (or the device record) and
  the transition into the active key, which the walk checked already: same
  verdicts, no induction over the walk.
- **The oracle** takes knowledge of private terms and goals that carry a
  signature first, Mail's records first for its uniqueness lemmas, and, in
  existence searches, solves secret-born names early and the read-and-put-back
  facts (`MailActive`, `Kept`) last.
- **Sanity and attack lemmas pin their trace's shape for every mailbox**
  (one enrollment, nothing that is not part of the flow): pinned to one
  mailbox only, the search wandered into others.

### Verified (base model, unbounded)

| Lemma | Steps, time | In plain words |
|---|---|---|
| `factor_secret` | 5, 11 s | The factor's secret, its decryption key and its signing key never reach the attacker. |
| `successor_authored_by_factor` | 8, 11 s | **Mail never moves the mailbox to a new key unless the factor holder signed that exact step**, whatever devices are stolen, and with the email-code path open to the attacker. This is the property the brief asked for: an email code (or anything short of a factor) cannot author a successor key. |
| `accepted_step_authored_by_factor` | 10, 11 s | Every step a browser takes along the key chain was signed by the factor holder. |
| `accepted_key_is_honest_stateless`, `accepted_key_is_honest_kept` (with the helpers `page_key_honest`, `kept_anchor_honest` by induction) | 17, 6, 554, 5 steps; 11–27 s | **A browser never accepts a key the attacker made, with no restriction on compromise**: round 2's fork (a removed device's old key, a hostile server, a forged successor) is closed. Round 2 needed "no compromise" here or failed. |
| `sealed_only_to_admitted_recipients` | 78, 19 s | A rotating browser seals the new key only to a recipient an honest party made, or to a device that is itself stolen (and is not the one being removed). **Round 2's planted recipient is closed.** |
| `factor_proof_spent_once` | 38, 11 s | A factor challenge is accepted at most once. |
| `session_needs_owner` | 77, 21 s | A session without a device opens only with the owner's factor answer bound to that very session challenge: **a copied mailbox key alone opens nothing** (D38). |
| the five sanity lemmas | 10–15 steps, 12–25 s | The honest flows run: keep a device and open its session; open a session without a device; rotate; a kept device rotates; a stateless browser unlocks after a rotation. Without these the lemmas above could hold vacuously. |

### The mutants: each mechanism removed, its attack found

| Variant | Attack lemma | Result | In plain words |
|---|---|---|---|
| `NO_TRANSITION_SIG` | `attack_fork` | trace, 16 steps, 19 s | Without the factor's signature on each step, a stolen device's key and a hostile server make a stateless browser accept the attacker's key (finding 1). |
| `NO_ADMISSION` | `attack_planted_recipient` | trace, 16 steps, 23 s | With binding tags as the only check, a stolen device's key plants a device record the owner's rotation seals the new key to (finding 2). |
| `MAIL_UNCHECKED` | `attack_relay_rotation` | trace, 9 steps, 104 s | If Mail took an unbound factor answer and no transition, the relay could move the mailbox to its own key (finding 3). |
| `EMAIL_ROTATES` | `attack_email_rotation` | trace, 5 steps, 18 s (with `--bound=6`; unbounded, the depth-first search went down the factor branch first) | If an email code could confirm a rotation, whoever reads the owner's email makes the key future mail is sealed to. |
| `KEY_ONLY_SESSION` | `attack_copied_key_session` | not terminated (3 min) | Not found by the prover. The same mechanism removed in code (the Worker letting a key proof alone open a session) fails the Worker's and the end-to-end tests. |

The all-traces lemmas under the mutants (e.g. `accepted_key_is_honest_stateless`
under `NO_TRANSITION_SIG`) did not terminate as falsifications within the
cap; the pinned attack lemmas are what found the traces.

### Not terminated (base model, 3-minute cap)

| Lemma | What it would have said | What we have instead |
|---|---|---|
| `factor_proof_bound` and its per-kind forms `rotation_proof_bound`, `registration_proof_bound` | Every factor proof Mail accepts was answered by the owner for that very request. | For rotations, `successor_authored_by_factor` (the factor's signature on the exact step); for sessions, `session_needs_owner`; for every kind, the code's tests (a proof answered for one request is refused on another: Worker and end-to-end). |
| `one_registration_per_device`, `revoked_device_opens_no_session` | A device is registered once, and after an email-code revocation it never opens a session. | The Worker's revocation tests and the end-to-end F13 test (a revoked device's token, signature and resume are all refused). |
| `mailbox_key_secret`, `dek_secret_honest_key`, `post_removal_secrecy_compromise_before_removal`, `kept_device_no_rollback` | Key and message-key secrecy, and secrecy of mail after a removal with a stolen device. | Round 2's induction wall over the unbounded successor chain is unchanged in kind; these need hand-written helper lemmas. |
| `post_removal_secrecy_applied_rotation_no_compromise` | With no device compromised, mail sealed after an applied rotation stays secret (round 2's relay finding). | It verified (8 steps) while the two secrecy lemmas above were available as `[reuse]`, so that verdict is **conditional** on them; with them hidden it did not terminate in 3 minutes. The relay itself is ruled out by `successor_authored_by_factor`. |

### Not machine-checked at all

The account check (D37) and the lock settings (D34, K6) are browser-local
reads of the right record; there is one factor in the model (ir.md P3); the
compare-and-swap of `lastKeyId` (K11) is modelled as such but the race it
prevents is a code property (tested in real browsers); Ed25519, HPKE, RFC
8785 and AES-GCM are symbolic; removing a factor is not modelled (spec §4
states its limit).
