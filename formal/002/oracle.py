#!/usr/bin/env python3
"""Goal-ranking oracle for device.spthy (tamarin-prover --heuristic=O).

Tamarin calls this with the lemma name as the first argument and hands the
open goals of a constraint system on stdin, one per line as "<index>: <goal>".
It reads back the indices to try first, in order; goals left out keep
Tamarin's default order after the listed ones.

Two rankings, chosen by the lemma's name. In both, knowledge of a term
built with one of the private functions of a factor's secret (fsk, fkey,
kek), or of a wrap made under kek, comes first: nothing outputs the
former and the attacker cannot build either, so such a goal closes its case
or points at the one honest rule that made it.

- Existence searches (the sanity lemmas and `stateless_rollback_possible`):
  protocol facts and action facts first, then knowledge of composed terms,
  then everything else, then knowledge of fresh names. The model types every
  key, id and secret as a fresh name, so a goal "the attacker knows some
  fresh name" (!KU( ~x )) has a precomputed case for every position in every
  honest output where a fresh name appears. Taken early, each case opens a
  deep subtree; taken last, once the protocol facts have bound every
  variable, almost all of them close on a fresh-name clash at once.

- Proofs (every other lemma): any goal that carries a signature first (its
  knowledge, or a premise whose content is signed). Round 3's authorship
  lemmas turn on "who could have made this transition or this admission",
  which the signing key's secrecy answers at once; taken late, the other
  premises (challenges, answers, pages, walks) open deep subtrees first.
  Then knowledge of fresh names. In a secrecy
  or agreement proof that goal is the crux: its cases enumerate every way
  the secret could have reached the attacker, and each either closes or
  points at the compromise the lemma allows for. Protocol facts come next,
  composed-term knowledge after them.
"""
import re
import sys

lemma = sys.argv[1] if len(sys.argv) > 1 else ""
# ORACLE_MODE=attack (set by run.sh for a mutant variant): the lemma is
# expected to fail, so the search is ordered as an existence search for the
# attack trace rather than as a proof.
import os
existence = lemma.startswith("sanity_") or lemma == "stateless_rollback_possible" or os.environ.get("ORACLE_MODE") == "attack"
# Agreement and uniqueness lemmas about Mail's own records: the answer is in
# the rule instances that consumed a linear fact, so the premises come first
# and knowledge of fresh names last (as in an existence search).
structural = lemma in {
    "factor_proof_spent_once", "one_registration_per_device",
    "revoked_device_opens_no_session",
}

private, signatures, premises, composed, other, fresh = [], [], [], [], [], []
goals = {}
for line in sys.stdin:
    m = re.match(r"\s*(\d+):\s*(.*)", line)
    if not m:
        continue
    index, goal = m.group(1), m.group(2).strip()
    goals[index] = goal
    if re.match(r"!KU\(\s*(fsk|fkey|kek)\(", goal) or (re.match(r"!KU\(\s*senc\(", goal) and "kek(" in goal):
        private.append(index)
    elif existence and re.match(r"!KU\(\s*~(ans|fans|fs|dek|dsk|dss)\b", goal):
        # In an existence search, the attacker's knowledge of a secret-born
        # fresh name (a challenge's answer, a factor secret, a message key, a
        # device key) closes at once, or points at the one compromise that
        # gives it: taken last, a dead branch is explored to its full depth.
        private.append(index)
    elif "sign(" in goal and not existence:
        signatures.append(index)
    elif goal.startswith("!KU( ~") or goal.startswith("!KU(~"):
        fresh.append(index)
    elif goal.startswith("!KU("):
        composed.append(index)
    elif "▶" in goal or "@" in goal:
        premises.append(index)
    else:
        other.append(index)

if lemma in {"factor_proof_bound", "session_needs_owner", "rotation_proof_bound", "registration_proof_bound"}:
    # Who gave the answer Mail compared: the answer's channel first, then the
    # factor's record, then knowledge of the answer itself (only the factor's
    # private key opens the challenge that carries it).
    first = [i for i in premises if goals[i].startswith(("MailFactorChallenge(", "MailSessionChallenge(", "FactorAnswer(", "!MailFactorKey("))]
    challenges = [i for i in composed if goals[i].startswith("!KU( aenc(<'challenge', 'factor'")]
    order = first + challenges + private + fresh + [i for i in premises if i not in first] + signatures + [i for i in composed if i not in challenges] + other
elif structural:
    # Rule instances first (actions), then Mail's own records (a linear fact
    # consumed twice, or after its last use, is the contradiction these proofs
    # need), then the rest.
    acts = [i for i in premises if "▶" not in goals[i] and not goals[i].startswith("!KU(")]
    mail = [i for i in premises if "▶" in goals[i] and (goals[i].startswith("Mail") or goals[i].startswith("!Mail"))]
    rest = [i for i in premises if i not in acts and i not in mail]
    order = private + acts + mail + rest + signatures + composed + other + fresh
elif existence:
    # Facts that rules read and put back (Mail's pointer, a kept device's
    # record) can be traced back through any number of readers; solving them
    # last lets the rest of the trace pin down which writer it was.
    loops = [i for i in premises if goals[i].startswith(("MailActive(", "Kept("))]
    order = private + [i for i in premises if i not in loops] + signatures + composed + other + fresh + loops
else:
    order = private + signatures + fresh + premises + composed + other

for index in order:
    print(index)
