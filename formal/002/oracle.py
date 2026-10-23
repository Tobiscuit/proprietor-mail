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
existence = lemma.startswith("sanity_") or lemma == "stateless_rollback_possible"

private, signatures, premises, composed, other, fresh = [], [], [], [], [], []
for line in sys.stdin:
    m = re.match(r"\s*(\d+):\s*(.*)", line)
    if not m:
        continue
    index, goal = m.group(1), m.group(2).strip()
    if re.match(r"!KU\(\s*(fsk|fkey|kek)\(", goal) or (re.match(r"!KU\(\s*senc\(", goal) and "kek(" in goal):
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

if existence:
    order = private + premises + composed + other + fresh
else:
    order = private + signatures + fresh + premises + composed + other

for index in order:
    print(index)
