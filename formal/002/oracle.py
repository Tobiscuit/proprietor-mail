#!/usr/bin/env python3
"""Goal-ranking oracle for device.spthy (tamarin-prover --heuristic=O).

Tamarin calls this with the lemma name as the first argument and hands the
open goals of a constraint system on stdin, one per line as "<index>: <goal>".
It reads back the indices to try first, in order; goals left out keep
Tamarin's default order after the listed ones.

Two rankings, chosen by the lemma's name:

- Existence searches (the sanity lemmas and `stateless_rollback_possible`):
  protocol facts and action facts first, then knowledge of composed terms,
  then everything else, then knowledge of fresh names. The model types every
  key, id and secret as a fresh name, so a goal "the attacker knows some
  fresh name" (!KU( ~x )) has a precomputed case for every position in every
  honest output where a fresh name appears. Taken early, each case opens a
  deep subtree; taken last, once the protocol facts have bound every
  variable, almost all of them close on a fresh-name clash at once.

- Proofs (every other lemma): knowledge of fresh names first. In a secrecy
  or agreement proof that goal is the crux: its cases enumerate every way
  the secret could have reached the attacker, and each either closes or
  points at the compromise the lemma allows for. Protocol facts come next,
  composed-term knowledge after them.
"""
import re
import sys

lemma = sys.argv[1] if len(sys.argv) > 1 else ""
existence = lemma.startswith("sanity_") or lemma == "stateless_rollback_possible"

premises, composed, other, fresh = [], [], [], []
for line in sys.stdin:
    m = re.match(r"\s*(\d+):\s*(.*)", line)
    if not m:
        continue
    index, goal = m.group(1), m.group(2).strip()
    if goal.startswith("!KU( ~") or goal.startswith("!KU(~"):
        fresh.append(index)
    elif goal.startswith("!KU("):
        composed.append(index)
    elif "▶" in goal or "@" in goal:
        premises.append(index)
    else:
        other.append(index)

if existence:
    order = premises + composed + other + fresh
else:
    order = fresh + premises + composed + other

for index in order:
    print(index)
