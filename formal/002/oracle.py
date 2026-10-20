#!/usr/bin/env python3
"""Goal-ranking oracle for device.spthy (tamarin-prover --heuristic=O).

Tamarin hands the open goals of a constraint system on stdin, one per line as
"<index>: <goal>", and reads back the indices it should try first, in order.
Goals left out keep Tamarin's default order after the listed ones.

Why it exists: the model types every key, id and secret as a fresh name, so a
goal "the attacker knows some fresh name" (!KU( ~x )) has a precomputed case
for every position in every honest output where a fresh name appears, about
two hundred of them. Taken early, each case opens a deep subtree. Taken last,
when every variable is bound by the protocol facts already solved, almost all
of them close on a fresh-name clash at once and the honest source is found.
So the order is: protocol facts and action facts, then knowledge of composed
terms (ciphertexts, signatures, pairs, public keys), then everything else,
then knowledge of fresh names.
"""
import re
import sys

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

for index in premises + composed + other + fresh:
    print(index)
