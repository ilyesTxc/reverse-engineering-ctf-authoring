#!/usr/bin/env python3
# Solver (organizer only).
#  1. recompute the five pieces (rax of dungeon1..dungeon5 in keygen)
#  2. try every arrangement: 5! orders x 2^5 byte-reversals = 3840 candidate keys
#  3. each candidate is tried against ./task (the gatekeeper is skipped with gdb);
#     task is slow on purpose (about 1.3 s per guess), so we run many in parallel
# Needs addresses.json (written by build.py), because the shipped task is stripped.
# Usage: python3 solve.py [path/to/task]
import itertools
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

here = os.path.dirname(os.path.abspath(__file__))
task = sys.argv[1] if len(sys.argv) > 1 else os.path.join(here, "task")
gate = json.load(open(os.path.join(here, "addresses.json")))["task"]["gatekeeper"]

t = [
    [0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0xF0, 0xE1, 0xD2],
    [0x91, 0x07, 0xC4, 0x5E, 0xA8, 0x23, 0x6D, 0xFB],
    [0x1F, 0x8A, 0x42, 0xD9, 0x60, 0xB7, 0x35, 0xEC],
    [0xAA, 0x55, 0x0E, 0x71, 0xC3, 0x98, 0x2B, 0x64],
    [0x7C, 0xE2, 0x19, 0xB0, 0x46, 0xD5, 0x83, 0x2F],
]
SHIFT, K1, K2, K3 = 0x35, 0x5A, 0xA7, 0x3D

p = [
    [(t[0][i] + SHIFT + i) & 0xFF for i in range(8)],                          # dungeon1
    [(t[1][i] + K1) & 0xFF for i in range(8)],                                 # dungeon2
    [((c << 4) & 0xF0) | ((c >> 4) & 0x0F) for c in t[2]],                     # dungeon3
    [t[3][i] ^ ((K2 + i) & 0xFF) for i in range(8)],                           # dungeon4
    [((t[4][i] + K3) & 0xFF) ^ (t[4][i - 1] if i else 0) for i in range(8)],   # dungeon5
]
pieces = ["%016x" % int.from_bytes(bytes(x), "little") for x in p]             # as shown in rax
rev = ["%016x" % int.from_bytes(bytes(x), "big") for x in p]                   # byte-reversed
for n, s in enumerate(pieces, 1):
    print("dungeon%d -> %s" % (n, s))


def candidates():
    for order in itertools.permutations(range(5)):
        for flips in itertools.product((0, 1), repeat=5):
            yield order, flips, "".join((rev if f else pieces)[n] for n, f in zip(order, flips))


def attempt(c):
    order, flips, key = c
    r = subprocess.run(
        ["gdb", "-q", "-batch", "-ex", "break *%s" % gate, "-ex", "run", "-ex", "return",
         "-ex", "continue", task],
        input=key + "\n", capture_output=True, text=True)
    return order, flips, key, r.stdout


workers = os.cpu_count() or 4
print("trying 3840 candidates with %d workers ..." % workers)
with ThreadPoolExecutor(max_workers=workers) as ex:
    for order, flips, key, out in ex.map(attempt, candidates()):
        if "groans open" in out:
            print("order =", [n + 1 for n in order], " flipped slots =", flips)
            print("key   =", key)
            print("blob  =", out.split("groans open")[1].splitlines()[1].strip())
            sys.stdout.flush()
            os._exit(0)
    print("no arrangement worked")
