#!/usr/bin/env python3
# Solver (organizer only).
#  1. recompute the five pieces (rax of dungeon1..dungeon5 in keygen)
#  2. work out the five slot masks (task: smix(seed + slot), seed from generated.h here),
#     then try every order of the five pieces, each piece XORed with its slot mask:
#     5! = 120 candidate keys (the order is nowhere in the programs)
#  3. each candidate is tried against ./task (the gatekeeper is skipped with gdb);
#     task is slow on purpose (about 1.3 s per guess), so we run them in parallel
# Needs addresses.json (written by build.py), because the shipped task is stripped.
# Usage: python3 solve.py [path/to/task]
import itertools
import json
import os
import re
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

M = (1 << 64) - 1


def smix(z):
    z = (z + 0x9E3779B97F4A7C15) & M
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M
    return z ^ (z >> 31)


seed = int(re.search(r"KEY_SEED (0x[0-9a-fA-F]+)", open(os.path.join(here, "generated.h")).read()).group(1), 16)
masks = [smix((seed + i) & M) for i in range(5)]


def candidates():
    for order in itertools.permutations(range(5)):
        yield order, "".join("%016x" % (int(pieces[n], 16) ^ m) for n, m in zip(order, masks))


def attempt(c):
    order, key = c
    r = subprocess.run(
        ["gdb", "-q", "-batch", "-ex", "break *%s" % gate, "-ex", "run", "-ex", "return",
         "-ex", "continue", task],
        input=key + "\n", capture_output=True, text=True)
    return order, key, r.stdout


workers = os.cpu_count() or 4
print("trying 120 candidates with %d workers ..." % workers)
with ThreadPoolExecutor(max_workers=workers) as ex:
    for order, key, out in ex.map(attempt, candidates()):
        if "groans open" in out:
            print("order =", [n + 1 for n in order])
            print("key   =", key)
            print("blob  =", out.split("groans open")[1].splitlines()[1].strip())
            sys.stdout.flush()
            os._exit(0)
    print("no arrangement worked")
