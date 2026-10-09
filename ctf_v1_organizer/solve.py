#!/usr/bin/env python3
# Solver: recompute the five pieces (rax of dungeon1..dungeon5 in keygen), then try
# all 5! = 120 orders against ./task. The gatekeeper is skipped with gdb.
# Usage: python3 solve.py [path/to/task]
import itertools
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

task = sys.argv[1] if len(sys.argv) > 1 else "./task"

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
for n, s in enumerate(pieces, 1):
    print("dungeon%d -> %s" % (n, s))


def attempt(order):
    key = "".join(pieces[n] for n in order)
    r = subprocess.run(
        ["gdb", "-q", "-batch", "-ex", "break gatekeeper", "-ex", "run", "-ex", "return",
         "-ex", "continue", task],
        input=key + "\n", capture_output=True, text=True)
    return order, key, r.stdout


with ThreadPoolExecutor(max_workers=8) as ex:
    for order, key, out in ex.map(attempt, itertools.permutations(range(5))):
        if "Gate groans open" in out:
            print("order =", [n + 1 for n in order])
            print("key   =", key)
            print("blob  =", out.split("groans open")[1].splitlines()[1].strip())
            break
    else:
        print("no order worked")
