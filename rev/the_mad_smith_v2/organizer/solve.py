#!/usr/bin/env python3
# Solver (organizer only).
#  1. run ./keygen in gdb: bypass the ptrace check (catch syscall ptrace) and read rax after
#     each of the eight real piece functions (addresses from addresses.json; the shipped binary is stripped)
#  2. read KEY_SEED / KEY_HASH / STRETCH_ROUNDS from generated.h (a player reads them out of task)
#  3. try the orders of the eight pieces offline: fnv1a + the slow lossy hash, in C, one process per core.
#     8! = 40320 orders, so on a normal machine this takes a long time. Give the first slots
#     (--prefix 4,7,1, the last hints of the ladder) to cut it down to minutes.
# Usage: python3 solve.py [--prefix 4,7,1] [--task path/to/task]   (run it from the organizer folder)
import argparse
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor

here = os.path.dirname(os.path.abspath(__file__))
M = (1 << 64) - 1

CHECK_C = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "generated.h"
static uint64_t fnv1a(const unsigned char *p, size_t n){uint64_t h=0xCBF29CE484222325ULL;while(n--){h^=*p++;h*=0x100000001B3ULL;}return h;}
static uint64_t stretch(uint64_t h){uint64_t r;for(r=0;r<STRETCH_ROUNDS;r++){h^=h>>29;h*=0xBF58476D1CE4E5B9ULL;h^=(h&(h>>13))<<3;h+=r;}return h;}
int main(int c, char **v){unsigned char k[KEY_BYTES];char b[3];int i;
 for(i=0;i<KEY_BYTES;i++){b[0]=v[1][2*i];b[1]=v[1][2*i+1];b[2]=0;k[i]=(unsigned char)strtoul(b,0,16);}
 return stretch(fnv1a(k,KEY_BYTES))==KEY_HASH ? 0 : 1;}
"""


def get_pieces(keygen):
    addr = json.load(open(os.path.join(here, "addresses.json")))["keygen"]
    cmds = ["catch syscall ptrace", "run", "continue", "set $rax = 0", "delete 1"]
    cmds += ["break *%s" % addr["piece%d" % i] for i in range(1, 9)]
    for i in range(8):
        cmds += ["continue", "finish",
                 'printf "RAX' + str(i + 1) + ' %016lx\\n", $rax']
    cmds.append("continue")
    args = ["gdb", "-q", "-batch"] + sum([["-ex", c] for c in cmds], []) + [keygen]
    out = subprocess.run(args, capture_output=True, text=True).stdout
    found = dict(re.findall(r"^RAX(\d) ([0-9a-f]{16})$", out, re.M))
    if len(found) != 8:
        sys.exit("could not read the eight pieces:\n" + out)
    return [int(found[str(i)], 16) for i in range(1, 9)]


def smix(z):
    z = (z + 0x9E3779B97F4A7C15) & M
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M
    return z ^ (z >> 31)


def check(order_and_key):
    order, keyhex, check_bin = order_and_key
    return order, keyhex, subprocess.run([check_bin, keyhex]).returncode == 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prefix", default="", help="known first slots, dungeon numbers, e.g. 4,7,1")
    ap.add_argument("--task", default=os.path.join(here, "task"))
    ap.add_argument("--keygen", default=os.path.join(here, "keygen"))
    a = ap.parse_args()
    prefix = [int(x) - 1 for x in a.prefix.split(",") if x]

    pieces = get_pieces(a.keygen)
    for n, p in enumerate(pieces, 1):
        print("piece%d = %016x" % (n, p))
    seed = int(re.search(r"KEY_SEED (0x[0-9a-fA-F]+)", open(os.path.join(here, "generated.h")).read()).group(1), 16)
    masks = [smix((seed + i) & M) for i in range(8)]

    tmp = tempfile.mkdtemp()
    open(os.path.join(tmp, "check.c"), "w").write(CHECK_C)
    check_bin = os.path.join(tmp, "check")
    subprocess.run(["gcc", "-O2", "-I", here, os.path.join(tmp, "check.c"), "-o", check_bin], check=True)

    rest = [n for n in range(8) if n not in prefix]
    cands = []
    for tail in itertools.permutations(rest):
        order = prefix + list(tail)
        cands.append((order, "".join(pieces[n].to_bytes(8, "little").hex() for n in order), check_bin))
    workers = os.cpu_count() or 4
    print("trying %d orders with %d workers ..." % (len(cands), workers))
    with ProcessPoolExecutor(max_workers=workers) as ex:
        for order, keyhex, ok in ex.map(check, cands, chunksize=1):
            if ok:
                typed = "".join("%016x" % (int.from_bytes(bytes.fromhex(keyhex)[8 * i:8 * i + 8], "little") ^ m)
                                for i, m in enumerate(masks))
                print("order =", [n + 1 for n in order])
                print("key   =", typed)
                print("run task with it (gdb, both guards skipped) to get the blob")
                sys.stdout.flush()
                for p in list(ex._processes.values()):   # stop the other workers (they would keep the pipe open)
                    p.kill()
                os._exit(0)
    print("no arrangement worked")


if __name__ == "__main__":
    main()
