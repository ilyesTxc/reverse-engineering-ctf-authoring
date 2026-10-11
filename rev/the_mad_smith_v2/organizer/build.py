#!/usr/bin/env python3
"""
build.py - builds both CTF V2 binaries (the deeper trial).

It writes the fifteen decoy dungeons (keygen_decoys.h), re-computes the eight serial key pieces in
Python (independently of keygen.c), joins them in ORDER, encodes the flag in three levels, masks
the blob with the key, writes generated.h, compiles, and writes addresses.json.

Usage:   python3 build.py                 # default flag
         FLAG='SecurinetsENIT{my_flag}' python3 build.py
         DECOY_SEED=0x1234 python3 build.py       # a different set of decoys
"""
import base64
import codecs
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
FLAG = os.environ.get("FLAG", "SecurinetsENIT{th3_m4d_sm1th_dug_d33p3r_1nt0_ch40s}")
MASK64 = (1 << 64) - 1

SEED0 = 0x4D41445F534D4954          # what dungeon1 eats (keygen.c)
TABLES = [
    [0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0xF0, 0xE1, 0xD2],
    [0x91, 0x07, 0xC4, 0x5E, 0xA8, 0x23, 0x6D, 0xFB],
    [0x1F, 0x8A, 0x42, 0xD9, 0x60, 0xB7, 0x35, 0xEC],
    [0xAA, 0x55, 0x0E, 0x71, 0xC3, 0x98, 0x2B, 0x64],
    [0x7C, 0xE2, 0x19, 0xB0, 0x46, 0xD5, 0x83, 0x2F],
    [0x2E, 0xB4, 0x63, 0xD8, 0x07, 0x9A, 0xF1, 0x4C],
    [0xD3, 0x18, 0xA5, 0x6E, 0xC9, 0x02, 0x7B, 0xF6],
    [0x58, 0xC1, 0x94, 0x2D, 0xE7, 0x3A, 0x80, 0x6F],
]

# The real arrangement: key = piece ORDER[0] + piece ORDER[1] + ... (dungeons numbered 1..8).
# The order is not stored anywhere in the shipped programs: task only knows a hash of the finished key.
ORDER = [4, 7, 1, 8, 3, 6, 2, 5]
# In task.c each typed 16-digit slot is mixed with smix(MASK_SEED + slot) before it is checked,
# so the typed key is (piece ^ mask) for every slot.
MASK_SEED = 0x7E57C0DE5EED2B1D
# Rounds of the slow, lossy hash in task.c
STRETCH_ROUNDS = 600_000_000

N_DECOYS = 15
DECOY_SEED = int(os.environ.get("DECOY_SEED", "0x4D41445F56320001"), 0)


# ---------------------------------------------------------------- pieces (ground truth)

def rotl(x: int, n: int) -> int:
    return ((x << n) | (x >> (64 - n))) & MASK64


def byte(p: int, i: int) -> int:
    return (p >> (8 * (i & 7))) & 0xFF


def le(b) -> int:
    return int.from_bytes(bytes(b), "little")


def compute_pieces() -> list:
    """The eight pieces exactly as keygen.c's piece1..piece8 return them (rax), serially dependent."""
    t = TABLES
    out = []

    # piece1
    p = SEED0
    x = le([((t[0][i] ^ byte(p, i)) + 0x35 + i) & 0xFF for i in range(8)])
    out.append(x)

    # piece2
    p = x
    x = le(t[1]) ^ rotl(p, 17)
    x = (x * 0xD6E8FEB86659FD93) & MASK64
    x ^= x >> 29
    out.append(x)

    # piece3
    p = x
    x = le([(((c << 4) & 0xF0) | ((c >> 4) & 0x0F)) ^ byte(p, i + 3) for i, c in enumerate(t[2])])
    out.append(x)

    # piece4
    p = x
    x = (le(t[3]) + p) & MASK64
    x = rotl(x, 23) ^ (p >> 7)
    out.append(x)

    # piece5
    p = x
    b = []
    for i in range(8):
        b.append(((t[4][i] + 0x3D) & 0xFF) ^ (b[i - 1] if i else byte(p, 0)))
    x = le(b) ^ rotl(p, 5)
    out.append(x)

    # piece6
    p = x
    x = (le(t[5]) - p * 3) & MASK64
    x ^= (x << 11) & MASK64
    x ^= x >> 7
    out.append(x)

    # piece7
    p = x
    x = rotl(le([t[6][i] ^ ((byte(p, i) + byte(p, i + 1)) & 0xFF) for i in range(8)]), 9)
    out.append(x)

    # piece8
    p = x
    x = (le(t[7]) * 0x9FB21C651E98DF25 + rotl(p, 31)) & MASK64
    x ^= x >> 32
    out.append(x)
    return out


# ---------------------------------------------------------------- decoys

def gen_decoys(seed: int) -> str:
    """C source of N_DECOYS decoy dungeons that look like the real ones.
    Same seed -> same decoys, so a build is reproducible. They are spread over four places in
    keygen.c (DECOY_PART 0..3), and called from main in between the real pieces."""
    rng = random.Random(seed)
    parts = [rng.randrange(4) for _ in range(N_DECOYS)]
    slots = sorted(rng.randrange(9) for _ in range(N_DECOYS))      # DECOY_AFTER_<slot>
    funcs = [[] for _ in range(4)]
    calls = [[] for _ in range(9)]

    for n in range(N_DECOYS):
        t = ", ".join("0x%02X" % rng.randrange(256) for _ in range(8))
        k = rng.getrandbits(64) | 1
        c1, c2, r, s = rng.randrange(1, 256), rng.randrange(1, 256), rng.randrange(3, 61), rng.randrange(5, 40)
        kind = rng.randrange(6)
        head = "__attribute__((noinline)) uint64_t decoy_%02d(uint64_t p)\n{\n    unsigned char t[8] = { %s };\n" % (n + 1, t)
        if kind == 0:
            body = ("    unsigned char b[8];\n    uint64_t x;\n    int i;\n\n"
                    "    for (i = 0; i < 8; i++)\n        b[i] = (unsigned char)((t[i] ^ BYTE(p, i)) + 0x%02X + i);\n"
                    "    memcpy(&x, b, sizeof x);\n    return x;\n") % c1
        elif kind == 1:
            body = ("    uint64_t x;\n\n    memcpy(&x, t, sizeof x);\n    x ^= ROTL(p, %d);\n"
                    "    x *= 0x%016XULL;\n    x ^= x >> %d;\n    return x;\n") % (r, k, s)
        elif kind == 2:
            body = ("    unsigned char b[8];\n    uint64_t x;\n    int i;\n\n"
                    "    for (i = 0; i < 8; i++)\n"
                    "        b[i] = (unsigned char)((((t[i] << 4) & 0xF0) | ((t[i] >> 4) & 0x0F)) ^ BYTE(p, i + %d));\n"
                    "    memcpy(&x, b, sizeof x);\n    return x;\n") % rng.randrange(1, 8)
        elif kind == 3:
            body = ("    uint64_t x;\n\n    memcpy(&x, t, sizeof x);\n    x += p;\n"
                    "    x = ROTL(x, %d) ^ (p >> %d);\n    return x;\n") % (r, s)
        elif kind == 4:
            body = ("    unsigned char b[8];\n    uint64_t x;\n    int i;\n\n"
                    "    for (i = 0; i < 8; i++)\n"
                    "        b[i] = (unsigned char)((t[i] + 0x%02X) ^ (i ? b[i - 1] : BYTE(p, 0)));\n"
                    "    memcpy(&x, b, sizeof x);\n    return x ^ ROTL(p, %d);\n") % (c2, r)
        else:
            body = ("    uint64_t x;\n\n    memcpy(&x, t, sizeof x);\n    x -= p * %d;\n"
                    "    x ^= x << %d;\n    x ^= x >> %d;\n    return x;\n") % (rng.randrange(2, 9), r % 20 + 3, s)
        funcs[parts[n]].append(head + body + "}\n")

        # argument: a constant, an earlier real piece, or an earlier decoy result
        slot = slots[n]
        choices = ["0x%016XULL" % rng.getrandbits(64)]
        choices += ["piece[%d]" % j for j in range(slot)]
        choices += ["junk[%d]" % j for j in range(n)]
        calls[slot].append("junk[%d] = decoy_%02d(%s);" % (n, n + 1, rng.choice(choices)))

    out = ["/* generated by build.py - do not edit */\n"]
    for part in range(4):
        out.append("%s DECOY_PART == %d\n%s#endif\n" % ("#if" if part == 0 else "#if", part,
                   "\n".join(funcs[part]) if funcs[part] else ""))
    out.append("#ifndef DECOY_COUNT\n#define DECOY_COUNT %d\n" % N_DECOYS)
    for slot in range(9):
        out.append("#define DECOY_AFTER_%d %s\n" % (slot, " ".join(calls[slot])))
    out.append("#endif\n")
    return "\n".join(out)


# ---------------------------------------------------------------- key, masks, hash, blob

def smix(z: int) -> int:
    z = (z + 0x9E3779B97F4A7C15) & MASK64
    z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
    z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & MASK64
    return z ^ (z >> 31)


def slot_masks() -> list:
    return [smix((MASK_SEED + i) & MASK64) for i in range(8)]


def compute_key() -> bytes:
    """64-byte key: the eight pieces in ORDER, each as 8 little-endian bytes (as in memory)"""
    p = compute_pieces()
    return b"".join(p[n - 1].to_bytes(8, "little") for n in ORDER)


def key_text(key: bytes) -> str:
    """What the player types: each real piece XORed with its slot mask, 16 hex digits each"""
    return "".join("%016x" % (int.from_bytes(key[8 * i:8 * i + 8], "little") ^ m)
                   for i, m in enumerate(slot_masks()))


def fnv1a(data: bytes) -> int:
    h = 0xCBF29CE484222325
    for c in data:
        h = ((h ^ c) * 0x100000001B3) & MASK64
    return h


STRETCH_C = (
    "static uint64_t stretch(uint64_t h, uint64_t n){uint64_t r;"
    "for(r=0;r<n;r++){h^=h>>29;h*=0xBF58476D1CE4E5B9ULL;h^=(h&(h>>13))<<3;h+=r;}return h;}\n"
)


def stretch(h: int) -> int:
    """Same slow loop as task.c. 600M rounds are far too slow in Python, so run it in C."""
    src = ("#include <stdint.h>\n#include <stdio.h>\n#include <stdlib.h>\n" + STRETCH_C +
           'int main(int c, char **v){printf("%016llx\\n",(unsigned long long)'
           "stretch(strtoull(v[1],0,16),strtoull(v[2],0,10)));return 0;}\n")
    with tempfile.TemporaryDirectory() as d:
        c = os.path.join(d, "s.c")
        open(c, "w").write(src)
        subprocess.run(["gcc", "-O2", c, "-o", os.path.join(d, "s")], check=True)
        out = subprocess.run([os.path.join(d, "s"), "%016x" % h, str(STRETCH_ROUNDS)], check=True,
                             capture_output=True, text=True).stdout
    return int(out, 16)


def encode_blob(flag: str) -> bytes:
    """Level 1: ROT13   Level 2: Base32   Level 3: reverse the text"""
    lvl1 = codecs.encode(flag, "rot_13")
    lvl2 = base64.b32encode(lvl1.encode()).decode()
    return lvl2[::-1].encode()


def mask(data: bytes, kb: bytes) -> bytes:
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


def write_header(key: bytes, blob: bytes) -> None:
    masked = mask(blob, key)
    arr = ", ".join("0x%02x" % b for b in masked)
    with open(os.path.join(HERE, "generated.h"), "w") as f:
        f.write("/* generated by build.py - do not edit */\n")
        f.write("#define KEY_BYTES %d\n" % len(key))
        f.write("#define KEY_SEED 0x%016xULL\n" % MASK_SEED)
        f.write("#define KEY_HASH 0x%016xULL\n" % stretch(fnv1a(key)))
        f.write("#define STRETCH_ROUNDS %dULL\n" % STRETCH_ROUNDS)
        f.write("#define BLOB_LEN %d\n" % len(masked))
        f.write("static const unsigned char blob_data[BLOB_LEN] = { %s };\n" % arr)


# ---------------------------------------------------------------- compile

def symbol_addresses(binary: str) -> dict:
    out = subprocess.run(["nm", binary], cwd=HERE, check=True, capture_output=True, text=True).stdout
    want = ("main", "gatekeeper", "tracer_check", "access_granted", "print_blob", "piece", "decoy_", "blob_data")
    return {l.split()[2]: "0x" + l.split()[0].lstrip("0") for l in out.splitlines()
            if len(l.split()) == 3 and l.split()[2].startswith(want)}


def compile_all() -> None:
    """Builds unstripped copies (*.unstripped, organizer only, with symbols) and the
    shipped binaries, which are stripped (Ghidra shows FUN_xxxxxxxx names)."""
    flags = ["-std=gnu11", "-O0", "-no-pie", "-fno-pie", "-fno-stack-protector", "-Wall", "-Wextra"]
    addrs = {}
    for src, out in (("keygen.c", "keygen"), ("task.c", "task")):
        cmd = ["gcc"] + flags + [src, "-o", out + ".unstripped"]
        print(" ".join(cmd))
        subprocess.run(cmd, cwd=HERE, check=True)
        addrs[out] = symbol_addresses(out + ".unstripped")
        shutil.copyfile(os.path.join(HERE, out + ".unstripped"), os.path.join(HERE, out))
        subprocess.run(["strip", "-s", out], cwd=HERE, check=True)
        os.chmod(os.path.join(HERE, out), 0o755)
    with open(os.path.join(HERE, "addresses.json"), "w") as f:
        json.dump(addrs, f, indent=2, sort_keys=True)


if __name__ == "__main__":
    assert sorted(ORDER) == list(range(1, 9))
    open(os.path.join(HERE, "keygen_decoys.h"), "w").write(gen_decoys(DECOY_SEED))
    key = compute_key()
    blob = encode_blob(FLAG)
    for n, p in enumerate(compute_pieces(), 1):
        print("piece%d = %016x" % (n, p))
    print("order = %s   masks = %s" % (ORDER, ["%016x" % m for m in slot_masks()]))
    print("key  = %s" % key_text(key))
    print("blob = %s" % blob.decode())
    write_header(key, blob)
    compile_all()
    sys.exit(0)
