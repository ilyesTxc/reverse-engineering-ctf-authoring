# The Mad Smith's Forge - Solution (organizer only)

**Category:** Reverse Engineering | **Difficulty:** beginner to intermediate (1-2 hours)
**Flag:** `SecurinetsENIT{th3_m4d_sm1th_h0lds_rax_1n_ch40s}`

Players get `keygen` (the Forge) and `task` (the Great Gate), both stripped, plus `CHALLENGE.txt`.

## The challenge in short

1. `keygen` builds **5 pieces** (one per dungeon) and throws them away. They are never printed.
2. `task` is blocked by a gatekeeper. It must be skipped in a debugger.
3. The real key is the 5 pieces **joined in a secret order**, with some pieces **byte-reversed**. That is 120 orders x 32 reversals = **3,840 possible keys**.
4. A wrong key costs about 1.3 seconds, so guessing blindly is slow.
5. A right key makes `task` print a blob. Decode it (Base64, Hex, ROT13) to get the flag.

## Solution

### Step 1 - First look
```
file keygen task      # stripped 64-bit ELF
strings keygen task   # only the Mad Smith messages
./task                # "The Great Gate is sealed ... You shall not pass."
```

### Step 2 - Get the 5 pieces from keygen
Open `keygen` in Ghidra. `main` (`FUN_004005dc`) calls five functions, one per dungeon. Each one builds 8 bytes from its own table with a simple transform. The result is the piece.

Read each piece in gdb:
```
gdb ./keygen
break *0x400466      # dungeon1 (repeat for the other 4 addresses below)
run
finish               # run until the function returns
info registers rax   # this is the piece
continue
```

| Dungeon | Address | What it does to its table (i = 0..7) | Piece (rax) |
|---|---|---|---|
| 1 | 0x400466 | `t[i] + 0x35 + i` | `0e1c2a4856647280` |
| 2 | 0x4004a8 | `t[i] + 0x5A` | `55c77d02b81e61eb` |
| 3 | 0x4004e5 | swap the two nibbles | `ce537b069d24a8f1` |
| 4 | 0x400537 | `t[i] ^ (0xA7 + i)` | `ca863468dba7fd0d` |
| 5 | 0x40057d | `(t[i] + 0x3D) ^ t[i-1]` (`t[-1]` = 0) | `ef155433f4b463b9` |

(All math is per byte, mod 256. `solve.py` shows the same thing in Python.)

### Step 3 - Find the arrangement
Still in `main` of `keygen`, after the five calls, a loop fills the 5 key slots:
- slot `i` takes piece number `order[i]` = 3, 5, 1, 4, 2
- and byte-reverses it when `flip[i]` = 1, 0, 1, 1, 0

So the key is, 16 hex digits per slot:

| Slot | Piece | Typed value |
|---|---|---|
| 1 | dungeon 3, reversed | `f1a8249d067b53ce` |
| 2 | dungeon 5 | `ef155433f4b463b9` |
| 3 | dungeon 1, reversed | `80726456482a1c0e` |
| 4 | dungeon 4, reversed | `0dfda7db683486ca` |
| 5 | dungeon 2 | `55c77d02b81e61eb` |

```
f1a8249d067b53ceef155433f4b463b980726456482a1c0e0dfda7db683486ca55c77d02b81e61eb
```

Players who do not read `main` can brute-force all 3,840 keys instead. `solve.py` does this in parallel (about 3 minutes on 16 cores). Run it with `python3 solve.py`. It needs `addresses.json`, which `build.py` writes.

`task` stores only a slow hash of the key, so the key cannot be read from `task` in Ghidra.

### Step 4 - Get past the gatekeeper in task
`main` of `task` (`FUN_0040064b`) calls `gatekeeper` (`FUN_004004d6`) first. It exits unless a variable is set, and nothing sets it. Any one of these works in gdb:

```
# a) return from it at once
break *0x4004d6
run
return

# b) jump over the call
break *0x400656
run
jump *0x40065b

# c) set the variable it checks
break *0x4004d6
run
set var *(int*)0x40306c = 1
continue
```
When the prompt appears, paste the 80-digit key.

### Step 5 - Decode the blob
Blob: `NDY3MjcwNjg2NTc2NjE3MjY3NjY1MjQxNTY0NzdiNjc3NTMzNWY3YTM0NzE1ZjY2N2EzMTY3NzU1Zjc1MzA3OTcxNjY1ZjY1NmU2YjVmMzE2MTVmNzA3NTM0MzA2Njdk`

| Level | Decode with | Result |
|---|---|---|
| 1 | From Base64 | hex digits as text (`4672706865...`) |
| 2 | From Hex | `FrphevargfRAVG{gu3_z4q_fz1gu_u0yqf_enk_1a_pu40f}` |
| 3 | ROT13 | `SecurinetsENIT{th3_m4d_sm1th_h0lds_rax_1n_ch40s}` |

CyberChef recipe: **From Base64 -> From Hex -> ROT13** (the Magic wand finds it too).

## Hints (give one at a time)

1. "The keygen does print the pieces, just not on the screen."
2. "Registers hold the result of a function when it returns."
3. "`finish` in gdb runs until the current function returns."
4. "The task refuses to start. What does `main` do first?"
5. "You do not have to obey a function. You can skip it."
6. "Each decoding level gives something. Does it look familiar?"
7. "Five pieces can be joined in more than one order. Look at what `main` does after the five calls."
8. "The key has 80 hex digits, 16 per piece."
9. "A piece does not have to be used the way rax shows it. Look at what `main` does to each piece."
10. "A wrong guess costs about a second. Do not guess blindly, read `main`."

## Building and shipping

```
python3 build.py
FLAG='SecurinetsENIT{your_flag}' python3 build.py     # different flag
```
- To change the arrangement, edit `ORDER` and `FLIP` at the top of `build.py`. To change the cost of a wrong guess, edit `STRETCH_ROUNDS`.
- After any rebuild the addresses in this file change. They are in `addresses.json`, or use `objdump -d -M intel task.unstripped`.
- `build.py` also writes `keygen.unstripped` and `task.unstripped` (with symbols) for you. Do not give those to players.
- Give players only `ctf_v1_player/` (`keygen`, `task`, `CHALLENGE.txt`). Keep this file, the `.c` files, `generated.h`, `solve.py`, `addresses.json` and the `*.unstripped` files private.
- The binaries need glibc 2.34 or newer (Ubuntu 22.04+, recent Debian or Kali).
- The blob is XOR-masked with the key, so patching out the key check does not give the flag.
- There is no anti-debugging and no packing, on purpose.
