# The Mad Smith's Forge V2 (the deeper trial) - Solution (organizer only)

**Category:** Reverse Engineering | **Difficulty:** intermediate to hard (several hours)
**Flag:** `SecurinetsENIT{th3_m4d_sm1th_dug_d33p3r_1nt0_ch40s}`

Players get `keygen` (the Forge) and `task` (the Great Gate), both stripped, plus `CHALLENGE.txt`.

## Answer sheet (quick reference)

| What | Value |
|---|---|
| Right key (128 hex digits) | `918538c38f340e863519d4efd3e05d7fca6468f24ec6411838183a8572cc670504ab51bb20bc4571822651b9889af2467e5625b73b5c94db6c53306db0164c86` |
| Order of the pieces (slot 1..8) | dungeon 4, 7, 1, 8, 3, 6, 2, 5 |
| Blob that `task` prints | `======UPGDMIT2BO7CMOWQFG7KZGTRNGTJ46F2BNR3XKXTFG2TZ6VYRG23XGT25M33RMVAJKG3ZEXQZOFD2AHZZI` |
| Decode the blob | Reverse -> From Base32 -> ROT13 |
| One wrong key costs | 1.30 s (median of 5 runs, see "Timing") |
| All 8! = 40320 orders | about 14.6 hours on one core (about 50 minutes on 16 cores) |
| Fast check | `python3 solve.py --prefix 4,7,1` (about 12 s); without `--prefix` it tries all orders |

## The idea in a few lines

1. `keygen` has **8 real dungeons** and **15 decoys**, all `noinline` functions of the same shape (a local 8-byte table plus a few operations). `main` calls all 23, stores the results and prints one line. Nothing else.
2. The 8 real dungeons are **serially dependent**: dungeon 1 eats a fixed constant, dungeon *n* eats the piece that dungeon *n-1* returned. A player must read them in order. Decoys sometimes eat real pieces or other decoys as input, but nothing real ever uses a decoy.
3. `keygen` starts with `ptrace(PTRACE_TRACEME)`. Under gdb or strace it fails and the program exits.
4. `task` has a **gatekeeper** (exits unless a variable is set, nothing sets it) and then a **TracerPid check** (reads `/proc/self/status`, exits when TracerPid is not 0). Both must be skipped.
5. `task` asks for a **128-digit key** (eight 16-digit chunks), mixes each chunk with a **mask computed from its position**, and compares a **slow, lossy hash** of the result with a stored value.
6. The right key is the 8 pieces in a **secret order**, each piece XORed with the mask of the slot it sits in. The order is stored nowhere. The slow hash cannot be run backwards (the AND in each round throws bits away), so every candidate order really costs about 1.3 s.
7. The right key makes `task` print a blob. Decoding it gives the flag.

## Step by step

### Step 1 - First look
```
file keygen task      # stripped 64-bit ELF, dynamically linked
strings keygen task   # Mad Smith messages, ptrace (keygen), /proc/self/status and TracerPid: (task)
floss keygen task     # FLOSS only does static strings on ELF, same result
./keygen              # prints one line, nothing else
./task                # "The Great Gate is sealed ... You shall not pass."
gdb ./keygen          # run -> "Someone is watching the forge. Begone, spy!"
```
The imports already give both anti-debug checks away (`ptrace` in keygen, `fopen` + `strtol` and the string `TracerPid:` in task). The strings contain no flag, no piece, no key and no order.

### Step 2 - Bypass the ptrace check in keygen
In Ghidra, `main` of `keygen` (`FUN_00400e65`) calls `ptrace(0, 0, 0, 0)` first and exits when the result is -1 (`cmp rax,-1` at `0x400e8e`, `jne` at `0x400e92`). Any of these works (all tested):

```
# a) catch the syscall and fake the result
catch syscall ptrace
run
continue              # now at syscall exit
set $rax = 0
delete 1              # drop the catchpoint, or it fires again on the next ptrace

# b) break on the compare and fake the result
break *0x400e8e
run
set $rax = 0
continue

# c) patch the conditional jump (jne -> jmp) before it runs
break *0x400e89
run
set {unsigned char}0x400e92 = 0xeb
continue
```
After this `keygen` runs to the end and prints its line.

### Step 3 - Get the 8 real pieces, in order
`main` calls 23 functions. They look alike and are spread over the binary in no useful order. The real ones are the ones whose result feeds the next real one: follow each call's argument and result through the stack slots in `main` (Ghidra's decompiler shows `local_xx = FUN_xxxx(local_yy)`). Dungeon 1 takes the constant `0x4d41445f534d4954`; the 8-element chain `piece[0]..piece[7]` is the real one, and anything that is never passed to the next real function is a decoy.

Read each piece in gdb, in order, with the ptrace bypass in place. Addresses (`addresses.json`):

| Dungeon | Address | What it does with its table `t` and the previous piece `p` | Piece (rax) |
|---|---|---|---|
| 1 | 0x4006a1 | `(t[i] ^ byte_i(p)) + 0x35 + i`, bytewise | `dbdbee898597ab54` |
| 2 | 0x40070c | `((t ^ rotl(p,17)) * 0xD6E8FEB86659FD93)`, then `x ^= x>>29` | `f6d8aa782982e02e` |
| 3 | 0x4008b8 | nibble-swap `t[i]`, XOR `byte_(i+3)(p)` | `4cb355f0458ed0d8` |
| 4 | 0x400934 | `rotl(t + p, 23) ^ (p >> 7)` | `59422838a1d372d6` |
| 5 | 0x400b41 | `(t[i]+0x3D) ^ prev byte` (byte 0 chains to `p`'s low byte), then `^ rotl(p,5)` | `dedf5d5cf1482aa4` |
| 6 | 0x400bbb | `t - 3*p`, then `x ^= x<<11; x ^= x>>7` | `2c04b1c6f793760a` |
| 7 | 0x400d87 | `rotl(bytes t[i] ^ (byte_i(p)+byte_(i+1)(p)), 9)` | `976f7da65e22a780` |
| 8 | 0x400e0a | `t * 0x9FB21C651E98DF25 + rotl(p,31)`, then `x ^= x>>32` | `68899e91fa6ac61a` |

gdb session (tested; prints exactly these values):
```
catch syscall ptrace
run
continue
set $rax = 0
delete 1
break *0x4006a1       # ... one break per real dungeon, 8 in all
continue
finish
info registers rax    # repeat continue / finish / info registers for each of the 8 stops
```
A player can also reimplement the 8 functions in Python (`build.py: compute_pieces()` is the reference), but every one needs the previous piece, so the order of extraction matters and a mistake in one corrupts all that follow. Reading rax in gdb avoids reimplementing anything.

### Step 4 - Get past both guards in task
`main` of `task` (`FUN_004007b5`) calls `gatekeeper` (`FUN_00400516`) and then `tracer_check` (`FUN_0040053b`). Every method below was tested.

Gatekeeper (any one):
```
break *0x400516
run
return                          # return from it at once
# or:  set var *(int*)0x40308c = 1    (the variable it checks)
```
`tracer_check` opens `/proc/self/status`, finds the `TracerPid:` line, converts it with `strtol`, and exits when it is not 0 (`cmp [rbp-8],0` at `0x4005d3`, `je` at `0x4005d8`). Any one of:
```
# a) return from it at once
break *0x40053b
...
return

# b) fake the value it just read
break *0x4005d3
...
set {long}($rbp-8) = 0
continue

# c) patch the conditional jump (je -> jmp)
set {unsigned char}0x4005d8 = 0xeb
```
Complete working example (prints the blob when given the right key):
```
echo KEY | gdb -q -batch -ex "break *0x400516" -ex run \
  -ex "set var *(int*)0x40308c=1" -ex "set {unsigned char}0x4005d8=0xeb" -ex continue ./task
```
After this `task` shows the prompt `Enter the key:`.

### Step 5 - Find the mask rule in task
In `main` of `task`: the typed key is read as eight 16-digit chunks. For chunk `i` (0 to 7) the program does:
- `mask = smix(0x7e57c0de5eed2b1d + i)`, where `smix` is a small hash (add, multiply, shifts),
- `chunk = chunk + mask - 2*(chunk & mask)`, which is `chunk ^ mask`, written so that it does not look like an XOR.

Then it joins the 8 results (64 bytes), hashes them with FNV-1a, runs a slow loop (600 million rounds) and compares with a stored value. The key is not stored in `task`.

Value to type for each slot is `piece ^ mask(slot)`:

| Slot | Mask | Piece in this slot (right order) | Typed value |
|---|---|---|---|
| 1 | `c8c710fb2ee77c50` | dungeon 4 `59422838a1d372d6` | `918538c38f340e86` |
| 2 | `a276a9498dc2faff` | dungeon 7 `976f7da65e22a780` | `3519d4efd3e05d7f` |
| 3 | `11bf867bcb51ea4c` | dungeon 1 `dbdbee898597ab54` | `ca6468f24ec64118` |
| 4 | `5091a41488a6a11f` | dungeon 8 `68899e91fa6ac61a` | `38183a8572cc6705` |
| 5 | `4818044b653295a9` | dungeon 3 `4cb355f0458ed0d8` | `04ab51bb20bc4571` |
| 6 | `ae22e07f7f09844c` | dungeon 6 `2c04b1c6f793760a` | `822651b9889af246` |
| 7 | `888e8fcf12de74f5` | dungeon 2 `f6d8aa782982e02e` | `7e5625b73b5c94db` |
| 8 | `b28c6d31415e6622` | dungeon 5 `dedf5d5cf1482aa4` | `6c53306db0164c86` |

The hash is computed over the **unmasked** bytes: each piece, little-endian, in slot order. A player who types raw pieces, or who forgets the masks, fails every time.

### Step 6 - Try the orders
Nothing in the programs shows the order. 8! = 40320 candidates.
- Through `task` in gdb a wrong guess costs about 1.3 s (that is about 14.6 hours of CPU in total).
- A player can skip `task` entirely: read `KEY_HASH` (the 8-byte constant it compares to) and reimplement FNV-1a and the 600-million-round loop in C, then test candidates offline. That costs the same time per guess (about 1.3 s), but with no gdb overhead and in parallel on all cores.
- Running the slow loop backwards does not work: `h ^= (h & (h >> 13)) << 3` is not invertible, so there is no shortcut around the 600 million rounds per candidate.

`solve.py` does exactly the offline approach: it reads the 8 pieces with gdb, takes the seed from `generated.h`, compiles a C checker and tries the orders on all cores. `--prefix 4,7,1` fixes the first slots (the last hint of the ladder). `python3 solve.py` alone tries all 40320.

### Step 7 - Decode the blob
| Level | Decode with | Result |
|---|---|---|
| 1 | Reverse (by character) | Base32 text |
| 2 | From Base32 | `FrphevargfRAVG{...}` |
| 3 | ROT13 | `SecurinetsENIT{th3_m4d_sm1th_dug_d33p3r_1nt0_ch40s}` |

CyberChef recipe: **Reverse -> From Base32 -> ROT13**.

## Timing (measured on the build machine, 16 cores)

| What | Measured |
|---|---|
| One wrong key through `task` in gdb (5 runs: 1.90 (cold), 1.31, 1.29, 1.30, 1.30 s) | **1.30 s** (median) |
| All 8! = 40320 orders, one core | 40320 x 1.30 s = **52,400 s = 14.6 hours** (calculated from the measured 1.30 s) |
| `solve.py --prefix 4,7,1` (120 orders, 16 workers, including gdb piece extraction) | **11.8 s** (measured) |
| All 40320 orders on 16 cores | about 50 minutes (extrapolated, not measured end to end) |

## Hints (give one at a time)

1. "The Forge does print the pieces, just not on the screen."
2. "Registers hold the result of a function when it returns."
3. "Not every dungeon is real. Real ones feed each other."
4. "The Forge does not like to be watched. What does `main` ask the kernel first?"
5. "`catch syscall` and `set $rax` can lie to a program."
6. "The Gate has two guards, not one. The second looks at `/proc`."
7. "You do not have to obey a function. You can skip it, or change what it saw."
8. "The key has 128 hex digits, 16 per piece. There are exactly eight pieces."
9. "The pieces from the Forge are not typed as they are. Look at what the Gate does to each chunk you type."
10. "Nothing tells you the order of the pieces. Write a script. A wrong guess costs a second or more: do not use gdb for every try, and use every core."
11. "The first three slots hold dungeons 4, 7 and 1, in that order."

## Building and shipping

```
python3 build.py
FLAG='SecurinetsENIT{your_flag}' python3 build.py     # different flag
DECOY_SEED=0x1234 python3 build.py                    # different decoys
```
- **Settings at the top of `build.py`:** `ORDER` (the secret order, stored nowhere in the shipped programs), `MASK_SEED` (the seed for the slot masks, used by `task`), `STRETCH_ROUNDS` (how slow a wrong guess is: 600 million is about 1.3 s here), `N_DECOYS`, `DECOY_SEED`.
- `build.py` writes `keygen_decoys.h` (the 15 decoy dungeons and their calls, the same seed gives the same decoys), `generated.h`, both binaries (`-O0 -no-pie -fno-stack-protector`, shipped ones stripped), the `*.unstripped` copies and `addresses.json`.
- After any rebuild (new decoy seed, new code), use the new `addresses.json` for every address in this file.
- **Give players only** `player/` (`keygen`, `task`, `CHALLENGE.txt`). **Keep private:** this file, the `.c` and `.h` files, `build.py`, `solve.py`, `addresses.json` and the `*.unstripped` files.
- The binaries need glibc 2.34 or newer (Ubuntu 22.04+, recent Debian or Kali). Built here with gcc 16.2 and glibc 2.43.
- The blob is XOR-masked with the key, so patching out the key check does not give the flag.
- Players need `/proc` mounted (the TracerPid check passes silently when `/proc/self/status` cannot be opened) and a kernel that allows `PTRACE_TRACEME` (under a seccomp profile that forbids `ptrace`, such as some container defaults, `keygen` exits at once even without a debugger: tell players to run it in a VM or normal Linux).
- Do not press Ctrl-C or send signals to a running `keygen`: after a successful `PTRACE_TRACEME` the shell is its tracer and a signal stops it. Plain runs are fine.
- No packing, no network code. The only anti-debug are the two well-known checks above.
