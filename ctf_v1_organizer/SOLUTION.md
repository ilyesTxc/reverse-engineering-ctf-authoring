# CTF V1 "The Mad Smith's Forge" - Organizer Notes and Solution

**Difficulty:** beginner (about 30 to 60 minutes)
**Category:** Reverse Engineering
**Flag:** `SecurinetsENIT{th3_m4d_sm1th_h0lds_rax_1n_ch40s}` 

## What players get

Two Linux 64-bit programs: `keygen` and `task`. See `CHALLENGE.txt` for the text players see.

## The idea in one paragraph

`keygen` (the Forge) builds five independent 64-bit pieces (`dungeon1` to `dungeon5`, one per dungeon), each with its own table and transform, and never prints them. `main` joins them in a hidden order into a 40-byte key. `task` (the Great Gate) refuses to start because `gatekeeper` always exits before the prompt appears, and it stores only a hash of the key. Players must (1) recover the five pieces (the value in rax after each dungeon function returns), (2) work out the arrangement (5! = 120 possible orders, found either by reading `main` in Ghidra or by trying them all), (3) get past `gatekeeper` in `task`, (4) type the 80-hex-digit key to receive an encoded blob, and (5) decode the blob in three levels to get the flag.

## Solution walkthrough

### Stage 0: first look
```
$ file keygen task          # ELF 64-bit, not stripped
$ strings keygen            # only the Mad Smith message
$ ./keygen                  # prints a message, no key
$ ./task                    # "The Great Gate is sealed by the Mad Smith. You shall not pass."
```

### Stage 1: get the five pieces from keygen

**Way A: read rax after each dungeon in gdb**
```
$ gdb ./keygen
pwndbg> break dungeon1             (and dungeon2 ... dungeon5)
pwndbg> run
pwndbg> finish                  # run until the dungeon returns
pwndbg> info registers rax      # the piece
pwndbg> continue                # next dungeon
```

| Dungeon | Address | Transform of its own 8-byte table (i = 0..7, mod 256) | Piece (rax) |
|---|---|---|---|
| dungeon1 | 0x400466 | `t[i] + 0x35 + i` | `0e1c2a4856647280` |
| dungeon2 | 0x4004a8 | `t[i] + 0x5A` | `55c77d02b81e61eb` |
| dungeon3 | 0x4004e5 | swap the nibbles of `t[i]` | `ce537b069d24a8f1` |
| dungeon4 | 0x400537 | `t[i] ^ (0xA7 + i)` | `ca863468dba7fd0d` |
| dungeon5 | 0x40057d | `(t[i] + 0x3D) ^ t[i-1]` (`t[-1]` = 0) | `ef155433f4b463b9` |

Each piece is the 8 result bytes read as a little-endian uint64, which is what rax shows. The tables are in `.rodata` (symbols `table1` 0x401220 to `table5` 0x401240; `main` in `keygen` is 0x4005dc). Way B is to read each function in Ghidra and recompute it (see `solve.py`).

### Stage 1b: find the arrangement

`main` calls the five dungeons in order, then copies the pieces into the key in a different order (`order[]` = 2, 4, 0, 3, 1, zero-based). Reading that array in Ghidra gives the answer directly. Without it there are 5! = 120 orders to try. Joined as 16 hex digits per piece, the right one is:

```
dungeon3 dungeon5 dungeon1 dungeon4 dungeon2
ce537b069d24a8f1ef155433f4b463b90e1c2a4856647280ca863468dba7fd0d55c77d02b81e61eb
```
`solve.py` computes the pieces and tries all 120 orders against `task` (skipping the gatekeeper with gdb). It runs in a couple of seconds:
```
$ python3 solve.py ./task
```
The key is not stored in `task`: only an FNV-1a hash of the 40 key bytes is, so it cannot be read from `task` in Ghidra. A wrong order or wrong length prints "... the anvil rings false. Wrong key.".

### Stage 2: get past the gatekeeper in task

Open `task` in Ghidra: `main` calls `gatekeeper()` before anything else, and `gatekeeper` exits unless a variable is set (it never is). Any of these works:

```
# 1. return from the function immediately
pwndbg> break gatekeeper
pwndbg> run
pwndbg> return

# 2. jump over the call (address from objdump / Ghidra)
pwndbg> break *0x400601
pwndbg> run
pwndbg> jump *0x400606

# 3. set the variable it checks
pwndbg> break gatekeeper
pwndbg> run
pwndbg> set var *(int*)0x40306c = 1
pwndbg> continue
```
(In `task`: `gatekeeper` = 0x4004d6, `main` = 0x4005f6, `print_blob` = 0x40055a, `access_granted` = 0x40306c, `blob_data` = 0x4013a0; the call to `gatekeeper` is at 0x400601. Addresses are for the shipped build. They stay the same on every run because it is built with `-no-pie`. If you rebuild, check them again with `objdump -d -M intel task`.)

Then type the 80-digit key at the prompt.

### Stage 3: decode the blob

Blob: `NDY3MjcwNjg2NTc2NjE3MjY3NjY1MjQxNTY0NzdiNjc3NTMzNWY3YTM0NzE1ZjY2N2EzMTY3NzU1Zjc1MzA3OTcxNjY1ZjY1NmU2YjVmMzE2MTVmNzA3NTM0MzA2Njdk`

| Level | Looks like | Decode with | Result |
|---|---|---|---|
| 1 | Letters and digits (Base64, may end in `=`) | From Base64 | `467270686576616...` (hex digits as text) |
| 2 | Only 0-9 and a-f | From Hex | `FrphevargfRAVG{gu3_z4q_fz1gu_u0yqf_enk_1a_pu40f}` |
| 3 | Looks like a flag, letters shifted | ROT13 | `SecurinetsENIT{th3_m4d_sm1th_h0lds_rax_1n_ch40s}` |

In CyberChef: build the recipe From Base64, From Hex, ROT13, or just click the Magic wand.

## Why this works as a V1

- Every stage uses a tool from the toolkit: `file`, `strings`, Ghidra, gdb, Python and CyberChef.
- The blob is stored XOR-masked with the 40-byte key, so patching out the key check does not give the flag. A wrong key prints garbage.
- Only a hash of the key is in `task`, so players must really build the pieces and find the order.
- No anti-debugging and no packing, on purpose.

## Hint ladder (give one at a time if players are stuck)

1. "The keygen does print the pieces of the key, just not on the screen."
2. "Registers hold the result of a function when it returns."
3. "`finish` in gdb runs until the current function returns."
4. "The task refuses to start. What does `main` do first?"
5. "You do not have to obey a function. You can skip it."
6. "Each decoding level gives something. Does it look familiar?"
7. "Five pieces can be joined in more than one order. Look at what `main` does after the five calls."
8. "The key has 80 hex digits, 16 per piece."

## Building and shipping

```
python3 build.py                      # builds keygen and task
FLAG='SecurinetsENIT{your_flag}' python3 build.py
# the arrangement is ORDER at the top of build.py (default [3, 5, 1, 4, 2])
```
- The binaries need **glibc 2.34 or newer** (built with `-std=gnu11` so they do not pull in glibc 2.38 symbols) (Ubuntu 22.04 and later, Kali, recent Debian). On older systems they will not start. If players use older systems, build on the oldest system they use.
- Give players only the files in `ctf_v1_player.zip`. Keep the `.c` files, `generated.h` and this file private.
- Remember that changing the flag changes the blob, so give players the newly built binaries.

