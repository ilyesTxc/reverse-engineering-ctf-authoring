# The Mad Smith's Forge - Solution (organizer only)

**Category:** Reverse Engineering | **Difficulty:** beginner to intermediate (1-2 hours)
**Flag:** `SecurinetsENIT{th3_m4d_sm1th_h0lds_rax_1n_ch40s}`

Players get `keygen` (the Forge) and `task` (the Great Gate), both stripped, plus `CHALLENGE.txt`.

## Answer sheet (quick reference)

| What | Value |
|---|---|
| Right key (80 hex digits) | `5c3a9c69450f52087363a143043dcb7110057aa5fc0ad9476da28b7222dc1a46d7c00818e6c5b717` |
| Order of the pieces | dungeon 3, 5, 1, 4, 2 |
| Blob that `task` prints | `NDY3MjcwNjg2NTc2NjE3MjY3NjY1MjQxNTY0NzdiNjc3NTMzNWY3YTM0NzE1ZjY2N2EzMTY3NzU1Zjc1MzA3OTcxNjY1ZjY1NmU2YjVmMzE2MTVmNzA3NTM0MzA2Njdk` |
| Decode the blob | From Base64 -> From Hex -> ROT13 |
| Fast check | `python3 solve.py` (finds the key in about 6 seconds) |

## The idea in five lines

1. `keygen` computes **5 pieces** (one per dungeon) and throws them away. They are never printed, but each is in `rax` when its function returns.
2. `task` refuses to start because of a **gatekeeper**. It must be skipped in a debugger.
3. After that, `task` asks for an **80-digit key**: five 16-digit chunks. It mixes each chunk with a **mask computed from its position**, then checks a slow hash of the result.
4. The right key is the 5 pieces in a **secret order**, each piece XORed with the mask of the slot it sits in. The order is not written in either program. Players must **script all 120 orders (5!)** and try them, at about 1.3 seconds per wrong guess.
5. The right key makes `task` print a blob. Decoding it gives the flag.

What a player needs: the pieces (from `keygen`), the mask rule (from `task`), a way past the gatekeeper (gdb), and a script.

## Step by step

### Step 1 - First look
```
file keygen task      # stripped 64-bit ELF
strings keygen task   # only the Mad Smith messages
./task                # "The Great Gate is sealed ... You shall not pass."
```
Both programs are stripped, so Ghidra shows `FUN_xxxxxxxx` names and gdb needs addresses (`break *0x...`).

### Step 2 - Get the 5 pieces from keygen
In Ghidra, `main` of `keygen` (`FUN_004005dc`) calls five functions, one per dungeon, and does nothing else with the results. Each function builds 8 bytes from its own table with a simple transform. Those 8 bytes (read as a number) are the piece.

Read each piece in gdb:
```
gdb ./keygen
break *0x400466      # dungeon 1; repeat for the other addresses in the table
run
finish               # run until the function returns
info registers rax   # this is the piece
continue
```

| Dungeon | Address | What it does to its 8-byte table (i = 0..7) | Piece (rax) |
|---|---|---|---|
| 1 | 0x400466 | `t[i] + 0x35 + i` | `0e1c2a4856647280` |
| 2 | 0x4004a8 | `t[i] + 0x5A` | `55c77d02b81e61eb` |
| 3 | 0x4004e5 | swap the two nibbles | `ce537b069d24a8f1` |
| 4 | 0x400537 | `t[i] ^ (0xA7 + i)` | `ca863468dba7fd0d` |
| 5 | 0x40057d | `(t[i] + 0x3D) ^ t[i-1]` (`t[-1]` = 0) | `ef155433f4b463b9` |

All math is per byte, mod 256. Players can also recompute the pieces in Python from the tables (see `solve.py`).

### Step 3 - Get past the gatekeeper in task
`main` of `task` (`FUN_004006d5`) calls `gatekeeper` (`FUN_004004d6`) first. It exits unless a variable is set, and nothing ever sets it. Any one of these works in gdb:

```
# a) return from it at once
break *0x4004d6
run
return

# b) jump over the call
break *0x4006e1
run
jump *0x4006e6

# c) set the variable it checks
break *0x4004d6
run
set var *(int*)0x40306c = 1
continue
```
After this, `task` shows the prompt `Enter the key:`.

### Step 4 - Find the mask rule in task
Still in `main` of `task`: the typed key is read as five 16-digit chunks. For chunk number `i` (0 to 4) the program does:
- `mask = smix(0x5eed1e55c0deba5e + i)`, where `smix` is a small hash (add, multiply, shift),
- `chunk = chunk + mask - 2*(chunk & mask)`, which is the same as `chunk ^ mask`, written so that it does not look like an XOR.

Then it joins the five results, hashes them slowly and compares with a stored hash. The key itself is not stored in `task`, so it cannot be read there.

So the value to type for a slot is `piece ^ mask(slot)`:

| Slot | Mask | Piece in this slot (right order) | Typed value |
|---|---|---|---|
| 1 | `9269e76fd82bfaf9` | dungeon 3 `ce537b069d24a8f1` | `5c3a9c69450f5208` |
| 2 | `9c76f570f089a8c8` | dungeon 5 `ef155433f4b463b9` | `7363a143043dcb71` |
| 3 | `1e1950edaa6eabc7` | dungeon 1 `0e1c2a4856647280` | `10057aa5fc0ad947` |
| 4 | `a724bf1af97be74b` | dungeon 4 `ca863468dba7fd0d` | `6da28b7222dc1a46` |
| 5 | `8207751a5edbd6fc` | dungeon 2 `55c77d02b81e61eb` | `d7c00818e6c5b717` |

Joined, that is the key from the answer sheet. In any other order the typed values are different, and `task` answers "Wrong key.".

### Step 5 - Try all 120 orders with a script
Nothing in the programs shows the order, so players must try them all:

1. For each of the 120 orders (`itertools.permutations` of the five pieces), build a candidate key. Piece number `p` placed in slot `i` is typed as `piece[p] ^ mask(i)`.
2. Run `task` with the gatekeeper skipped (Step 3) and give it the candidate.
3. A wrong candidate prints "... Wrong key." after about 1.3 seconds. The right one prints the blob.

That takes about 2.5 minutes one after another, or a few seconds with several processes in parallel. Skipping the masks (typing the raw pieces) makes all 120 guesses fail.

`solve.py` is exactly this script. It works out the pieces and the masks (the seed comes from `generated.h`), tries the 120 orders in parallel through gdb, and prints the order, the key and the blob. It needs `addresses.json`, which `build.py` writes, because the programs are stripped.
```
python3 solve.py
```

### Step 6 - Decode the blob
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
7. "The key has 80 hex digits, 16 per piece. There are exactly five pieces."
8. "The pieces from keygen are not typed as they are. Look at what `task` does to each chunk you type."
9. "Nothing tells you the order of the pieces. Write a small script and try them all."
10. "5! is only 120 tries. A wrong guess costs about a second, so run the tries in parallel."

## Building and shipping

```
python3 build.py
FLAG='SecurinetsENIT{your_flag}' python3 build.py     # different flag
```
- **Settings at the top of `build.py`:** `ORDER` (the secret order, stored nowhere in the shipped programs), `MASK_SEED` (the seed for the slot masks, used by `task`) and `STRETCH_ROUNDS` (how slow a wrong guess is).
- After any rebuild, check the addresses again. They are in `addresses.json`, or use `objdump -d -M intel task.unstripped`.
- `build.py` also writes `keygen.unstripped` and `task.unstripped` (with symbols) for you. Do not give those to players.
- **Give players only** `ctf_v1_player/` (`keygen`, `task`, `CHALLENGE.txt`). **Keep private:** this file, the `.c` files, `generated.h`, `solve.py`, `addresses.json` and the `*.unstripped` files.
- The binaries need glibc 2.34 or newer (Ubuntu 22.04+, recent Debian or Kali).
- The blob is XOR-masked with the key, so patching out the key check does not give the flag.
- There is no anti-debugging and no packing, on purpose.
