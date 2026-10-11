/*
 * keygen.c  -  CTF V2 (the deeper trial)
 *
 * Eight real dungeons build eight 64-bit pieces of the key. Each dungeon eats the
 * piece of the one before it (dungeon1 eats a fixed constant), so the pieces come out
 * one after another. Fifteen decoy dungeons (keygen_decoys.h, written by build.py)
 * look the same, are called from main too, and are never used for the key.
 * Nothing is printed. The pieces are thrown away. Each dungeon returns in rax.
 * The right key is the eight pieces joined in a secret order that only task knows.
 *
 * Anti-debug: ptrace(PTRACE_TRACEME) fails when a debugger is already attached.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ptrace.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (64 - (n))))
#define BYTE(p, i) ((unsigned char)((p) >> (8 * ((i) & 7))))

#define SEED0 0x4D41445F534D4954ULL

#define DECOY_PART 0
#include "keygen_decoys.h"
#undef DECOY_PART

/* dungeon1: each table byte XOR a byte of the previous piece, then a position-dependent shift */
__attribute__((noinline)) uint64_t piece1(uint64_t p)
{
    unsigned char t[8] = { 0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0xF0, 0xE1, 0xD2 };
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)((t[i] ^ BYTE(p, i)) + 0x35 + i);
    memcpy(&x, b, sizeof x);
    return x;
}

/* dungeon2: table XOR rotated previous piece, odd multiply, xorshift */
__attribute__((noinline)) uint64_t piece2(uint64_t p)
{
    unsigned char t[8] = { 0x91, 0x07, 0xC4, 0x5E, 0xA8, 0x23, 0x6D, 0xFB };
    uint64_t x;

    memcpy(&x, t, sizeof x);
    x ^= ROTL(p, 17);
    x *= 0xD6E8FEB86659FD93ULL;
    x ^= x >> 29;
    return x;
}

#define DECOY_PART 1
#include "keygen_decoys.h"
#undef DECOY_PART

/* dungeon3: nibble swap, XOR with the previous piece's bytes read from byte 3 on */
__attribute__((noinline)) uint64_t piece3(uint64_t p)
{
    unsigned char t[8] = { 0x1F, 0x8A, 0x42, 0xD9, 0x60, 0xB7, 0x35, 0xEC };
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)((((t[i] << 4) & 0xF0) | ((t[i] >> 4) & 0x0F)) ^ BYTE(p, i + 3));
    memcpy(&x, b, sizeof x);
    return x;
}

/* dungeon4: add the previous piece, rotate, XOR with a shifted copy of it */
__attribute__((noinline)) uint64_t piece4(uint64_t p)
{
    unsigned char t[8] = { 0xAA, 0x55, 0x0E, 0x71, 0xC3, 0x98, 0x2B, 0x64 };
    uint64_t x;

    memcpy(&x, t, sizeof x);
    x += p;
    x = ROTL(x, 23) ^ (p >> 7);
    return x;
}

#define DECOY_PART 2
#include "keygen_decoys.h"
#undef DECOY_PART

/* dungeon5: add, then chain each byte to the one before it (byte 0 chains to the previous piece) */
__attribute__((noinline)) uint64_t piece5(uint64_t p)
{
    unsigned char t[8] = { 0x7C, 0xE2, 0x19, 0xB0, 0x46, 0xD5, 0x83, 0x2F };
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)((t[i] + 0x3D) ^ (i ? b[i - 1] : BYTE(p, 0)));
    memcpy(&x, b, sizeof x);
    return x ^ ROTL(p, 5);
}

/* dungeon6: subtract three times the previous piece, then two xorshifts */
__attribute__((noinline)) uint64_t piece6(uint64_t p)
{
    unsigned char t[8] = { 0x2E, 0xB4, 0x63, 0xD8, 0x07, 0x9A, 0xF1, 0x4C };
    uint64_t x;

    memcpy(&x, t, sizeof x);
    x -= p * 3;
    x ^= x << 11;
    x ^= x >> 7;
    return x;
}

#define DECOY_PART 3
#include "keygen_decoys.h"
#undef DECOY_PART

/* dungeon7: XOR with the sum of two neighbouring bytes of the previous piece, then rotate */
__attribute__((noinline)) uint64_t piece7(uint64_t p)
{
    unsigned char t[8] = { 0xD3, 0x18, 0xA5, 0x6E, 0xC9, 0x02, 0x7B, 0xF6 };
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)(t[i] ^ (unsigned char)(BYTE(p, i) + BYTE(p, i + 1)));
    memcpy(&x, b, sizeof x);
    return ROTL(x, 9);
}

/* dungeon8: multiply the table, add a rotated copy of the previous piece, fold the top half down */
__attribute__((noinline)) uint64_t piece8(uint64_t p)
{
    unsigned char t[8] = { 0x58, 0xC1, 0x94, 0x2D, 0xE7, 0x3A, 0x80, 0x6F };
    uint64_t x;

    memcpy(&x, t, sizeof x);
    x = x * 0x9FB21C651E98DF25ULL + ROTL(p, 31);
    x ^= x >> 32;
    return x;
}

int main(void)
{
    volatile uint64_t piece[8];
    volatile uint64_t junk[DECOY_COUNT];

    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
        puts("The Mad Smith's bellows go still. Someone is watching the forge. Begone, spy!");
        return 1;
    }

    DECOY_AFTER_0
    piece[0] = piece1(SEED0);
    DECOY_AFTER_1
    piece[1] = piece2(piece[0]);
    DECOY_AFTER_2
    piece[2] = piece3(piece[1]);
    DECOY_AFTER_3
    piece[3] = piece4(piece[2]);
    DECOY_AFTER_4
    piece[4] = piece5(piece[3]);
    DECOY_AFTER_5
    piece[5] = piece6(piece[4]);
    DECOY_AFTER_6
    piece[6] = piece7(piece[5]);
    DECOY_AFTER_7
    piece[7] = piece8(piece[6]);
    DECOY_AFTER_8
    (void)piece;
    (void)junk;

    puts("The Mad Smith hammered the pieces of the key, hid them among false ones, and flung the lot into the chaos. Seek the true ones out!");
    return 0;
}
