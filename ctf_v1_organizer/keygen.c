/*
 * keygen.c  -  CTF V1 (beginner reverse engineering)
 *
 * Five independent dungeons each build one 64-bit piece of the key.
 * main() joins the five pieces in a fixed order (KEY_ORDER, from generated.h)
 * to make a 40-byte key. The key and the pieces are NEVER printed.
 * Each dungeon returns its piece in rax.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "generated.h"

static const unsigned char table1[8] = { 0x4B, 0x3C, 0x2D, 0x1E, 0x0F, 0xF0, 0xE1, 0xD2 };
static const unsigned char table2[8] = { 0x91, 0x07, 0xC4, 0x5E, 0xA8, 0x23, 0x6D, 0xFB };
static const unsigned char table3[8] = { 0x1F, 0x8A, 0x42, 0xD9, 0x60, 0xB7, 0x35, 0xEC };
static const unsigned char table4[8] = { 0xAA, 0x55, 0x0E, 0x71, 0xC3, 0x98, 0x2B, 0x64 };
static const unsigned char table5[8] = { 0x7C, 0xE2, 0x19, 0xB0, 0x46, 0xD5, 0x83, 0x2F };

#define SHIFT 0x35
#define K1    0x5A
#define K2    0xA7
#define K3    0x3D

/* dungeon1: position-dependent Caesar */
__attribute__((noinline)) uint64_t dungeon1(void)
{
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)(table1[i] + SHIFT + i);
    memcpy(&x, b, sizeof x);
    return x;
}

/* dungeon2: static Caesar */
__attribute__((noinline)) uint64_t dungeon2(void)
{
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)(table2[i] + K1);
    memcpy(&x, b, sizeof x);
    return x;
}

/* dungeon3: nibble swap */
__attribute__((noinline)) uint64_t dungeon3(void)
{
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)(((table3[i] << 4) & 0xF0) | ((table3[i] >> 4) & 0x0F));
    memcpy(&x, b, sizeof x);
    return x;
}

/* dungeon4: index-dependent XOR */
__attribute__((noinline)) uint64_t dungeon4(void)
{
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)(table4[i] ^ (K2 + i));
    memcpy(&x, b, sizeof x);
    return x;
}

/* dungeon5: constant shift, then XOR with the previous byte's table value */
__attribute__((noinline)) uint64_t dungeon5(void)
{
    unsigned char b[8];
    uint64_t x;
    int i;

    for (i = 0; i < 8; i++)
        b[i] = (unsigned char)((table5[i] + K3) ^ (i ? table5[i - 1] : 0));
    memcpy(&x, b, sizeof x);
    return x;
}

/* a small 64-bit hash, used to make one mask per key slot */
__attribute__((noinline)) static uint64_t smix(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* mixes the piece with the mask (a + b - 2*(a & b) is the same as a ^ b) */
__attribute__((noinline)) static uint64_t seal(uint64_t p, uint64_t m)
{
    return p + m - 2 * (p & m);
}

int main(void)
{
    static const int order[5] = KEY_ORDER;
    uint64_t piece[5];
    volatile uint64_t key[5];
    int i;

    piece[0] = dungeon1();
    piece[1] = dungeon2();
    piece[2] = dungeon3();
    piece[3] = dungeon4();
    piece[4] = dungeon5();

    for (i = 0; i < 5; i++)
        key[i] = seal(piece[order[i]], smix(KEY_SEED + i));
    (void)key;

    puts("The Mad Smith hammered five pieces of the key, then hurled them into the chaos. Seek them out!");
    return 0;
}
