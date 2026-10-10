/*
 * task.c  -  CTF V1 (beginner reverse engineering)
 *
 * 1. gatekeeper() stops the program before the prompt ever appears.
 * 2. After getting past it, the player enters the key: 80 hex digits
 *    (five 16-digit pieces joined in the right order).
 * 3. A correct key unmasks and prints an encoded blob (3 levels).
 *
 * Only a slow, stretched hash of the key is stored, so the key cannot be read out of this
 * program. The blob is stored XOR-masked with the key, so patching out the
 * key check does not help: a wrong key would only print garbage.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "generated.h"

/* Nobody ever sets this, so the gatekeeper always blocks. */
static volatile int access_granted = 0;

__attribute__((noinline)) void gatekeeper(void)
{
    if (access_granted == 0) {
        puts("The Great Gate is sealed by the Mad Smith. You shall not pass.");
        exit(1);
    }
}

static uint64_t fnv1a(const unsigned char *p, size_t n)
{
    uint64_t h = 0xCBF29CE484222325ULL;

    while (n--) {
        h ^= *p++;
        h *= 0x100000001B3ULL;
    }
    return h;
}

/* a small 64-bit hash, used to make one mask per key slot */
static uint64_t smix(uint64_t z)
{
    z += 0x9E3779B97F4A7C15ULL;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

/* mixes the typed piece with the mask (a + b - 2*(a & b) is the same as a ^ b) */
static uint64_t seal(uint64_t p, uint64_t m)
{
    return p + m - 2 * (p & m);
}

/* slow on purpose: every wrong guess costs about a second */
static uint64_t stretch(uint64_t h)
{
    uint64_t r;

    for (r = 0; r < STRETCH_ROUNDS; r++) {
        h ^= h >> 29;
        h *= 0xBF58476D1CE4E5B9ULL;
        h ^= h >> 32;
    }
    return h;
}

__attribute__((noinline)) void print_blob(const unsigned char *kb)
{
    char out[BLOB_LEN + 1];
    int i;

    for (i = 0; i < BLOB_LEN; i++)
        out[i] = (char)(blob_data[i] ^ kb[i % KEY_BYTES]);
    out[BLOB_LEN] = '\0';

    puts("The Great Gate groans open! The Mad Smith hands you the secret of Chaos :");
    puts(out);
}

int main(void)
{
    char line[256];
    char chunk[17];
    unsigned char kb[KEY_BYTES];
    uint64_t piece;
    int i;

    gatekeeper();

    printf("Enter the key: ");
    fflush(stdout);
    if (fgets(line, sizeof line, stdin) == NULL)
        return 1;
    line[strcspn(line, "\r\n")] = '\0';

    if (strlen(line) != 2 * KEY_BYTES) {
        puts("The Mad Smith cackles: the anvil rings false. Wrong key.");
        return 1;
    }
    for (i = 0; i < KEY_BYTES / 8; i++) {
        memcpy(chunk, line + 16 * i, 16);
        chunk[16] = '\0';
        piece = seal(strtoull(chunk, NULL, 16), smix(KEY_SEED + i));
        memcpy(kb + 8 * i, &piece, 8);
    }

    if (stretch(fnv1a(kb, KEY_BYTES)) != KEY_HASH) {
        puts("The Mad Smith cackles: the anvil rings false. Wrong key.");
        return 1;
    }

    print_blob(kb);
    return 0;
}
