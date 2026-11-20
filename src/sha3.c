/* sha3.c — compact SHA3-256 (FIPS 202), Keccak-f[1600]. Checked against NIST vectors in tests/. */
#include <stdint.h>
#include <string.h>
#include "bn_journal.h"

static const uint64_t RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
    0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
    0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
    0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
    0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL };
static const unsigned ROT[25] = { 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39,
                                  41, 45, 15, 21, 8, 18, 2, 61, 56, 14 };

static uint64_t rol(uint64_t x, unsigned n) { return n ? (x << n) | (x >> (64 - n)) : x; }

static void keccakf(uint64_t s[25]) {
    for (int r = 0; r < 24; r++) {
        uint64_t c[5], d, b[25];
        for (int x = 0; x < 5; x++) c[x] = s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20];
        for (int x = 0; x < 5; x++) {
            d = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
            for (int y = 0; y < 25; y += 5) s[y + x] ^= d;
        }
        for (int x = 0; x < 5; x++)
            for (int y = 0; y < 5; y++)
                b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(s[x + 5 * y], ROT[x + 5 * y]);
        for (int y = 0; y < 25; y += 5)
            for (int x = 0; x < 5; x++)
                s[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
        s[0] ^= RC[r];
    }
}

void bn_sha3_256(uint8_t out[BN_HASH_LEN], const void *in, size_t len) {
    enum { RATE = 136 };
    uint64_t s[25] = {0};
    const uint8_t *p = in;
    uint8_t blk[RATE];
    while (len >= RATE) {
        for (int i = 0; i < RATE / 8; i++) {
            uint64_t w = 0;
            for (int k = 7; k >= 0; k--) w = (w << 8) | p[8 * i + k];
            s[i] ^= w;
        }
        keccakf(s);
        p += RATE; len -= RATE;
    }
    memset(blk, 0, RATE);
    memcpy(blk, p, len);
    blk[len] ^= 0x06;
    blk[RATE - 1] ^= 0x80;
    for (int i = 0; i < RATE / 8; i++) {
        uint64_t w = 0;
        for (int k = 7; k >= 0; k--) w = (w << 8) | blk[8 * i + k];
        s[i] ^= w;
    }
    keccakf(s);
    for (int i = 0; i < BN_HASH_LEN; i++) out[i] = (uint8_t)(s[i / 8] >> (8 * (i % 8)));
}
