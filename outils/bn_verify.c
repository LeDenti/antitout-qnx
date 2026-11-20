/* bn_verify — check a black-box journal: hash chain, ML-DSA seals, SLH-DSA roots.
 * Runs on the QNX target and on the host (macOS / Linux / Windows-WSL). Exit 0 = intact. */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "bn_journal.h"

int main(int argc, char **argv) {
    if (argc != 3) { fprintf(stderr, "usage: %s <journal> <public-key-dir>\n", argv[0]); return 2; }
    bn_keys k;
    if (bn_keys_load(&k, argv[2], 0)) { fprintf(stderr, "cannot load public keys from %s\n", argv[2]); return 2; }
    bn_report r;
    bn_verify_file(argv[1], &k, &r);
    char hx[2 * BN_HASH_LEN + 1];
    bn_hex(hx, r.head, BN_HASH_LEN);
    printf("events          %llu\n", (unsigned long long)r.events);
    printf("ML-DSA seals    %llu", (unsigned long long)r.seals);
    if (r.last_sealed_seq != UINT64_MAX) printf("  (last covers seq %llu)", (unsigned long long)r.last_sealed_seq);
    printf("\nSLH-DSA roots   %llu", (unsigned long long)r.roots);
    if (r.last_rooted_seq != UINT64_MAX) printf("  (last covers seq %llu)", (unsigned long long)r.last_rooted_seq);
    printf("\nunsealed tail   %llu events\n", (unsigned long long)r.unsealed_tail);
    printf("head            %s\n", hx);
    if (r.ok) { printf("VERDICT         INTACT\n"); bn_keys_free(&k); return 0; }
    printf("VERDICT         TAMPERED: %s at byte %ld", r.reason, r.first_bad_offset);
    if (r.first_bad_seq != UINT64_MAX) printf(", event seq %llu", (unsigned long long)r.first_bad_seq);
    printf("\n");
    bn_keys_free(&k);
    return 1;
}
