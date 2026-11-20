/* bn_keys — provision a device: generate ML-DSA-65 + SLH-DSA-SHA2-128s key pairs. */
#include <stdio.h>
#include <sys/stat.h>
#include "bn_journal.h"

int main(int argc, char **argv) {
    if (argc != 2) { fprintf(stderr, "usage: %s <key-dir>\n", argv[0]); return 2; }
    mkdir(argv[1], 0700);
    bn_keys k;
    if (bn_keys_generate(&k) || bn_keys_save(&k, argv[1])) { perror("bn_keys"); return 1; }
    uint8_t fp[BN_HASH_LEN]; char hx[2 * BN_HASH_LEN + 1];
    bn_sha3_256(fp, k.mldsa_pk, k.mldsa_pk_len); bn_hex(hx, fp, BN_HASH_LEN);
    printf("ML-DSA-65 public key fingerprint   %s\n", hx);
    bn_sha3_256(fp, k.slh_pk, k.slh_pk_len); bn_hex(hx, fp, BN_HASH_LEN);
    printf("SLH-DSA-128s public key fingerprint %s\n", hx);
    bn_keys_free(&k);
    return 0;
}
