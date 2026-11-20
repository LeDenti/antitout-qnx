/* bn_soi — learn the self: print "<sha3-256> <path>" for each binary given. */
#include <stdio.h>
#include "bn_journal.h"
#include "../qnx/soi.h"

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <binary>... > soi.conf\n", argv[0]); return 2; }
    int rc = 0;
    for (int i = 1; i < argc; i++) {
        uint8_t h[BN_HASH_LEN]; char hx[2 * BN_HASH_LEN + 1];
        if (soi_hash_file(argv[i], h) != 0) { fprintf(stderr, "cannot read %s\n", argv[i]); rc = 1; continue; }
        bn_hex(hx, h, BN_HASH_LEN);
        printf("%s %s\n", hx, argv[i]);
    }
    return rc;
}
