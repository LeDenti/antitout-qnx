/* bn_list — print a black-box journal as readable lines (no verification: run bn_verify for that).
 * usage: bn_list <journal> [last-n]
 * Payload layouts mirror qnx/bn_qnx.h (little-endian, packed into the 40-byte event payload). */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bn_journal.h"

static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t g32(const uint8_t *p) { return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }
static uint64_t g64(const uint8_t *p) { return (uint64_t)g32(p) | (uint64_t)g32(p + 4) << 32; }

static void payload(char *out, size_t n, uint16_t type, const uint8_t *p) {
    char s[17];
    switch (type) {
    case BN_T_JITTER_REPORT: snprintf(out, n, "worst late %u us over %u ticks", g32(p), g32(p + 4)); return;
    case BN_T_DEADLINE_MISSED: snprintf(out, n, "no heartbeat for %u ms", g32(p)); return;
    case BN_T_RING_DROP: snprintf(out, n, "%u events lost", g32(p)); return;
    case BN_T_BOOT: snprintf(out, n, "black box up, %u binaries in the self", g32(p)); return;
    }
    switch (type >> 8) {
    case 0x01:                                       /* bn_dose_payload */
        memcpy(s, p, 16); s[16] = 0;
        snprintf(out, n, "%s target %.2f mg delivered %.2f mg deviation %+.2f %% jitter %u us pid %u",
                 s, g32(p + 16) / 100.0, g32(p + 20) / 100.0, (int32_t)g32(p + 24) / 1e4,
                 g32(p + 28), g32(p + 32));
        return;
    case 0x02:
        if (type == BN_T_SELF_OK) {
            snprintf(out, n, "self %u declared, %u tolerated at start, memory %u", g32(p), g32(p + 8), g32(p + 4));
            return;
        }
        memcpy(s, p + 24, 16); s[16] = 0;            /* bn_immune_payload */
        snprintf(out, n, "%s pid %u tid %u priority %u -> %u exe %02x%02x%02x%02x...",
                 s[0] ? s : "?", g32(p), g32(p + 4), g32(p + 8), g32(p + 12), p[16], p[17], p[18], p[19]);
        return;
    default:
        snprintf(out, n, "%u %u", g32(p), g32(p + 4));
    }
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <journal> [last-n]\n", argv[0]); return 2; }
    long last = argc > 2 ? atol(argv[2]) : 0;
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror(argv[1]); return 2; }
    char (*lines)[256] = calloc(last > 0 ? (size_t)last : 1, 256);
    long count = 0;
    uint8_t h[12];
    while (fread(h, 1, 12, f) == 12) {
        uint16_t kind = g16(h + 4);
        uint32_t len = g32(h + 8);
        uint8_t *b = malloc(len ? len : 1);
        if (!b || fread(b, 1, len, f) != len) { free(b); break; }
        char line[256], pl[200] = "";
        if (kind == BN_K_EVENT && len >= 24 + BN_PAYLOAD_LEN) {
            uint16_t type = g16(b + 20);
            payload(pl, sizeof pl, type, b + 24);
            snprintf(line, sizeof line, "#%-6llu %-16s %s", (unsigned long long)g64(b), bn_type_name(type), pl);
        } else if (kind == BN_K_SEAL || kind == BN_K_ROOT) {
            snprintf(line, sizeof line, "        %s covers seq %llu", kind == BN_K_SEAL ? "ML-DSA-65 SEAL " : "SLH-DSA ROOT   ",
                     (unsigned long long)g64(b));
        } else if (kind == BN_K_GENESIS) {
            snprintf(line, sizeof line, "        GENESIS");
        } else {
            snprintf(line, sizeof line, "        frame kind %u, %u bytes", kind, len);
        }
        free(b);
        if (last > 0) snprintf(lines[count % last], 256, "%s", line);
        else puts(line);
        count++;
    }
    if (last > 0)
        for (long i = count > last ? count - last : 0; i < count; i++) puts(lines[i % last]);
    free(lines);
    fclose(f);
    return 0;
}
