/* test_journal — NIST SHA3 vectors, chain, resume, and tamper attacks. */
#define _POSIX_C_SOURCE 200809L
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "bn_journal.h"

static int fails = 0, passes = 0;
#define CHECK(c, msg) do { if (c) { passes++; } else { fails++; printf("FAIL  %s (line %d)\n", msg, __LINE__); } } while (0)

static const char *J = "/tmp/bn_test.journal";

static void sha3_vectors(void) {
    uint8_t d[32]; char hx[65];
    bn_sha3_256(d, "", 0); bn_hex(hx, d, 32);
    CHECK(!strcmp(hx, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"), "SHA3-256 empty");
    bn_sha3_256(d, "abc", 3); bn_hex(hx, d, 32);
    CHECK(!strcmp(hx, "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"), "SHA3-256 abc");
    uint8_t m[200]; memset(m, 0xa3, sizeof m);
    bn_sha3_256(d, m, sizeof m); bn_hex(hx, d, 32);
    CHECK(!strcmp(hx, "79f38adec5c20307a98ef76e8324afbfd46cfd81b22e3973c65fa1bd9de31787"), "SHA3-256 200 x 0xa3");
}

static void write_journal(const bn_keys *k, int n, double *seal_ms, double *root_ms) {
    unlink(J);
    bn_journal j;
    CHECK(bn_open(&j, J, k, "test-device") == 0, "open new journal");
    double s_total = 0; int s_count = 0;
    for (int i = 0; i < n; i++) {
        uint32_t dose = 1000 + (uint32_t)i;
        CHECK(bn_append(&j, bn_now_mono_ns(), 42, BN_T_DOSE_DELIVERED, 0, &dose, sizeof dose, NULL) == 0, "append");
        if ((i + 1) % 256 == 0) {
            uint64_t t0 = bn_now_mono_ns();
            CHECK(bn_seal(&j, bn_now_real_ns()) == 0, "seal");
            s_total += (bn_now_mono_ns() - t0) / 1e6; s_count++;
        }
    }
    uint64_t t0 = bn_now_mono_ns();
    CHECK(bn_root(&j, bn_now_real_ns()) == 0, "root");
    *root_ms = (bn_now_mono_ns() - t0) / 1e6;
    *seal_ms = s_count ? s_total / s_count : 0;
    bn_close(&j);
}

static long frame_offset_of_event(uint64_t seq) {
    /* walk frames to find the byte offset of event `seq` */
    int fd = open(J, O_RDONLY); long off = 0; uint8_t h[12];
    while (read(fd, h, 12) == 12) {
        uint32_t len = h[8] | h[9] << 8 | h[10] << 16 | (uint32_t)h[11] << 24;
        uint16_t kind = h[4] | h[5] << 8;
        if (kind == BN_K_EVENT) {
            uint8_t s[8]; read(fd, s, 8); lseek(fd, -8, SEEK_CUR);
            uint64_t v = 0; for (int i = 7; i >= 0; i--) v = v << 8 | s[i];
            if (v == seq) { close(fd); return off; }
        }
        lseek(fd, len, SEEK_CUR); off += 12 + len;
    }
    close(fd); return -1;
}

static void flip_byte(long at) {
    int fd = open(J, O_RDWR); uint8_t b;
    pread(fd, &b, 1, at); b ^= 0x01; pwrite(fd, &b, 1, at); close(fd);
}

static void copy_file(const char *from, const char *to) {
    char cmd[512]; snprintf(cmd, sizeof cmd, "cp '%s' '%s'", from, to); system(cmd);
}

int main(void) {
    sha3_vectors();

    bn_keys k, other;
    CHECK(bn_keys_generate(&k) == 0, "keygen");
    CHECK(bn_keys_generate(&other) == 0, "keygen other");

    double seal_ms, root_ms;
    write_journal(&k, 1000, &seal_ms, &root_ms);
    bn_report r;
    bn_verify_file(J, &k, &r);
    CHECK(r.ok, "clean journal verifies");
    CHECK(r.events == 1000, "1000 events");
    CHECK(r.seals == 3 && r.last_sealed_seq == 767, "3 seals, last covers 767");
    CHECK(r.roots == 1 && r.last_rooted_seq == 999, "root covers 999");
    CHECK(r.unsealed_tail == 232, "unsealed tail 232");
    copy_file(J, "/tmp/bn_test.clean");

    /* resume and continue the chain */
    bn_journal j;
    CHECK(bn_open(&j, J, &k, "ignored") == 0, "resume existing journal");
    CHECK(j.next_seq == 1000, "resume next_seq");
    for (int i = 0; i < 24; i++) bn_append(&j, bn_now_mono_ns(), 7, BN_T_SELF_OK, 0, NULL, 0, NULL);
    CHECK(bn_seal(&j, bn_now_real_ns()) == 0, "seal after resume");
    CHECK(bn_seal(&j, bn_now_real_ns()) == 0, "second seal is a no-op");
    bn_close(&j);
    bn_verify_file(J, &k, &r);
    CHECK(r.ok && r.events == 1024 && r.seals == 4 && r.unsealed_tail == 0, "resumed journal verifies");

    /* attack 1: flip one payload byte of event 500 */
    copy_file("/tmp/bn_test.clean", J);
    flip_byte(frame_offset_of_event(500) + 12 + 24);
    bn_verify_file(J, &k, &r);
    CHECK(!r.ok && r.first_bad_seq == 500 && strstr(r.reason, "altered"), "payload flip caught at seq 500");
    CHECK(bn_open(&j, J, &k, "x") != 0, "writer refuses to extend a tampered journal");

    /* attack 2: delete event 300 */
    copy_file("/tmp/bn_test.clean", J);
    {
        long a = frame_offset_of_event(300), b = frame_offset_of_event(301);
        char cmd[512];
        snprintf(cmd, sizeof cmd, "head -c %ld /tmp/bn_test.clean > %s && tail -c +%ld /tmp/bn_test.clean >> %s", a, J, b + 1, J);
        system(cmd);
    }
    bn_verify_file(J, &k, &r);
    CHECK(!r.ok && r.first_bad_seq == 300, "deleted event caught at seq 300");

    /* attack 3: forger rewrites event 100 and recomputes every later hash (no signing key) */
    {
        copy_file("/tmp/bn_test.clean", J);
        bn_journal f; memset(&f, 0, sizeof f);
        bn_report clean; bn_verify_file("/tmp/bn_test.clean", &k, &clean);
        /* rebuild events 0..999 with event 100 changed, copying the original seals verbatim */
        unlink("/tmp/bn_test.forged");
        bn_journal w;
        bn_open(&w, "/tmp/bn_test.forged", &k, "test-device");
        bn_close(&w);                                   /* genesis only */
        int in = open("/tmp/bn_test.clean", O_RDONLY), out = open("/tmp/bn_test.forged", O_WRONLY | O_APPEND);
        uint8_t h[12], *body = malloc(1 << 16), head[32];
        read(in, h, 12); { uint32_t len = h[8] | h[9] << 8 | h[10] << 16; read(in, body, len);
            uint8_t buf[9 + 256]; memcpy(buf, "BN-GEN-v1", 9); memcpy(buf + 9, body, len); bn_sha3_256(head, buf, 9 + len); }
        while (read(in, h, 12) == 12) {
            uint32_t len = h[8] | h[9] << 8 | h[10] << 16 | (uint32_t)h[11] << 24;
            uint16_t kind = h[4] | h[5] << 8;
            read(in, body, len);
            if (kind == BN_K_EVENT) {
                const size_t core = 64;
                uint64_t seq = 0; for (int i = 7; i >= 0; i--) seq = seq << 8 | body[i];
                if (seq == 100) body[24] ^= 0x40;       /* change the dose */
                memcpy(body + core, head, 32);
                uint8_t buf[9 + 32 + 128]; memcpy(buf, "BN-EVT-v1", 9); memcpy(buf + 9, head, 32); memcpy(buf + 41, body, core);
                bn_sha3_256(head, buf, 41 + core);
                memcpy(body + core + 32, head, 32);
            }
            write(out, h, 12); write(out, body, len);
        }
        close(in); close(out); free(body);
        bn_verify_file("/tmp/bn_test.forged", &k, &r);
        CHECK(!r.ok && strstr(r.reason, "cover"), "recomputed chain rejected by the first seal");
    }

    /* attack 4: corrupt one byte inside the first ML-DSA signature */
    copy_file("/tmp/bn_test.clean", J);
    flip_byte(frame_offset_of_event(256) - 100);
    bn_verify_file(J, &k, &r);
    CHECK(!r.ok && strstr(r.reason, "ML-DSA"), "corrupted seal caught");

    /* attack 5: verify with someone else's keys */
    copy_file("/tmp/bn_test.clean", J);
    bn_verify_file(J, &other, &r);
    CHECK(!r.ok && strstr(r.reason, "genesis"), "foreign keys rejected at genesis");

    /* crash: truncate in the middle of the last frame */
    {
        struct stat st; stat("/tmp/bn_test.clean", &st);
        copy_file("/tmp/bn_test.clean", J);
        truncate(J, st.st_size - 50);
        bn_verify_file(J, &k, &r);
        CHECK(!r.ok && strstr(r.reason, "torn"), "torn tail reported");
    }

    printf("ML-DSA-65 seal: %.2f ms on average, SLH-DSA-128s root: %.1f ms\n", seal_ms, root_ms);
    printf("%d passed, %d failed\n", passes, fails);
    bn_keys_free(&k); bn_keys_free(&other);
    unlink(J); unlink("/tmp/bn_test.clean"); unlink("/tmp/bn_test.forged");
    return fails ? 1 : 0;
}
