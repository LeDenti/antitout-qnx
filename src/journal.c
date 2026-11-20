/* journal.c — append-only, hash-chained, post-quantum sealed journal (portable POSIX + liboqs). */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <oqs/oqs.h>
#include "bn_journal.h"

#define BN_MAGIC 0x31464e42u   /* "BNF1" little-endian */
#define BN_MAX_BODY (1u << 16)

/* ---------- little helpers ---------- */
static void put16(uint8_t *p, uint16_t v) { p[0] = v; p[1] = v >> 8; }
static void put32(uint8_t *p, uint32_t v) { for (int i = 0; i < 4; i++) p[i] = v >> (8 * i); }
static void put64(uint8_t *p, uint64_t v) { for (int i = 0; i < 8; i++) p[i] = v >> (8 * i); }
static uint16_t get16(const uint8_t *p) { return (uint16_t)(p[0] | p[1] << 8); }
static uint32_t get32(const uint8_t *p) { uint32_t v = 0; for (int i = 3; i >= 0; i--) v = v << 8 | p[i]; return v; }
static uint64_t get64(const uint8_t *p) { uint64_t v = 0; for (int i = 7; i >= 0; i--) v = v << 8 | p[i]; return v; }

void bn_hex(char *out, const uint8_t *in, size_t len) {
    static const char h[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) { out[2 * i] = h[in[i] >> 4]; out[2 * i + 1] = h[in[i] & 15]; }
    out[2 * len] = 0;
}

uint64_t bn_now_real_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}
uint64_t bn_now_mono_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

const char *bn_type_name(uint16_t t) {
    switch (t) {
    case BN_T_BOOT: return "BOOT";                 case BN_T_RING_DROP: return "RING_DROP";
    case BN_T_DOSE_REQUESTED: return "DOSE_REQUESTED"; case BN_T_DOSE_DELIVERED: return "DOSE_DELIVERED";
    case BN_T_DOSE_REFUSED: return "DOSE_REFUSED"; case BN_T_SAFE_STOP: return "SAFE_STOP";
    case BN_T_JITTER_REPORT: return "JITTER_REPORT"; case BN_T_SELF_OK: return "SELF_OK";
    case BN_T_INTRUDER: return "INTRUDER";         case BN_T_QUARANTINE: return "QUARANTINE";
    case BN_T_EXPEL: return "EXPEL";               case BN_T_RELEASE: return "RELEASE";
    case BN_T_DEADLINE_MISSED: return "DEADLINE_MISSED"; case BN_T_MEMBRANE_REFUSE: return "MEMBRANE_REFUSE";
    default: return "UNKNOWN";
    }
}

static int write_all(int fd, const uint8_t *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        p += w; n -= (size_t)w;
    }
    return 0;
}

static int write_frame(int fd, uint16_t kind, const uint8_t *body, uint32_t len) {
    uint8_t *f = malloc(12 + len);
    if (!f) return -1;
    put32(f, BN_MAGIC); put16(f + 4, kind); put16(f + 6, 0); put32(f + 8, len);
    memcpy(f + 12, body, len);
    int rc = write_all(fd, f, 12 + len);   /* one write() per frame, file opened O_APPEND */
    free(f);
    return rc;
}

/* ---------- hashing rules ---------- */
static void genesis_head(uint8_t out[BN_HASH_LEN], const uint8_t *body, size_t len) {
    uint8_t buf[16 + 256];
    memcpy(buf, "BN-GEN-v1", 9);
    memcpy(buf + 9, body, len);
    bn_sha3_256(out, buf, 9 + len);
}

static void event_hash(uint8_t out[BN_HASH_LEN], const uint8_t prev[BN_HASH_LEN], const uint8_t *core, size_t core_len) {
    uint8_t buf[9 + BN_HASH_LEN + BN_EVENT_BODY];
    memcpy(buf, "BN-EVT-v1", 9);
    memcpy(buf + 9, prev, BN_HASH_LEN);
    memcpy(buf + 9 + BN_HASH_LEN, core, core_len);
    bn_sha3_256(out, buf, 9 + BN_HASH_LEN + core_len);
}

static size_t sign_msg(uint8_t *m, const char *dom, uint64_t seq, uint64_t t, const uint8_t head[BN_HASH_LEN]) {
    size_t n = strlen(dom);
    memcpy(m, dom, n); put64(m + n, seq); put64(m + n + 8, t); memcpy(m + n + 16, head, BN_HASH_LEN);
    return n + 16 + BN_HASH_LEN;
}

/* ---------- keys ---------- */
int bn_keys_generate(bn_keys *k) {
    memset(k, 0, sizeof *k);
    OQS_SIG *a = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65), *b = OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128s);
    if (!a || !b) { OQS_SIG_free(a); OQS_SIG_free(b); return -1; }
    k->mldsa_pk_len = a->length_public_key; k->mldsa_sk_len = a->length_secret_key;
    k->slh_pk_len = b->length_public_key;   k->slh_sk_len = b->length_secret_key;
    k->mldsa_pk = malloc(k->mldsa_pk_len); k->mldsa_sk = malloc(k->mldsa_sk_len);
    k->slh_pk = malloc(k->slh_pk_len);     k->slh_sk = malloc(k->slh_sk_len);
    int rc = (k->mldsa_pk && k->mldsa_sk && k->slh_pk && k->slh_sk
              && OQS_SIG_keypair(a, k->mldsa_pk, k->mldsa_sk) == OQS_SUCCESS
              && OQS_SIG_keypair(b, k->slh_pk, k->slh_sk) == OQS_SUCCESS) ? 0 : -1;
    OQS_SIG_free(a); OQS_SIG_free(b);
    if (rc) bn_keys_free(k);
    return rc;
}

static int save_file(const char *dir, const char *name, const uint8_t *p, size_t n, mode_t mode) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (fd < 0) return -1;
    int rc = write_all(fd, p, n);
    fchmod(fd, mode);
    if (fsync(fd)) rc = -1;
    close(fd);
    return rc;
}

static uint8_t *load_file(const char *dir, const char *name, size_t want) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    uint8_t *p = malloc(want);
    ssize_t r = p ? read(fd, p, want) : -1;
    close(fd);
    if (r != (ssize_t)want) { free(p); return NULL; }
    return p;
}

int bn_keys_save(const bn_keys *k, const char *dir) {
    if (save_file(dir, "mldsa65.pub", k->mldsa_pk, k->mldsa_pk_len, 0644)) return -1;
    if (save_file(dir, "slhdsa128s.pub", k->slh_pk, k->slh_pk_len, 0644)) return -1;
    if (k->mldsa_sk && save_file(dir, "mldsa65.sec", k->mldsa_sk, k->mldsa_sk_len, 0600)) return -1;
    if (k->slh_sk && save_file(dir, "slhdsa128s.sec", k->slh_sk, k->slh_sk_len, 0600)) return -1;
    return 0;
}

int bn_keys_load(bn_keys *k, const char *dir, int with_secret) {
    memset(k, 0, sizeof *k);
    k->mldsa_pk_len = OQS_SIG_ml_dsa_65_length_public_key; k->mldsa_sk_len = OQS_SIG_ml_dsa_65_length_secret_key;
    OQS_SIG *b = OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128s);
    if (!b) return -1;
    k->slh_pk_len = b->length_public_key; k->slh_sk_len = b->length_secret_key;
    OQS_SIG_free(b);
    k->mldsa_pk = load_file(dir, "mldsa65.pub", k->mldsa_pk_len);
    k->slh_pk = load_file(dir, "slhdsa128s.pub", k->slh_pk_len);
    if (with_secret) {
        k->mldsa_sk = load_file(dir, "mldsa65.sec", k->mldsa_sk_len);
        k->slh_sk = load_file(dir, "slhdsa128s.sec", k->slh_sk_len);
    }
    if (!k->mldsa_pk || !k->slh_pk || (with_secret && (!k->mldsa_sk || !k->slh_sk))) { bn_keys_free(k); return -1; }
    return 0;
}

void bn_keys_free(bn_keys *k) {
    if (k->mldsa_sk) OQS_MEM_cleanse(k->mldsa_sk, k->mldsa_sk_len);
    if (k->slh_sk) OQS_MEM_cleanse(k->slh_sk, k->slh_sk_len);
    free(k->mldsa_pk); free(k->mldsa_sk); free(k->slh_pk); free(k->slh_sk);
    memset(k, 0, sizeof *k);
}

/* ---------- writer ---------- */
static size_t genesis_body(uint8_t *b, const bn_keys *k, const char *device_id) {
    put32(b, 1);
    memset(b + 4, 0, BN_DEVICE_LEN);
    strncpy((char *)b + 4, device_id ? device_id : "", BN_DEVICE_LEN);
    bn_sha3_256(b + 4 + BN_DEVICE_LEN, k->mldsa_pk, k->mldsa_pk_len);
    bn_sha3_256(b + 4 + BN_DEVICE_LEN + BN_HASH_LEN, k->slh_pk, k->slh_pk_len);
    return 4 + BN_DEVICE_LEN + 2 * BN_HASH_LEN;
}

int bn_open(bn_journal *j, const char *path, const bn_keys *k, const char *device_id) {
    memset(j, 0, sizeof *j);
    j->fd = -1;
    j->keys = k;
    j->last_sealed_seq = UINT64_MAX;
    j->mldsa = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    j->slh = OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128s);
    if (!j->mldsa || !j->slh) goto fail;

    struct stat st;
    if (stat(path, &st) == 0 && st.st_size > 0) {
        /* Resume: refuse to extend a journal that does not verify. */
        bn_report r;
        if (bn_verify_file(path, k, &r) != 0 || !r.ok) { errno = EBADMSG; goto fail; }
        j->next_seq = r.events;
        j->last_sealed_seq = r.last_sealed_seq;
        memcpy(j->head, r.head, BN_HASH_LEN);
        j->fd = open(path, O_WRONLY | O_APPEND);
        if (j->fd < 0) goto fail;
        return 0;
    }
    j->fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_EXCL, 0640);
    if (j->fd < 0) goto fail;
    uint8_t g[256];
    size_t gl = genesis_body(g, k, device_id);
    if (write_frame(j->fd, BN_K_GENESIS, g, (uint32_t)gl) || fsync(j->fd)) goto fail;
    genesis_head(j->head, g, gl);
    return 0;
fail:
    bn_close(j);
    return -1;
}

int bn_append(bn_journal *j, uint64_t t_ns, uint32_t source, uint16_t type, uint16_t flags,
              const void *payload, size_t len, bn_event *out) {
    if (len > BN_PAYLOAD_LEN) { errno = EMSGSIZE; return -1; }
    uint8_t body[BN_EVENT_BODY];
    const size_t core = 8 + 8 + 4 + 2 + 2 + BN_PAYLOAD_LEN;
    put64(body, j->next_seq); put64(body + 8, t_ns); put32(body + 16, source);
    put16(body + 20, type); put16(body + 22, flags);
    memset(body + 24, 0, BN_PAYLOAD_LEN);
    if (len) memcpy(body + 24, payload, len);
    memcpy(body + core, j->head, BN_HASH_LEN);
    event_hash(body + core + BN_HASH_LEN, j->head, body, core);
    if (write_frame(j->fd, BN_K_EVENT, body, BN_EVENT_BODY)) return -1;
    if (out) {
        out->seq = j->next_seq; out->t_ns = t_ns; out->source = source; out->type = type; out->flags = flags;
        memcpy(out->payload, body + 24, BN_PAYLOAD_LEN);
        memcpy(out->prev, j->head, BN_HASH_LEN);
        memcpy(out->hash, body + core + BN_HASH_LEN, BN_HASH_LEN);
    }
    memcpy(j->head, body + core + BN_HASH_LEN, BN_HASH_LEN);
    j->next_seq++;
    return 0;
}

static int sign_frame(bn_journal *j, OQS_SIG *s, const uint8_t *sk, const char *dom, uint16_t kind, uint64_t t) {
    if (j->next_seq == 0) return 0;                       /* nothing to cover yet */
    uint64_t seq = j->next_seq - 1;
    uint8_t m[64];
    size_t ml = sign_msg(m, dom, seq, t, j->head);
    size_t cap = s->length_signature, sl = 0;
    uint8_t *b = malloc(8 + 8 + BN_HASH_LEN + 4 + cap);
    if (!b) return -1;
    int rc = -1;
    if (OQS_SIG_sign(s, b + 52, &sl, m, ml, sk) == OQS_SUCCESS) {
        put64(b, seq); put64(b + 8, t); memcpy(b + 16, j->head, BN_HASH_LEN); put32(b + 48, (uint32_t)sl);
        rc = write_frame(j->fd, kind, b, (uint32_t)(52 + sl));
        if (rc == 0) rc = fsync(j->fd);                   /* a seal is a durability point */
    }
    free(b);
    return rc;
}

int bn_seal(bn_journal *j, uint64_t t_real_ns) {
    if (j->last_sealed_seq != UINT64_MAX && j->last_sealed_seq + 1 == j->next_seq) return 0;
    int rc = sign_frame(j, j->mldsa, j->keys->mldsa_sk, "BN-SEAL-v1", BN_K_SEAL, t_real_ns);
    if (rc == 0 && j->next_seq) j->last_sealed_seq = j->next_seq - 1;
    return rc;
}

int bn_root(bn_journal *j, uint64_t t_real_ns) {
    return sign_frame(j, j->slh, j->keys->slh_sk, "BN-ROOT-v1", BN_K_ROOT, t_real_ns);
}

void bn_close(bn_journal *j) {
    if (j->fd >= 0) { fsync(j->fd); close(j->fd); }
    OQS_SIG_free(j->mldsa); OQS_SIG_free(j->slh);
    j->fd = -1; j->mldsa = j->slh = NULL;
}

/* ---------- reader / verifier ---------- */
static void fail_at(bn_report *r, long off, uint64_t seq, const char *why) {
    if (!r->ok) return;
    r->ok = 0; r->first_bad_offset = off; r->first_bad_seq = seq;
    snprintf(r->reason, sizeof r->reason, "%s", why);
}

int bn_verify_file(const char *path, const bn_keys *pub, bn_report *r) {
    memset(r, 0, sizeof *r);
    r->ok = 1; r->first_bad_offset = -1;
    r->first_bad_seq = r->last_sealed_seq = r->last_rooted_seq = UINT64_MAX;
    int fd = open(path, O_RDONLY);
    if (fd < 0) { fail_at(r, 0, UINT64_MAX, "cannot open journal"); return -1; }
    OQS_SIG *a = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65), *b = OQS_SIG_new(OQS_SIG_alg_slh_dsa_pure_sha2_128s);
    uint8_t *body = malloc(BN_MAX_BODY);
    if (!a || !b || !body) { fail_at(r, 0, UINT64_MAX, "out of memory"); goto done; }

    long off = 0;
    int have_genesis = 0;
    uint64_t expect_seq = 0;
    uint8_t head[BN_HASH_LEN] = {0};
    for (;;) {
        uint8_t h[12];
        ssize_t n = read(fd, h, 12);
        if (n == 0) break;
        if (n != 12) { fail_at(r, off, expect_seq, "torn frame header at end of file"); break; }
        uint32_t len = get32(h + 8);
        uint16_t kind = get16(h + 4);
        if (get32(h) != BN_MAGIC) { fail_at(r, off, expect_seq, "bad frame magic"); break; }
        if (len > BN_MAX_BODY) { fail_at(r, off, expect_seq, "frame too large"); break; }
        if (read(fd, body, len) != (ssize_t)len) { fail_at(r, off, expect_seq, "torn frame body at end of file"); break; }

        if (!have_genesis) {
            if (kind != BN_K_GENESIS || len != 4 + BN_DEVICE_LEN + 2 * BN_HASH_LEN) { fail_at(r, off, 0, "missing genesis"); break; }
            uint8_t fp[BN_HASH_LEN];
            bn_sha3_256(fp, pub->mldsa_pk, pub->mldsa_pk_len);
            if (memcmp(fp, body + 4 + BN_DEVICE_LEN, BN_HASH_LEN)) { fail_at(r, off, 0, "ML-DSA key does not match genesis"); break; }
            bn_sha3_256(fp, pub->slh_pk, pub->slh_pk_len);
            if (memcmp(fp, body + 4 + BN_DEVICE_LEN + BN_HASH_LEN, BN_HASH_LEN)) { fail_at(r, off, 0, "SLH-DSA key does not match genesis"); break; }
            genesis_head(head, body, len);
            have_genesis = 1;
        } else if (kind == BN_K_EVENT) {
            const size_t core = 8 + 8 + 4 + 2 + 2 + BN_PAYLOAD_LEN;
            uint8_t calc[BN_HASH_LEN];
            if (len != BN_EVENT_BODY) { fail_at(r, off, expect_seq, "bad event size"); break; }
            if (get64(body) != expect_seq) { fail_at(r, off, expect_seq, "sequence gap or reorder"); break; }
            if (memcmp(body + core, head, BN_HASH_LEN)) { fail_at(r, off, expect_seq, "previous-hash link broken"); break; }
            event_hash(calc, head, body, core);
            if (memcmp(calc, body + core + BN_HASH_LEN, BN_HASH_LEN)) { fail_at(r, off, expect_seq, "event content altered"); break; }
            memcpy(head, calc, BN_HASH_LEN);
            expect_seq++; r->events++;
        } else if (kind == BN_K_SEAL || kind == BN_K_ROOT) {
            if (len < 52 || get32(body + 48) != len - 52) { fail_at(r, off, expect_seq, "bad signature frame"); break; }
            uint64_t seq = get64(body), t = get64(body + 8);
            if (expect_seq == 0 || seq != expect_seq - 1 || memcmp(body + 16, head, BN_HASH_LEN)) {
                fail_at(r, off, seq, "signature does not cover the current head"); break;
            }
            uint8_t m[64];
            int seal = kind == BN_K_SEAL;
            size_t ml = sign_msg(m, seal ? "BN-SEAL-v1" : "BN-ROOT-v1", seq, t, head);
            OQS_STATUS ok = OQS_SIG_verify(seal ? a : b, m, ml, body + 52, len - 52, seal ? pub->mldsa_pk : pub->slh_pk);
            if (ok != OQS_SUCCESS) { fail_at(r, off, seq, seal ? "ML-DSA seal invalid" : "SLH-DSA root invalid"); break; }
            if (seal) { r->seals++; r->last_sealed_seq = seq; } else { r->roots++; r->last_rooted_seq = seq; }
        } else {
            fail_at(r, off, expect_seq, "unknown frame kind"); break;
        }
        off += 12 + (long)len;
    }
    if (!have_genesis && r->ok) fail_at(r, 0, 0, "empty journal");
    memcpy(r->head, head, BN_HASH_LEN);
    r->unsealed_tail = r->last_sealed_seq == UINT64_MAX ? r->events : r->events - 1 - r->last_sealed_seq;
done:
    free(body); OQS_SIG_free(a); OQS_SIG_free(b); close(fd);
    return 0;
}
