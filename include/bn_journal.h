/* bn_journal.h — tamper-evident, post-quantum signed black-box journal.
 *
 * File layout: a sequence of frames.
 *   frame  = magic(u32 "BNF1") | kind(u16) | reserved(u16) | body_len(u32) | body
 *   GENESIS body: version, device id, ML-DSA-65 and SLH-DSA public key fingerprints
 *   EVENT   body: seq | t_ns | source | type | flags | payload[40] | prev[32] | hash[32]
 *            hash = SHA3-256("BN-EVT-v1" | prev | seq..payload)
 *   SEAL    body: seq | t_real_ns | head[32] | sig_len | ML-DSA-65 signature
 *            signed message = "BN-SEAL-v1" | seq | t_real_ns | head
 *   ROOT    body: seq | t_real_ns | head[32] | sig_len | SLH-DSA-SHA2-128s signature
 *            signed message = "BN-ROOT-v1" | seq | t_real_ns | head
 * All integers little-endian. The chain head after GENESIS is SHA3-256(genesis body).
 */
#ifndef BN_JOURNAL_H
#define BN_JOURNAL_H

#include <stdint.h>
#include <stddef.h>

#define BN_HASH_LEN      32
#define BN_PAYLOAD_LEN   40
#define BN_DEVICE_LEN    32
#define BN_EVENT_BODY    (8 + 8 + 4 + 2 + 2 + BN_PAYLOAD_LEN + BN_HASH_LEN + BN_HASH_LEN)

enum bn_kind { BN_K_GENESIS = 1, BN_K_EVENT = 2, BN_K_SEAL = 3, BN_K_ROOT = 4 };

/* Event types. 0x01xx: dispensing robot, 0x02xx: antiTOUT, 0x03xx: system. */
enum bn_type {
    BN_T_BOOT            = 0x0301,
    BN_T_RING_DROP       = 0x0302,
    BN_T_DOSE_REQUESTED  = 0x0101,
    BN_T_DOSE_DELIVERED  = 0x0102,
    BN_T_DOSE_REFUSED    = 0x0103,
    BN_T_SAFE_STOP       = 0x0104,
    BN_T_JITTER_REPORT   = 0x0105,
    BN_T_SELF_OK         = 0x0201,
    BN_T_INTRUDER        = 0x0202,
    BN_T_QUARANTINE      = 0x0203,
    BN_T_EXPEL           = 0x0204,
    BN_T_RELEASE         = 0x0205,
    BN_T_DEADLINE_MISSED = 0x0206,
    BN_T_MEMBRANE_REFUSE = 0x0207,
};

typedef struct {
    uint64_t seq;
    uint64_t t_ns;
    uint32_t source;
    uint16_t type;
    uint16_t flags;
    uint8_t  payload[BN_PAYLOAD_LEN];
    uint8_t  prev[BN_HASH_LEN];
    uint8_t  hash[BN_HASH_LEN];
} bn_event;

typedef struct {
    uint8_t *mldsa_pk, *mldsa_sk;   /* ML-DSA-65 */
    uint8_t *slh_pk,   *slh_sk;     /* SLH-DSA-SHA2-128s (pure) */
    size_t mldsa_pk_len, mldsa_sk_len, slh_pk_len, slh_sk_len;
} bn_keys;

typedef struct {
    int      fd;
    uint64_t next_seq;
    uint64_t last_sealed_seq;   /* UINT64_MAX when nothing sealed yet */
    uint8_t  head[BN_HASH_LEN];
    const bn_keys *keys;
    void    *mldsa, *slh;       /* OQS_SIG handles */
} bn_journal;

typedef struct {
    int      ok;                /* 1 when every frame checks out */
    uint64_t events;
    uint64_t seals, roots;
    uint64_t last_sealed_seq;   /* UINT64_MAX when none */
    uint64_t last_rooted_seq;   /* UINT64_MAX when none */
    uint64_t unsealed_tail;     /* events after the last valid seal */
    uint64_t first_bad_seq;     /* UINT64_MAX when none */
    long     first_bad_offset;  /* byte offset of the first bad frame, -1 when none */
    char     reason[160];
    uint8_t  head[BN_HASH_LEN];
} bn_report;

/* Keys */
int  bn_keys_generate(bn_keys *k);
int  bn_keys_save(const bn_keys *k, const char *dir);          /* *.pub 0644, *.sec 0600 */
int  bn_keys_load(bn_keys *k, const char *dir, int with_secret);
void bn_keys_free(bn_keys *k);

/* Writer */
int  bn_open(bn_journal *j, const char *path, const bn_keys *k, const char *device_id);
int  bn_append(bn_journal *j, uint64_t t_ns, uint32_t source, uint16_t type, uint16_t flags,
               const void *payload, size_t len, bn_event *out);
int  bn_seal(bn_journal *j, uint64_t t_real_ns);                /* ML-DSA-65 over head */
int  bn_root(bn_journal *j, uint64_t t_real_ns);                /* SLH-DSA over head */
void bn_close(bn_journal *j);

/* Reader */
int  bn_verify_file(const char *path, const bn_keys *pub, bn_report *r);

/* Helpers */
void bn_sha3_256(uint8_t out[BN_HASH_LEN], const void *in, size_t len);
void bn_hex(char *out, const uint8_t *in, size_t len);          /* out: 2*len+1 */
uint64_t bn_now_real_ns(void);
uint64_t bn_now_mono_ns(void);
const char *bn_type_name(uint16_t type);

#endif
