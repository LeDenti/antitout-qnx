/* bn_qnx.h — shared definitions for the QNX processes (doseur, boitenoire, antitout, intrus). */
#ifndef BN_QNX_H
#define BN_QNX_H

#include <stdatomic.h>
#include <stdint.h>
#include <sys/neutrino.h>
#include "bn_journal.h"

/* Priorities (SCHED_FIFO). The supervisor sits above everything it supervises,
 * but it is blocked almost all the time, so it never steals the control loop. */
#define PRIO_ANTITOUT   50
#define PRIO_DOSEUR     40
#define PRIO_BOITENOIRE 15
#define PRIO_QUARANTINE  1

#define BN_DEVICE        "/dev/boitenoire"
#define BN_RING_SHM      "/bn_ring"
#define ANTITOUT_NAME    "antitout"
#define DOSEUR_NAME      "antitout-doseur"

/* Pulse codes */
enum {
    CODE_RING_READY = _PULSE_CODE_MINAVAIL,  /* doseur -> boitenoire: ring has data           */
    CODE_TICK,                               /* timer -> doseur: 1 ms control tick             */
    CODE_SEAL_TIMER,                         /* timer -> boitenoire: seal now                  */
    CODE_ROOT_TIMER,                         /* timer -> boitenoire: SLH-DSA root now          */
    CODE_HEARTBEAT,                          /* doseur -> antitout: value = worst jitter (us)  */
    CODE_DOSE_OUT,                           /* doseur -> antitout: value = deviation (ppm)    */
    CODE_MEMBRANE,                           /* boitenoire -> antitout: value = refused pid    */
    CODE_WATCH_TIMER,                        /* timer -> antitout: periodic checks             */
    CODE_SAFE_STOP,                          /* antitout -> doseur: close valve, stop          */
    CODE_RESUME,                             /* antitout -> doseur: resume dispensing          */
};

/* Lock-free single-producer / single-consumer ring in shared memory. */
#define BN_RING_SLOTS 4096u
typedef struct {
    uint64_t t_ns;
    uint32_t source;
    uint16_t type;
    uint16_t flags;
    uint8_t  payload[BN_PAYLOAD_LEN];
} bn_slot;

typedef struct {
    _Atomic uint32_t head;      /* written by the producer */
    _Atomic uint32_t tail;      /* written by the consumer */
    _Atomic uint32_t dropped;   /* events lost because the ring was full: never block the loop */
    bn_slot slot[BN_RING_SLOTS];
} bn_ring;

/* write() message accepted by /dev/boitenoire from processes of the self. */
typedef struct {
    uint16_t type;
    uint16_t flags;
    uint8_t  payload[BN_PAYLOAD_LEN];
} bn_write_msg;

/* Prescription message sent to the dispensing robot. */
#define MSG_PRESCRIBE 0x4250   /* "PB" — above _IO_MAX so it never collides with I/O messages */
typedef struct {
    uint16_t type;             /* MSG_PRESCRIBE */
    uint16_t reserved;
    uint32_t dose_mg;
    char     drug[24];
} bn_prescribe_msg;

/* Payloads (little-endian, packed into the 40-byte event payload) */
typedef struct {
    char     drug[16];
    uint32_t target_mg_x100;
    uint32_t delivered_mg_x100;
    int32_t  deviation_ppm;
    uint32_t max_jitter_us;
    uint32_t requester_pid;
    uint32_t reserved;
} bn_dose_payload;

typedef struct {
    uint32_t pid;
    uint32_t tid;
    uint32_t old_prio;
    uint32_t new_prio;
    uint8_t  exe_hash8[8];     /* first 8 bytes of SHA3-256 of the binary */
    char     name[16];
} bn_immune_payload;

static inline void ring_push(bn_ring *r, uint64_t t, uint32_t src, uint16_t type, const void *p, size_t n) {
    uint32_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    uint32_t t_ = atomic_load_explicit(&r->tail, memory_order_acquire);
    if (h - t_ >= BN_RING_SLOTS) { atomic_fetch_add_explicit(&r->dropped, 1, memory_order_relaxed); return; }
    bn_slot *s = &r->slot[h % BN_RING_SLOTS];
    s->t_ns = t; s->source = src; s->type = type; s->flags = 0;
    for (size_t i = 0; i < BN_PAYLOAD_LEN; i++) s->payload[i] = i < n ? ((const uint8_t *)p)[i] : 0;
    atomic_store_explicit(&r->head, h + 1, memory_order_release);
}

static inline int ring_pop(bn_ring *r, bn_slot *out) {
    uint32_t t_ = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint32_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    if (t_ == h) return 0;
    *out = r->slot[t_ % BN_RING_SLOTS];
    atomic_store_explicit(&r->tail, t_ + 1, memory_order_release);
    return 1;
}

#endif
