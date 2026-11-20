/* boitenoire — QNX resource manager /dev/boitenoire.
 *
 * - The dispensing loop never waits for it: events arrive through a lock-free ring in shared
 *   memory, announced by a non-blocking pulse on the /dev/boitenoire connection.
 * - Every event is chained with SHA3-256; seals are ML-DSA-65 (FIPS 204), roots SLH-DSA (FIPS 205).
 * - Membrane: opening for writing is allowed only to binaries of the self (SHA3 of the executable,
 *   identity taken from the kernel with iofunc_client_info_ext). A refusal is journaled and
 *   reported to antiTOUT by pulse.
 * - read() returns a one-line status, so `cat /dev/boitenoire` shows the chain head.
 *
 * usage: boitenoire <journal-file> <key-dir> <soi-file>
 */
// Typed OCB: QNX 8.0 leaves RESMGR_OCB_T as void unless it is set before the headers.
struct _iofunc_ocb;
#define IOFUNC_OCB_T struct _iofunc_ocb
#define RESMGR_OCB_T struct _iofunc_ocb
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iofunc.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <time.h>
#include <unistd.h>
#include "bn_qnx.h"
#include "soi.h"

#define SEAL_EVERY 256
#define SEAL_PERIOD_MS 1000
#define ROOT_PERIOD_S  60

static resmgr_connect_funcs_t cfuncs;
static resmgr_io_funcs_t iofuncs;
static iofunc_attr_t attr;
static bn_journal J;
static bn_keys K;
static bn_ring *ring;
static soi_list soi;
static int antitout_coid = -1;
static uint32_t refused, drops_logged;
static volatile sig_atomic_t stop;

static void journal(uint32_t src, uint16_t type, const void *p, size_t n) {
    if (bn_append(&J, bn_now_mono_ns(), src, type, 0, p, n, NULL) != 0)
        perror("boitenoire: append");
    if (J.next_seq && (J.last_sealed_seq == UINT64_MAX || J.next_seq - 1 - J.last_sealed_seq >= SEAL_EVERY))
        bn_seal(&J, bn_now_real_ns());
}

static void tell_antitout(int code, int value) {
    if (antitout_coid < 0) antitout_coid = name_open(ANTITOUT_NAME, 0);
    if (antitout_coid >= 0 && MsgSendPulse(antitout_coid, PRIO_ANTITOUT, code, value) == -1) {
        name_close(antitout_coid);
        antitout_coid = -1;
    }
}

static void drain(void) {
    bn_slot s;
    while (ring_pop(ring, &s))
        journal(s.source, s.type, s.payload, BN_PAYLOAD_LEN);
    uint32_t d = atomic_load(&ring->dropped);
    if (d != drops_logged) {
        uint32_t lost = d - drops_logged;
        drops_logged = d;
        journal(0, BN_T_RING_DROP, &lost, sizeof lost);
    }
}

/* ---- resource manager handlers ---- */
static int bn_open_handler(resmgr_context_t *ctp, io_open_t *msg, RESMGR_HANDLE_T *handle, void *extra) {
    if (msg->connect.ioflag & _IO_FLAG_WR) {
        struct _client_info *info = NULL;
        if (iofunc_client_info_ext(ctp, 0, &info, 0) != EOK) return EACCES;
        pid_t pid = info->pid;
        iofunc_client_info_ext_free(&info);
        if (!soi_contains_pid(&soi, pid)) {
            bn_immune_payload p = { .pid = (uint32_t)pid };
            uint8_t h[BN_HASH_LEN];
            if (soi_hash_pid(pid, h, p.name, sizeof p.name) == 0) memcpy(p.exe_hash8, h, 8);
            refused++;
            journal((uint32_t)pid, BN_T_MEMBRANE_REFUSE, &p, sizeof p);
            bn_seal(&J, bn_now_real_ns());             /* a refusal is sealed at once */
            tell_antitout(CODE_MEMBRANE, pid);
            return EACCES;
        }
    }
    return iofunc_open_default(ctp, msg, handle, extra);
}

static int bn_read_handler(resmgr_context_t *ctp, io_read_t *msg, RESMGR_OCB_T *ocb) {
    int status = iofunc_read_verify(ctp, msg, ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    drain();
    static char buf[256];
    char hx[2 * BN_HASH_LEN + 1];
    bn_hex(hx, J.head, BN_HASH_LEN);
    unsigned long long sealed = J.last_sealed_seq == UINT64_MAX ? 0 : J.last_sealed_seq + 1;
    int len = snprintf(buf, sizeof buf, "events %llu sealed %llu drops %u refused %u head %s\n",
                       (unsigned long long)J.next_seq, sealed, drops_logged, refused, hx);
    size_t nbytes = 0;
    if (ocb->offset < len) {
        nbytes = (size_t)(len - ocb->offset);
        if (nbytes > _IO_READ_GET_NBYTES(msg)) nbytes = _IO_READ_GET_NBYTES(msg);
    }
    _IO_SET_READ_NBYTES(ctp, nbytes);
    if (nbytes) {
        SETIOV(ctp->iov, buf + ocb->offset, nbytes);
        ocb->offset += (off_t)nbytes;
        return _RESMGR_NPARTS(1);
    }
    return _RESMGR_NPARTS(0);
}

static int bn_write_handler(resmgr_context_t *ctp, io_write_t *msg, RESMGR_OCB_T *ocb) {
    int status = iofunc_write_verify(ctp, msg, ocb, NULL);
    if (status != EOK) return status;
    if ((msg->i.xtype & _IO_XTYPE_MASK) != _IO_XTYPE_NONE) return ENOSYS;
    size_t n = _IO_WRITE_GET_NBYTES(msg);
    if (n != sizeof(bn_write_msg)) return EINVAL;
    bn_write_msg w;
    if (resmgr_msgread(ctp, &w, sizeof w, sizeof msg->i) != (ssize_t)sizeof w) return EIO;
    drain();                                            /* keep causal order with the ring */
    journal((uint32_t)ctp->info.pid, w.type, w.payload, BN_PAYLOAD_LEN);
    if (w.type == BN_T_QUARANTINE || w.type == BN_T_EXPEL || w.type == BN_T_SAFE_STOP)
        bn_seal(&J, bn_now_real_ns());                 /* immune acts are sealed at once */
    _IO_SET_WRITE_NBYTES(ctp, n);
    return EOK;
}

/* ---- pulses ---- */
static int on_ring(message_context_t *ctp, int code, unsigned flags, void *h) {
    (void)ctp; (void)code; (void)flags; (void)h;
    drain();
    return 0;
}
static int on_seal(message_context_t *ctp, int code, unsigned flags, void *h) {
    (void)ctp; (void)code; (void)flags; (void)h;
    drain();
    bn_seal(&J, bn_now_real_ns());
    return 0;
}
static int on_root(message_context_t *ctp, int code, unsigned flags, void *h) {
    (void)ctp; (void)code; (void)flags; (void)h;
    drain();
    bn_seal(&J, bn_now_real_ns());
    bn_root(&J, bn_now_real_ns());     /* hash-based signature: slow, rare, at low priority */
    return 0;
}

static int start_timer(int coid, int code, long period_ns) {
    struct sigevent ev;
    timer_t id;
    SIGEV_PULSE_INIT(&ev, coid, PRIO_BOITENOIRE, code, 0);
    if (timer_create(CLOCK_MONOTONIC, &ev, &id) == -1) return -1;
    struct itimerspec it = { .it_value = { period_ns / 1000000000L, period_ns % 1000000000L },
                             .it_interval = { period_ns / 1000000000L, period_ns % 1000000000L } };
    return timer_settime(id, 0, &it, NULL);
}

static void on_signal(int s) { (void)s; stop = 1; }

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);   /* logs reach a file line by line */
    if (argc != 4) { fprintf(stderr, "usage: %s <journal> <key-dir> <soi-file>\n", argv[0]); return 2; }
    struct sched_param sp = { .sched_priority = PRIO_BOITENOIRE };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);

    if (soi_load(&soi, argv[3]) != 0 || soi.n == 0) { fprintf(stderr, "boitenoire: empty self list %s\n", argv[3]); return 2; }
    if (bn_keys_load(&K, argv[2], 1) != 0) { fprintf(stderr, "boitenoire: cannot load keys from %s\n", argv[2]); return 2; }
    if (bn_open(&J, argv[1], &K, "qnx-boitenoire") != 0) {
        fprintf(stderr, "boitenoire: journal %s does not verify, refusing to extend it (%s)\n", argv[1], strerror(errno));
        return 3;
    }

    int fd = shm_open(BN_RING_SHM, O_RDWR | O_CREAT, 0600);
    if (fd < 0 || ftruncate(fd, sizeof(bn_ring)) != 0) { perror("boitenoire: shm"); return 1; }
    ring = mmap(NULL, sizeof(bn_ring), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) { perror("boitenoire: mmap"); return 1; }
    close(fd);
    drops_logged = atomic_load(&ring->dropped);

    dispatch_t *dpp = dispatch_create();
    if (!dpp) { perror("boitenoire: dispatch_create"); return 1; }
    iofunc_func_init(_RESMGR_CONNECT_NFUNCS, &cfuncs, _RESMGR_IO_NFUNCS, &iofuncs);
    cfuncs.open = bn_open_handler;
    iofuncs.read = bn_read_handler;
    iofuncs.write = bn_write_handler;
    iofunc_attr_init(&attr, S_IFCHR | 0666, NULL, NULL);   /* access is decided by the membrane */
    resmgr_attr_t rattr;
    memset(&rattr, 0, sizeof rattr);
    rattr.nparts_max = 1;
    rattr.msg_max_size = 2048;
    if (resmgr_attach(dpp, &rattr, BN_DEVICE, _FTYPE_ANY, 0, &cfuncs, &iofuncs, &attr) == -1) {
        perror("boitenoire: resmgr_attach"); return 1;
    }
    pulse_attach(dpp, 0, CODE_RING_READY, on_ring, NULL);
    pulse_attach(dpp, 0, CODE_SEAL_TIMER, on_seal, NULL);
    pulse_attach(dpp, 0, CODE_ROOT_TIMER, on_root, NULL);

    dispatch_context_t *ctp = dispatch_context_alloc(dpp);
    int self = message_connect(dpp, MSG_FLAG_SIDE_CHANNEL);
    if (self == -1 || start_timer(self, CODE_SEAL_TIMER, SEAL_PERIOD_MS * 1000000L) == -1
        || start_timer(self, CODE_ROOT_TIMER, ROOT_PERIOD_S * 1000000000L) == -1) {
        perror("boitenoire: timers"); return 1;
    }

    uint32_t n = (uint32_t)soi.n;
    journal((uint32_t)getpid(), BN_T_BOOT, &n, sizeof n);
    bn_seal(&J, bn_now_real_ns());
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    printf("boitenoire: %s ready, %d binaries in the self, journal %s\n", BN_DEVICE, soi.n, argv[1]);

    while (!stop) {
        dispatch_context_t *c = dispatch_block(ctp);
        if (!c) { if (errno == EINTR) continue; perror("boitenoire: dispatch_block"); break; }
        ctp = c;
        dispatch_handler(ctp);
    }
    drain();
    bn_seal(&J, bn_now_real_ns());
    bn_root(&J, bn_now_real_ns());
    bn_close(&J);
    bn_keys_free(&K);
    return 0;
}
