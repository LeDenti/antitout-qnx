/* doseur — simulated gravimetric compounding robot (e.g. chemotherapy preparation), 1 kHz loop.
 *
 * The valve is driven from the scale reading every millisecond. If the loop is late, the valve
 * stays open for the whole delay: a missed deadline is an overdose. That is why this runs on QNX.
 *
 * - SCHED_FIFO 40, periodic timer delivered as a pulse on its own named channel.
 * - Events go to the black box through a lock-free ring + a non-blocking pulse.
 * - Heartbeat pulse to antiTOUT every 10 ms carrying the worst lateness seen (us).
 * - Accepts MSG_PRESCRIBE messages; refuses doses above the protocol maximum.
 * - Obeys CODE_SAFE_STOP / CODE_RESUME pulses from antiTOUT.
 *
 * Protocol maxima below are illustrative demo values, not clinical guidance.
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include <sys/mman.h>
#include <sys/neutrino.h>
#include <time.h>
#include <unistd.h>
#include "bn_qnx.h"

#define TICK_NS        1000000L
#define TOLERANCE_PPM  50000        /* +/- 5 % */
#define FAST_MG_PER_MS 1.0
#define FINE_MG_PER_MS 0.05
#define FINE_ZONE      0.05         /* last 5 % of the dose at the fine flow */

typedef struct { const char *drug; double max_mg; } protocol;
static const protocol PROTOCOLS[] = {
    { "cyclophosphamide", 2000 }, { "fluorouracil", 1600 }, { "carboplatin", 900 }, { "gemcitabine", 3200 },
};
typedef struct { char drug[24]; double target_mg; pid_t requester; } order;

static order queue[32];
static int q_head, q_tail;
static const order DEMO[] = {
    { "cyclophosphamide", 1000, 0 }, { "fluorouracil", 800, 0 }, { "carboplatin", 450, 0 }, { "gemcitabine", 1600, 0 },
};

static bn_ring *ring;
static int bn_coid = -1, at_coid = -1;

static uint64_t now_ns(void) { return bn_now_mono_ns(); }

static void emit(uint16_t type, const void *p, size_t n) {
    ring_push(ring, now_ns(), (uint32_t)getpid(), type, p, n);
    if (bn_coid >= 0) MsgSendPulse(bn_coid, PRIO_BOITENOIRE, CODE_RING_READY, 0);  /* never blocks */
}

static void tell_antitout(int code, int value) {
    if (at_coid < 0) at_coid = name_open(ANTITOUT_NAME, 0);
    if (at_coid >= 0 && MsgSendPulse(at_coid, PRIO_ANTITOUT, code, value) == -1) { name_close(at_coid); at_coid = -1; }
}

static const protocol *find_protocol(const char *drug) {
    for (size_t i = 0; i < sizeof PROTOCOLS / sizeof *PROTOCOLS; i++)
        if (!strcmp(PROTOCOLS[i].drug, drug)) return &PROTOCOLS[i];
    return NULL;
}

static void fill(bn_dose_payload *p, const order *o, double delivered, uint32_t jitter_us) {
    memset(p, 0, sizeof *p);
    memcpy(p->drug, o->drug, strnlen(o->drug, sizeof p->drug));   /* not NUL-terminated at 16 */
    p->target_mg_x100 = (uint32_t)(o->target_mg * 100);
    p->delivered_mg_x100 = (uint32_t)(delivered * 100);
    p->deviation_ppm = o->target_mg > 0 ? (int32_t)((delivered - o->target_mg) / o->target_mg * 1e6) : 0;
    p->max_jitter_us = jitter_us;
    p->requester_pid = (uint32_t)o->requester;
}

/* Returns 0 if accepted, an errno if refused (the refusal is journaled). */
static int prescribe(const char *drug, double mg, pid_t who) {
    order o = { .target_mg = mg, .requester = who };
    snprintf(o.drug, sizeof o.drug, "%s", drug);
    const protocol *p = find_protocol(o.drug);
    if (!p || mg <= 0 || mg > p->max_mg) {
        bn_dose_payload pl; fill(&pl, &o, 0, 0);
        emit(BN_T_DOSE_REFUSED, &pl, sizeof pl);
        printf("doseur: REFUSED %s %.0f mg from pid %d (protocol max %.0f mg)\n", o.drug, mg, (int)who, p ? p->max_mg : 0.0);
        return p ? ERANGE : ENOENT;
    }
    if ((q_tail + 1) % 32 == q_head) return EAGAIN;
    queue[q_tail] = o; q_tail = (q_tail + 1) % 32;
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);   /* logs reach a file line by line */
    struct sched_param sp = { .sched_priority = PRIO_DOSEUR };
    if (pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp) != 0) fprintf(stderr, "doseur: cannot set FIFO %d\n", PRIO_DOSEUR);

    int fd = shm_open(BN_RING_SHM, O_RDWR, 0);
    if (fd < 0) { perror("doseur: start boitenoire first"); return 1; }
    ring = mmap(NULL, sizeof(bn_ring), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    close(fd);
    if (ring == MAP_FAILED) { perror("doseur: mmap"); return 1; }
    bn_coid = open(BN_DEVICE, O_RDONLY);           /* a read-only connection is enough for pulses */
    if (bn_coid < 0) { perror("doseur: open " BN_DEVICE); return 1; }

    name_attach_t *att = name_attach(NULL, DOSEUR_NAME, 0);
    if (!att) { perror("doseur: name_attach"); return 1; }
    int self = ConnectAttach(0, 0, att->chid, _NTO_SIDE_CHANNEL, 0);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, self, PRIO_DOSEUR, CODE_TICK, 0);
    timer_t tid;
    struct itimerspec it = { .it_value = { 0, TICK_NS }, .it_interval = { 0, TICK_NS } };
    if (timer_create(CLOCK_MONOTONIC, &ev, &tid) == -1 || timer_settime(tid, 0, &it, NULL) == -1) {
        perror("doseur: timer"); return 1;
    }

    for (size_t i = 0; i < sizeof DEMO / sizeof *DEMO; i++) prescribe(DEMO[i].drug, DEMO[i].target_mg, getpid());

    union { struct _pulse pulse; uint16_t type; struct _io_connect connect; bn_prescribe_msg rx; } msg;
    struct _msg_info info;
    int stopped = 0, valve = 0, busy = 0, demo_i = 0;
    double scale = 0, delivered = 0;
    order cur = {0};
    uint64_t last = now_ns(), pause_until = 0;
    uint32_t worst_us = 0, worst_report_us = 0, ticks = 0;
    uint32_t noise = 12345;
    printf("doseur: running at 1 kHz, SCHED_FIFO %d\n", PRIO_DOSEUR);

    for (;;) {
        int rcvid = MsgReceive(att->chid, &msg, sizeof msg, &info);
        if (rcvid == -1) { if (errno == EINTR) continue; perror("doseur: MsgReceive"); break; }
        if (rcvid > 0) {                                    /* a message */
            if (msg.type == _IO_CONNECT) { MsgReply(rcvid, EOK, NULL, 0); continue; }
            if (msg.type == MSG_PRESCRIBE) {
                msg.rx.drug[sizeof msg.rx.drug - 1] = 0;
                int rc = prescribe(msg.rx.drug, msg.rx.dose_mg, info.pid);
                if (rc) MsgError(rcvid, rc); else MsgReply(rcvid, EOK, NULL, 0);
                continue;
            }
            MsgError(rcvid, ENOSYS);
            continue;
        }
        switch (msg.pulse.code) {                           /* a pulse */
        case _PULSE_CODE_DISCONNECT: ConnectDetach(msg.pulse.scoid); continue;
        case CODE_SAFE_STOP:
            if (!stopped) {
                stopped = 1; valve = 0;
                bn_dose_payload pl; fill(&pl, &cur, delivered, worst_us);
                emit(BN_T_SAFE_STOP, &pl, sizeof pl);
                printf("doseur: SAFE STOP ordered by antiTOUT, valve closed\n");
            }
            continue;
        case CODE_RESUME:
            if (stopped) { stopped = 0; printf("doseur: resumed\n"); }
            continue;
        case CODE_TICK: break;
        default: continue;
        }

        /* ---- 1 ms control tick ---- */
        uint64_t now = now_ns();
        uint64_t dt = now - last;          /* while we were not running, the valve kept its state */
        last = now;
        uint32_t late_us = dt > (uint64_t)TICK_NS ? (uint32_t)((dt - TICK_NS) / 1000) : 0;
        if (late_us > worst_us) worst_us = late_us;
        if (late_us > worst_report_us) worst_report_us = late_us;
        ticks++;

        if (valve) {
            double flow = (cur.target_mg - scale) > cur.target_mg * FINE_ZONE ? FAST_MG_PER_MS : FINE_MG_PER_MS;
            delivered += flow * (double)dt / 1e6;
        }
        noise = noise * 1103515245u + 12345u;
        scale = delivered + ((double)(noise >> 16 & 0xff) - 127.5) * 0.0002;   /* +/- 0.025 mg */

        if (busy && !stopped) {
            double next = (cur.target_mg - scale) > cur.target_mg * FINE_ZONE ? FAST_MG_PER_MS : FINE_MG_PER_MS;
            valve = scale + next < cur.target_mg;          /* close before the next step overshoots */
            if (!valve) {                                  /* dose finished */
                bn_dose_payload pl; fill(&pl, &cur, delivered, worst_us);
                emit(BN_T_DOSE_DELIVERED, &pl, sizeof pl);
                int32_t dev = pl.deviation_ppm;
                printf("doseur: %-16s target %7.1f mg delivered %7.1f mg  %+6.2f %%  worst late %u us%s\n",
                       cur.drug, cur.target_mg, delivered, dev / 1e4, worst_us,
                       (dev > TOLERANCE_PPM || dev < -TOLERANCE_PPM) ? "  OUT OF TOLERANCE" : "");
                if (dev > TOLERANCE_PPM || dev < -TOLERANCE_PPM) tell_antitout(CODE_DOSE_OUT, dev);
                busy = 0;
                pause_until = now + 500000000ull;
            }
        } else if (!busy && !stopped && now >= pause_until) {
            if (q_head == q_tail) {                        /* demo: loop over the standard orders */
                const order *d = &DEMO[demo_i++ % (int)(sizeof DEMO / sizeof *DEMO)];
                prescribe(d->drug, d->target_mg, getpid());
            }
            if (q_head != q_tail) {
                cur = queue[q_head]; q_head = (q_head + 1) % 32;
                delivered = scale = 0; worst_us = 0; busy = 1; valve = 1;
                bn_dose_payload pl; fill(&pl, &cur, 0, 0);
                emit(BN_T_DOSE_REQUESTED, &pl, sizeof pl);
            }
        }
        if (ticks % 10 == 0) tell_antitout(CODE_HEARTBEAT, (int)worst_report_us), worst_report_us = 0;
        if (ticks % 1000 == 0) {
            uint32_t j[2] = { worst_us, ticks };
            emit(BN_T_JITTER_REPORT, j, sizeof j);
        }
    }
    return 0;
}
