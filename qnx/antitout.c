/* antitout — immune supervisor for a QNX real-time system, in three layers.
 *
 *  SELF   : the binaries allowed on this machine (SHA3-256 of each executable). Anything else is
 *           foreign. The black box enforces the same self as a membrane on /dev/boitenoire.
 *  STATE  : heartbeats and lateness of the dispensing loop, doses out of tolerance, membrane
 *           refusals, and a persistent memory of binaries already quarantined.
 *  ACTS   : nourishing quarantine (the culprit's threads drop to priority 1: alive but harmless),
 *           expulsion on relapse (SIGKILL), safe stop of the robot when doses drift.
 *           Every act is written to the black box and sealed.
 *
 * usage: antitout <soi-file> <memory-file>
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/iomsg.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <sys/procmgr.h>
#include <time.h>
#include <unistd.h>
#include "bn_qnx.h"
#include "soi.h"

#define WATCH_PERIOD_NS   10000000L   /* 10 ms */
#define HEARTBEAT_LATE_NS_DEFAULT 50000000ull /* 50 ms without heartbeat = missed deadline */
/* ANTITOUT_HB_MS overrides it: under full software emulation (QEMU TCG) the whole guest can stall
 * for 100+ ms, which is the host, not an intruder. On hardware or KVM keep the default. */
static uint64_t HEARTBEAT_LATE_NS = HEARTBEAT_LATE_NS_DEFAULT;
#define JITTER_LIMIT_US   500
#define MAX_TRACKED       64

typedef struct { pid_t pid; uint8_t hash[BN_HASH_LEN]; int known; int foreign; int quarantined; } proc_cache;

static soi_list soi;
static soi_list memory;                 /* binaries quarantined before: hash list, same format */
static const char *memory_file;
static proc_cache cache[MAX_TRACKED];
static int bn_fd = -1, doseur_coid = -1;
static pid_t doseur_pid = -1, self_pid;
static uint64_t last_hb, incident_until;
static int bad_jitter, doses_out, robot_stopped;
static uint64_t clean_since;

static void record(uint16_t type, const void *p, size_t n) {
    if (bn_fd < 0) bn_fd = open(BN_DEVICE, O_WRONLY);
    if (bn_fd < 0) { perror("antitout: open " BN_DEVICE); return; }
    bn_write_msg w = { .type = type };
    memcpy(w.payload, p, n > BN_PAYLOAD_LEN ? BN_PAYLOAD_LEN : n);
    if (write(bn_fd, &w, sizeof w) != (ssize_t)sizeof w) { close(bn_fd); bn_fd = -1; }
}

static proc_cache *lookup(pid_t pid) {
    proc_cache *free_slot = NULL;
    for (int i = 0; i < MAX_TRACKED; i++) {
        if (cache[i].known && cache[i].pid == pid) return &cache[i];
        if (!cache[i].known && !free_slot) free_slot = &cache[i];
    }
    if (!free_slot) { memset(cache, 0, sizeof cache); free_slot = &cache[0]; }
    memset(free_slot, 0, sizeof *free_slot);
    free_slot->pid = pid;
    if (soi_hash_pid(pid, free_slot->hash, NULL, 0) != 0) return NULL;
    free_slot->known = 1;
    free_slot->foreign = !soi_contains(&soi, free_slot->hash);
    return free_slot;
}

static void remember(const uint8_t hash[BN_HASH_LEN], const char *name) {
    if (soi_contains(&memory, hash) || memory.n >= SOI_MAX) return;
    memcpy(memory.e[memory.n].hash, hash, BN_HASH_LEN);
    snprintf(memory.e[memory.n].path, sizeof memory.e[0].path, "%s", name);
    memory.n++;
    FILE *f = fopen(memory_file, "a");
    if (f) {
        char hx[2 * BN_HASH_LEN + 1];
        bn_hex(hx, hash, BN_HASH_LEN);
        fprintf(f, "%s %s\n", hx, name);
        fclose(f);
    }
}

static int open_ctl(pid_t pid) {
    char p[64];
    snprintf(p, sizeof p, "/proc/%d/ctl", (int)pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) { snprintf(p, sizeof p, "/proc/%d/as", (int)pid); fd = open(p, O_RDONLY); }
    return fd;
}

/* Highest priority among the process's threads, -1 if unreadable. */
static int top_priority(pid_t pid) {
    int fd = open_ctl(pid), top = -1;
    if (fd < 0) return -1;
    debug_thread_t t;
    memset(&t, 0, sizeof t);
    t.tid = 1;
    while (devctl(fd, DCMD_PROC_TIDSTATUS, &t, sizeof t, NULL) == EOK) {
        /* real_priority, not priority: a server held at 1 inherits its client's priority while it
         * serves a message (QNX priority inheritance). That is not a relapse. */
        if (t.real_priority > top) top = t.real_priority;
        t.tid++;
    }
    close(fd);
    return top;
}

/* ACT: nourishing quarantine — every thread to priority 1. */
static void quarantine(pid_t pid, const char *why) {
    proc_cache *c = lookup(pid);
    char name[16] = "?";
    uint8_t h[BN_HASH_LEN];
    if (soi_hash_pid(pid, h, name, sizeof name) != 0) return;
    if (c && c->quarantined) {                      /* relapse: expel */
        bn_immune_payload p = { .pid = (uint32_t)pid };
        memcpy(p.exe_hash8, h, 8); memcpy(p.name, name, sizeof p.name);
        kill(pid, SIGKILL);
        record(BN_T_EXPEL, &p, sizeof p);
        printf("antitout: EXPELLED %s (pid %d), relapse after quarantine\n", name, (int)pid);
        if (c) c->known = 0;
        return;
    }
    int fd = open_ctl(pid);
    if (fd < 0) return;
    debug_thread_t t;
    memset(&t, 0, sizeof t);
    t.tid = 1;
    while (devctl(fd, DCMD_PROC_TIDSTATUS, &t, sizeof t, NULL) == EOK) {
        if (t.real_priority <= PRIO_QUARANTINE) { t.tid++; continue; }   /* already held */
        struct sched_param sp = { .sched_priority = PRIO_QUARANTINE };
        int old = t.real_priority;
        if (SchedSet(pid, (int)t.tid, SCHED_NOCHANGE, &sp) != -1) {
            bn_immune_payload p = { .pid = (uint32_t)pid, .tid = (uint32_t)t.tid,
                                    .old_prio = (uint32_t)old, .new_prio = PRIO_QUARANTINE };
            memcpy(p.exe_hash8, h, 8); memcpy(p.name, name, sizeof p.name);
            record(BN_T_QUARANTINE, &p, sizeof p);
            printf("antitout: QUARANTINE %s pid %d tid %d priority %d -> %d (%s)\n",
                   name, (int)pid, (int)t.tid, old, PRIO_QUARANTINE, why);
        }
        t.tid++;
    }
    close(fd);
    if (c) c->quarantined = 1;
    remember(h, name);
}

/* SELF, central tolerance: every binary already running when antiTOUT starts is self (the system
 * booted it: drivers, slogger2, the network stack...), unless immune memory says otherwise. Without
 * this, the hunt took high-priority drivers for intruders and killed the OS — an autoimmune disease,
 * observed on QNX 8.0 under QEMU on 19/11/2026. Respawned drivers keep the same hash, so stay self. */
static int tolerate_running(void) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    int added = 0;
    while ((e = readdir(d)) && soi.n < SOI_MAX) {
        char *end;
        long pid = strtol(e->d_name, &end, 10);
        if (*end || pid <= 1 || pid == self_pid) continue;
        uint8_t h[BN_HASH_LEN];
        char name[16] = "?";
        if (soi_hash_pid((pid_t)pid, h, name, sizeof name) != 0) continue;
        if (soi_contains(&soi, h) || soi_contains(&memory, h)) continue;
        memcpy(soi.e[soi.n].hash, h, BN_HASH_LEN);
        snprintf(soi.e[soi.n].path, sizeof soi.e[0].path, "%s (tolerated at start)", name);
        soi.n++;
        added++;
    }
    closedir(d);
    return added;
}

/* STATE -> ACTS: look for foreign processes able to preempt the dispensing loop. */
static int hunt(const char *why) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *e;
    int found = 0;
    while ((e = readdir(d))) {
        char *end;
        long pid = strtol(e->d_name, &end, 10);
        if (*end || pid <= 1 || pid == self_pid || pid == doseur_pid) continue;
        proc_cache *c = lookup((pid_t)pid);
        if (!c) continue;
        int remembered = soi_contains(&memory, c->hash);
        if (!c->foreign && !remembered) continue;
        int prio = top_priority((pid_t)pid);
        if (c->quarantined) {                       /* already held: act again only on relapse */
            if (prio > PRIO_QUARANTINE) { quarantine((pid_t)pid, "priority raised again"); found++; }
            continue;
        }
        if (remembered || prio >= PRIO_DOSEUR) {
            quarantine((pid_t)pid, remembered ? "remembered binary" : why);
            found++;
        }
    }
    closedir(d);
    return found;
}

static void find_doseur(void) {
    if (doseur_coid >= 0) return;
    doseur_coid = name_open(DOSEUR_NAME, 0);
    if (doseur_coid < 0) return;
    struct _server_info si;
    if (ConnectServerInfo(0, doseur_coid, &si) == doseur_coid) doseur_pid = si.pid;
    last_hb = bn_now_mono_ns();
    printf("antitout: watching doseur pid %d\n", (int)doseur_pid);
}

static void safe_stop(void) {
    if (robot_stopped || doseur_coid < 0) return;
    MsgSendPulse(doseur_coid, PRIO_ANTITOUT, CODE_SAFE_STOP, 0);
    robot_stopped = 1;
    clean_since = 0;
    uint32_t pid = (uint32_t)doseur_pid;
    record(BN_T_SAFE_STOP, &pid, sizeof pid);
    printf("antitout: SAFE STOP sent to the dispensing robot\n");
}

static void lock_down(void) {
    /* The supervisor may change priorities and send signals, but may never spawn or fork. */
    procmgr_ability(0,
        PROCMGR_ADN_ROOT | PROCMGR_ADN_NONROOT | PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK | PROCMGR_AID_SPAWN,
        PROCMGR_ADN_ROOT | PROCMGR_ADN_NONROOT | PROCMGR_AOP_DENY | PROCMGR_AOP_LOCK | PROCMGR_AID_FORK,
        PROCMGR_AID_EOL);
}

/* Every pulse except the watch timer. */
static void on_pulse(const struct _pulse *pl) {
    uint64_t now = bn_now_mono_ns();
    switch (pl->code) {
    case _PULSE_CODE_DISCONNECT:
        ConnectDetach(pl->scoid);
        break;
    case CODE_HEARTBEAT: {
        last_hb = now;
        int late = pl->value.sival_int;
        if (late > JITTER_LIMIT_US) {
            if (++bad_jitter >= 3) { hunt("loop lateness"); bad_jitter = 0; }
            clean_since = 0;
        } else {
            bad_jitter = 0;
            if (!clean_since) clean_since = now;
            if (robot_stopped && now - clean_since > 3000000000ull) {   /* 3 s clean: resume */
                MsgSendPulse(doseur_coid, PRIO_ANTITOUT, CODE_RESUME, 0);
                robot_stopped = 0; doses_out = 0;
                uint32_t v[2] = { (uint32_t)soi.n, 1 };
                record(BN_T_RELEASE, v, sizeof v);
                printf("antitout: loop clean for 3 s, robot resumed\n");
            }
        }
        break;
    }
    case CODE_DOSE_OUT: {
        int32_t dev = pl->value.sival_int;
        record(BN_T_DOSE_REFUSED, &dev, sizeof dev);
        printf("antitout: dose out of tolerance (%+.2f %%)\n", dev / 1e4);
        hunt("dose out of tolerance");
        if (++doses_out >= 2) safe_stop();
        break;
    }
    case CODE_MEMBRANE: {
        pid_t pid = pl->value.sival_int;
        bn_immune_payload p = { .pid = (uint32_t)pid };
        uint8_t h[BN_HASH_LEN];
        /* gone already (expelled after an earlier try): the black box journaled the refusal */
        if (soi_hash_pid(pid, h, p.name, sizeof p.name) != 0) break;
        memcpy(p.exe_hash8, h, 8);
        record(BN_T_INTRUDER, &p, sizeof p);
        printf("antitout: INTRUDER %s (pid %d) knocked on the black box\n", p.name, (int)pid);
        quarantine(pid, "membrane refusal");
        break;
    }
    }
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IOLBF, 0);   /* logs reach a file line by line */
    if (getenv("ANTITOUT_HB_MS")) HEARTBEAT_LATE_NS = strtoull(getenv("ANTITOUT_HB_MS"), NULL, 10) * 1000000ull;
    if (argc != 3) { fprintf(stderr, "usage: %s <soi-file> <memory-file>\n", argv[0]); return 2; }
    self_pid = getpid();
    memory_file = argv[2];
    if (soi_load(&soi, argv[1]) != 0 || soi.n == 0) { fprintf(stderr, "antitout: empty self %s\n", argv[1]); return 2; }
    soi_load(&memory, memory_file);              /* may not exist yet */
    struct sched_param sp = { .sched_priority = PRIO_ANTITOUT };
    pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
    lock_down();

    name_attach_t *att = name_attach(NULL, ANTITOUT_NAME, 0);
    if (!att) { perror("antitout: name_attach"); return 1; }
    int self = ConnectAttach(0, 0, att->chid, _NTO_SIDE_CHANNEL, 0);
    struct sigevent ev;
    SIGEV_PULSE_INIT(&ev, self, PRIO_ANTITOUT, CODE_WATCH_TIMER, 0);
    timer_t tid;
    struct itimerspec it = { .it_value = { 0, WATCH_PERIOD_NS }, .it_interval = { 0, WATCH_PERIOD_NS } };
    timer_create(CLOCK_MONOTONIC, &ev, &tid);
    timer_settime(tid, 0, &it, NULL);

    int declared = soi.n, tolerated = tolerate_running();
    uint32_t counts[3] = { (uint32_t)declared, (uint32_t)memory.n, (uint32_t)tolerated };
    record(BN_T_SELF_OK, counts, sizeof counts);
    printf("antitout: self = %d declared + %d tolerated at start, memory = %d quarantined before\n",
           declared, tolerated, memory.n);
    hunt("startup scan");

    union { struct _pulse pulse; uint16_t type; } msg;
    unsigned watch = 0;
    for (;;) {
        int rcvid = MsgReceive(att->chid, &msg, sizeof msg, NULL);
        if (rcvid == -1) { if (errno == EINTR) continue; break; }
        if (rcvid > 0) {
            if (msg.type == _IO_CONNECT) MsgReply(rcvid, EOK, NULL, 0); else MsgError(rcvid, ENOSYS);
            continue;
        }
        if (msg.pulse.code != CODE_WATCH_TIMER) { on_pulse(&msg.pulse); continue; }

        /* Watch timer. Pulses are queued by priority, so this one (50) overtakes heartbeats (40)
         * already waiting behind it, typically after a long hunt. Take what is queued, then judge. */
        struct _pulse q;
        for (;;) {
            uint64_t zero = 0;
            TimerTimeout(CLOCK_MONOTONIC, _NTO_TIMEOUT_RECEIVE, NULL, &zero, NULL);
            if (MsgReceivePulse(att->chid, &q, sizeof q, NULL) == -1) break;   /* queue empty */
            if (q.code == CODE_WATCH_TIMER) watch++; else on_pulse(&q);
        }
        uint64_t now = bn_now_mono_ns();
        find_doseur();
        if (doseur_coid >= 0 && now > last_hb && now - last_hb > HEARTBEAT_LATE_NS && now > incident_until) {
            uint32_t ms = (uint32_t)((now - last_hb) / 1000000);
            record(BN_T_DEADLINE_MISSED, &ms, sizeof ms);
            printf("antitout: no heartbeat for %u ms, hunting\n", ms);
            if (!hunt("missed deadline")) printf("antitout: no foreign culprit found\n");
            incident_until = bn_now_mono_ns() + 200000000ull;
        }
        if (++watch % 100 == 0) hunt("periodic scan");          /* about every second */
    }
    return 0;
}
