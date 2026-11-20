/* intrus — demonstration attacker. Not part of the self: its hash is not in soi.conf.
 *
 *   intrus cpu <seconds>            busy loop at SCHED_FIFO 45, above the dispensing loop
 *   intrus cpu-relapse <seconds>    same, and raises its priority back every 500 ms
 *   intrus write                    tries to write a fake event into /dev/boitenoire
 *   intrus prescribe <drug> <mg>    sends a prescription to the robot (try a x10 dose)
 *   intrus tamper <journal> <byte>  flips one byte of the journal file
 *   intrus forge <journal> <seq>    rewrites event <seq>: delivered dose x10 (hide an overdose)
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/dispatch.h>
#include <sys/neutrino.h>
#include <unistd.h>
#include "bn_qnx.h"

static int set_prio(int p) {
    struct sched_param sp = { .sched_priority = p };
    return pthread_setschedparam(pthread_self(), SCHED_FIFO, &sp);
}
static int get_prio(void) {
    struct sched_param sp; int pol;
    pthread_getschedparam(pthread_self(), &pol, &sp);
    return sp.sched_priority;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "see the header of intrus.c for usage\n"); return 2; }
    if (!strncmp(argv[1], "cpu", 3) && argc == 3) {
        int relapse = !strcmp(argv[1], "cpu-relapse");
        uint64_t end = bn_now_mono_ns() + (uint64_t)atoi(argv[2]) * 1000000000ull, next = 0;
        set_prio(45);
        printf("intrus: spinning at priority 45 for %s s\n", argv[2]);
        fflush(stdout);
        volatile uint64_t x = 0;
        while (bn_now_mono_ns() < end) {
            x++;
            if (relapse && bn_now_mono_ns() > next) { if (get_prio() < 45) set_prio(45); next = bn_now_mono_ns() + 500000000ull; }
        }
        printf("intrus: done, my priority is now %d\n", get_prio());
        return 0;
    }
    if (!strcmp(argv[1], "write")) {                   /* a real attacker insists: 5 tries */
        for (int i = 0; i < 5; i++) {
            int fd = open(BN_DEVICE, O_WRONLY);
            if (fd >= 0) {
                bn_write_msg w = { .type = BN_T_DOSE_DELIVERED };
                printf("intrus: write returned %zd\n", write(fd, &w, sizeof w));
                close(fd);
                return 0;
            }
            printf("intrus: open %s for writing: %s\n", BN_DEVICE, strerror(errno));
            usleep(300000);
        }
        return 1;
    }
    if (!strcmp(argv[1], "forge") && argc == 4) {     /* rewrite history: x10 the delivered dose of event seq */
        int fd = open(argv[2], O_RDWR);
        if (fd < 0) { perror("intrus: open journal"); return 1; }
        unsigned long long want = strtoull(argv[3], NULL, 10);
        unsigned char h[12], b[24];
        off_t at = 0;
        while (pread(fd, h, 12, at) == 12) {
            uint32_t len = h[8] | h[9] << 8 | h[10] << 16 | (uint32_t)h[11] << 24;
            uint16_t kind = h[4] | h[5] << 8;
            if (kind == BN_K_EVENT && pread(fd, b, 24, at + 12) == 24) {
                unsigned long long seq = 0;
                for (int i = 7; i >= 0; i--) seq = seq << 8 | b[i];
                if (seq == want) {
                    off_t f = at + 12 + 24 + 20;       /* payload.delivered_mg_x100 */
                    uint32_t v;
                    pread(fd, &v, 4, f);
                    uint32_t forged = v * 10;
                    pwrite(fd, &forged, 4, f);
                    close(fd);
                    printf("intrus: event #%llu now says %.2f mg delivered instead of %.2f mg\n",
                           want, forged / 100.0, v / 100.0);
                    return 0;
                }
            }
            at += 12 + len;
        }
        close(fd);
        printf("intrus: event #%llu not found\n", want);
        return 1;
    }
    if (!strcmp(argv[1], "prescribe") && argc == 4) {
        int coid = name_open(DOSEUR_NAME, 0);
        if (coid < 0) { perror("intrus: name_open"); return 1; }
        bn_prescribe_msg m = { .type = MSG_PRESCRIBE, .dose_mg = (uint32_t)atoi(argv[3]) };
        snprintf(m.drug, sizeof m.drug, "%s", argv[2]);
        if (MsgSend(coid, &m, sizeof m, NULL, 0) == -1) printf("intrus: prescription refused: %s\n", strerror(errno));
        else printf("intrus: prescription accepted\n");
        return 0;
    }
    if (!strcmp(argv[1], "tamper") && argc == 4) {
        int fd = open(argv[2], O_RDWR);
        if (fd < 0) { perror("intrus: open journal"); return 1; }
        off_t at = atol(argv[3]);
        unsigned char b;
        if (pread(fd, &b, 1, at) != 1) { perror("intrus: pread"); return 1; }
        b ^= 0x01;
        pwrite(fd, &b, 1, at);
        close(fd);
        printf("intrus: flipped byte %lld of %s\n", (long long)at, argv[2]);
        return 0;
    }
    fprintf(stderr, "see the header of intrus.c for usage\n");
    return 2;
}
