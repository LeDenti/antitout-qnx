#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "soi.h"

static int unhex(uint8_t *out, const char *hx, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hx + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

int soi_load(soi_list *s, const char *file) {
    memset(s, 0, sizeof *s);
    FILE *f = fopen(file, "r");
    if (!f) return -1;
    char line[256], hx[65], path[128];
    while (fgets(line, sizeof line, f) && s->n < SOI_MAX) {
        if (line[0] == '#' || sscanf(line, "%64s %127s", hx, path) != 2) continue;
        if (unhex(s->e[s->n].hash, hx, BN_HASH_LEN) == 0) {
            snprintf(s->e[s->n].path, sizeof s->e[s->n].path, "%s", path);
            s->n++;
        }
    }
    fclose(f);
    return 0;
}

int soi_hash_file(const char *path, uint8_t out[BN_HASH_LEN]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) || st.st_size <= 0 || st.st_size > (64 << 20)) { close(fd); return -1; }
    uint8_t *buf = malloc((size_t)st.st_size);
    ssize_t r = buf ? read(fd, buf, (size_t)st.st_size) : -1;
    close(fd);
    if (r != st.st_size) { free(buf); return -1; }
    bn_sha3_256(out, buf, (size_t)st.st_size);
    free(buf);
    return 0;
}

int soi_hash_pid(pid_t pid, uint8_t out[BN_HASH_LEN], char *name, size_t name_len) {
    char p[64], exe[256] = {0};
    snprintf(p, sizeof p, "/proc/%d/exefile", (int)pid);
    int fd = open(p, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, exe, sizeof exe - 1);
    close(fd);
    if (n <= 0) return -1;
    exe[n] = 0;
    char *nl = strchr(exe, '\n'); if (nl) *nl = 0;
    if (name && name_len) {
        const char *b = strrchr(exe, '/');
        snprintf(name, name_len, "%s", b ? b + 1 : exe);
    }
    return soi_hash_file(exe, out);
}

int soi_contains(const soi_list *s, const uint8_t hash[BN_HASH_LEN]) {
    for (int i = 0; i < s->n; i++) if (!memcmp(s->e[i].hash, hash, BN_HASH_LEN)) return 1;
    return 0;
}

int soi_contains_pid(const soi_list *s, pid_t pid) {
    uint8_t h[BN_HASH_LEN];
    return soi_hash_pid(pid, h, NULL, 0) == 0 && soi_contains(s, h);
}
