/* soi.h — the "self": which binaries belong to this machine, identified by SHA3-256. */
#ifndef SOI_H
#define SOI_H
#include <stdint.h>
#include <sys/types.h>
#include "bn_journal.h"

#define SOI_MAX 256
typedef struct { uint8_t hash[BN_HASH_LEN]; char path[128]; } soi_entry;
typedef struct { soi_entry e[SOI_MAX]; int n; } soi_list;

int  soi_load(soi_list *s, const char *file);                 /* lines: <sha3-hex> <path> */
int  soi_hash_file(const char *path, uint8_t out[BN_HASH_LEN]);
/* Hash the executable of a running process (/proc/<pid>/exefile). name: basename, may be NULL. */
int  soi_hash_pid(pid_t pid, uint8_t out[BN_HASH_LEN], char *name, size_t name_len);
int  soi_contains(const soi_list *s, const uint8_t hash[BN_HASH_LEN]);
int  soi_contains_pid(const soi_list *s, pid_t pid);
#endif
