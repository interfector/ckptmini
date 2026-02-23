#ifndef CKPTMINI_H
#define CKPTMINI_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>

#include <pmparser.h>

#if defined(__x86_64__)
  #include <sys/user.h>
  typedef struct user_regs_struct regs_t;
#else
  #error "This demo currently targets x86_64 only."
#endif

#define DIE(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)
#define ENSURE(cond, msg) do { if(!(cond)) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE);} } while(0)

#define A_RESET  "\033[0m"
#define A_BOLD   "\033[1m"
#define A_DIM    "\033[2m"
#define A_RED    "\033[31m"
#define A_GREEN  "\033[32m"
#define A_YELLOW "\033[33m"
#define A_CYAN   "\033[36m"
#define A_WHITE  "\033[97m"
#define A_BGBLUE "\033[44m"

#define S_OK "★"
#define S_INFO "◆"
#define S_ERR "⚠"

typedef struct { const char *name; size_t offset; } reg_entry_t;

typedef enum { SETREG_LIVE, SETREG_DUMP } setreg_mode_t;
typedef enum { SHOW_LIVE, SHOW_DUMP } show_mode_t;

typedef struct {
    uint64_t start, end;
    int prot;
    char name[256];
    bool dump;
} region_t;

typedef struct {
    uint64_t start, end;
    int prot;
} saved_map_t;

typedef struct {
    bool (*callback)(uint64_t start, uint64_t end, int prot, const char *pathname, void *arg);
    void *arg;
} pm_iter_ctx_t;

typedef struct { const unsigned char *needle; size_t nlen; const char *seg; uint64_t found; FILE *out_all; } search_ctx_t;

int set_reg_by_name(struct user_regs_struct *regs, const char *name, uint64_t value);
int get_reg_by_name(const struct user_regs_struct *regs, const char *name, uint64_t *out);
int setreg(setreg_mode_t mode, void *target, const char *regname, uint64_t value);

unsigned char* parse_hex(const char *hex, size_t *out_len);
int parse_perms(const char *s);
void mkpath_or_die(const char *p);
void write_all_or_die(int fd, const void *buf, size_t sz);
void read_all_or_die(int fd, void *buf, size_t sz);

bool is_tty(void);
const char *hr_size(uint64_t bytes, char *buf, size_t bufsz);
void hexdump_line(uint64_t base, const unsigned char *buf, size_t len);
void print_timestamp(void);

procmaps_iterator* parse_maps_live(pid_t pid);
procmaps_iterator* parse_maps_dump(const char *indir);
int prot_for_range_live(pid_t pid, uint64_t start, uint64_t end);
void for_each_map_live(pid_t pid, bool (*cb)(uint64_t, uint64_t, int, const char*, void*), void *arg);
void for_each_map_dump(const char *indir, bool (*cb)(uint64_t, uint64_t, int, const char*, void*), void *arg);
bool for_each_mapping(pid_t pid, bool (*cb)(pid_t, uint64_t, uint64_t, const char*, const char*, void*), void *ud);

void save_regs(pid_t pid, const char *dir);
void save_meta(pid_t pid, const char *dir);
void save_maps_and_memory(pid_t pid, const char *dir);
void checkpoint(pid_t pid, const char *outdir);

long remote_syscall_x64(pid_t pid, long nr, unsigned long a1, unsigned long a2, unsigned long a3,
                        unsigned long a4, unsigned long a5, unsigned long a6);
int remote_mmap_fixed(pid_t pid, uint64_t addr, size_t len, int prot, int flags);
int remote_mprotect(pid_t pid, uint64_t addr, size_t len, int prot);

size_t load_saved_maps(const char *dir, saved_map_t **out);
int prot_for_range(saved_map_t *maps, size_t nmaps, uint64_t start, uint64_t end, int defprot);

bool read_bytes_from_pid(pid_t pid, uintptr_t addr, void *data, size_t len);
bool write_bytes_to_pid(pid_t pid, uint64_t addr, const void *buf, size_t len);
bool mem_write_region(pid_t pid, uint64_t addr, const void *data, size_t len);

void load_regs(pid_t pid, const char *dir);
bool map_and_fill_region(pid_t pid, int memfd, uint64_t start, uint64_t end, int prot, const char *binfile);
bool restore_regions(pid_t pid, const char *dir);
void restore_into(pid_t pid, const char *dir);
void relocate_into(pid_t pid, const char *indir);

void show_maps_and_regs(show_mode_t mode, const char *arg);

void cmd_dump(const char *arg);
void cmd_watch(pid_t pid, uint64_t addr, size_t len, unsigned int interval_ms);
void cmd_snapshot_diff(pid_t pid, const char *indir);
void cmd_breakpoint(pid_t pid, uint64_t addr);
void cmd_inject_shellcode(pid_t pid, const char *hex);
void cmd_trace(pid_t pid);
void cmd_mprotect(pid_t pid, uint64_t addr, size_t len, const char *perms_str);
void cmd_backtrace(pid_t pid, bool pause);
void cmd_signals(pid_t pid);
void cmd_fds(pid_t pid);
uintptr_t cmd_call(pid_t pid, uint64_t addr, int argc, char **argv, bool detach);
uintptr_t cmd_call_ret(pid_t pid, uint64_t addr, int argc, char **argv, bool detach, uintptr_t *ret_val);
void cmd_load_so(pid_t pid, const char *so_path);

void spawn_paused_and_print(char **argv);
void spawn_show_then_pause(char **argv, useconds_t run_us);
void stop_pid(pid_t pid);
void cont_pid(pid_t pid);
void step_pid(pid_t pid, int max_steps);

size_t search_all_in_dumped_maps(const char *indir, const unsigned char *needle, size_t nlen, const char *seg, size_t count);
bool mapping_matches_seg_perms(const char *perms, const char *seg);
bool mapping_matches_seg(const char *perms, const char *path, const char *seg);
bool search_bytes_in_map_cb(pid_t pid, uint64_t start, uint64_t end, const char *perms, const char *path, void *ud);

void usage(const char *prog);

#endif
