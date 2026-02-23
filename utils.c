#include "ckptmini.h"

bool g_is_tty = false;

static const reg_entry_t reg_table[] = {
    { "r15", 0x00 },
    { "r14", 0x08 },
    { "r13", 0x10 },
    { "r12", 0x18 },
    { "rbp", 0x20 },
    { "rbx", 0x28 },
    { "r11", 0x30 },
    { "r10", 0x38 },
    { "r9",  0x40 },
    { "r8",  0x48 },
    { "rax", 0x50 },
    { "rcx", 0x58 },
    { "rdx", 0x60 },
    { "rsi", 0x68 },
    { "rdi", 0x70 },
    { "rip", 0x80 },
    { "rsp", 0x98 },
};
#define REG_TABLE_SIZE (sizeof(reg_table)/sizeof(reg_table[0]))

static const reg_entry_t* find_reg(const char *name) {
    for (size_t i = 0; i < REG_TABLE_SIZE; ++i) {
        if (!strcasecmp(name, reg_table[i].name)) {
            return &reg_table[i];
        }
    }
    return NULL;
}

int set_reg_by_name(struct user_regs_struct *regs, const char *name, uint64_t value) {
    const reg_entry_t *entry = find_reg(name);
    if (!entry) return -1;
    *(uint64_t *)((char*)regs + entry->offset) = value;
    return 0;
}

int get_reg_by_name(const struct user_regs_struct *regs, const char *name, uint64_t *out) {
    const reg_entry_t *entry = find_reg(name);
    if (!entry) return -1;
    *out = *(uint64_t *)((const char*)regs + entry->offset);
    return 0;
}

int setreg(setreg_mode_t mode, void *target, const char *regname, uint64_t value) {
    struct user_regs_struct regs;
    int ret = 0;
    if (mode == SETREG_LIVE) {
        pid_t pid = *(pid_t*)target;
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) { perror("PTRACE_ATTACH"); return -1; }
        waitpid(pid, NULL, 0);
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) { perror("PTRACE_GETREGS"); ptrace(PTRACE_DETACH, pid, NULL, NULL); return -1; }
    } else {
        const char *indir = (const char*)target;
        char rpath[512]; snprintf(rpath, sizeof(rpath), "%s/regs.bin", indir);
        FILE *rf = fopen(rpath, "rb+");
        if (!rf) { perror("fopen regs.bin"); return -1; }
        if (fread(&regs, 1, sizeof(regs), rf) != sizeof(regs)) { perror("fread regs.bin"); fclose(rf); return -1; }
        fclose(rf);
    }
    uint64_t oldval = 0;
    if (get_reg_by_name(&regs, regname, &oldval) != 0) {
        fprintf(stderr, "Unknown register: %s\n", regname);
        if (mode == SETREG_LIVE) ptrace(PTRACE_DETACH, *(pid_t*)target, NULL, NULL);
        return -1;
    }
    if (set_reg_by_name(&regs, regname, value) != 0) {
        fprintf(stderr, "Unknown register: %s\n", regname);
        if (mode == SETREG_LIVE) ptrace(PTRACE_DETACH, *(pid_t*)target, NULL, NULL);
        return -1;
    }
    fprintf(stderr, "[setreg] %s: 0x%016llx -> 0x%016llx\n", regname, (unsigned long long)oldval, (unsigned long long)value);
    if (mode == SETREG_LIVE) {
        pid_t pid = *(pid_t*)target;
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) { perror("PTRACE_SETREGS"); ptrace(PTRACE_DETACH, pid, NULL, NULL); return -1; }
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    } else {
        const char *indir = (const char*)target;
        char rpath[512]; snprintf(rpath, sizeof(rpath), "%s/regs.bin", indir);
        FILE *rf = fopen(rpath, "rb+");
        if (!rf) { perror("fopen regs.bin"); return -1; }
        rewind(rf);
        if (fwrite(&regs, 1, sizeof(regs), rf) != sizeof(regs)) { perror("fwrite regs.bin"); fclose(rf); return -1; }
        fclose(rf);
    }
    return ret;
}

unsigned char* parse_hex(const char *hex, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return NULL;
    size_t bin_len = len / 2;
    unsigned char *bin = (unsigned char*)malloc(bin_len);
    for (size_t i = 0; i < bin_len; i++) {
        char tmp[3] = { hex[2*i], hex[2*i+1], 0 };
        bin[i] = (unsigned char)strtoul(tmp, NULL, 16);
    }
    if (out_len) *out_len = bin_len;
    return bin;
}

void mkpath_or_die(const char *p) {
    struct stat st;
    if (stat(p, &st) == 0) return;
    if (mkdir(p, 0755) != 0) DIE("mkdir");
}

void write_all_or_die(int fd, const void *buf, size_t sz) {
    const char *p = (const char*)buf; size_t w=0; ssize_t n;
    while (w < sz) { n = write(fd, p+w, sz-w); if (n < 0) DIE("write"); w += (size_t)n; }
}

void read_all_or_die(int fd, void *buf, size_t sz) {
    char *p = (char*)buf; size_t r=0; ssize_t n;
    while (r < sz) { n = read(fd, p+r, sz-r); if (n <= 0) DIE("read"); r += (size_t)n; }
}

bool is_tty(void) { return isatty(STDOUT_FILENO); }

const char *hr_size(uint64_t bytes, char *buf, size_t bufsz) {
    if      (bytes >= 1024ULL*1024*1024) snprintf(buf, bufsz, "%.1fG", (double)bytes/(1024.0*1024*1024));
    else if (bytes >= 1024ULL*1024)      snprintf(buf, bufsz, "%.1fM", (double)bytes/(1024.0*1024));
    else if (bytes >= 1024ULL)           snprintf(buf, bufsz, "%.1fK", (double)bytes/1024.0);
    else                                 snprintf(buf, bufsz, "%lluB",  (unsigned long long)bytes);
    return buf;
}

void hexdump_line(uint64_t base, const unsigned char *buf, size_t len) {
    printf("  %016llx  ", (unsigned long long)base);
    for (size_t i = 0; i < 16; i++) {
        if (i < len) printf("%02x ", buf[i]); else printf("   ");
        if (i == 7) printf(" ");
    }
    printf(" |");
    for (size_t i = 0; i < len; i++)
        putchar(buf[i] >= 0x20 && buf[i] < 0x7f ? buf[i] : '.');
    for (size_t i = len; i < 16; i++) putchar(' ');
    printf("|\n");
}

void print_timestamp(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm *t = localtime(&ts.tv_sec);
    char buf[32];
    strftime(buf, sizeof(buf), "%H:%M:%S", t);
    printf("[%s.%03ld] ", buf, ts.tv_nsec / 1000000L);
}

int parse_perms(const char *s) {
    int prot = 0;
    if (s[0] == 'r') prot |= PROT_READ;
    if (s[1] == 'w') prot |= PROT_WRITE;
    if (s[2] == 'x') prot |= PROT_EXEC;
    return prot;
}

static bool region_is_minimal_target_pm(const procmaps_struct *map) {
    if (!map->is_r) return false;
    if (map->map_type == PROCMAPS_MAP_HEAP || map->map_type == PROCMAPS_MAP_STACK ||
        map->map_type == PROCMAPS_MAP_STACK_TID) return true;
    return true;
}

procmaps_iterator* parse_maps_live(pid_t pid) {
    procmaps_iterator *it = (procmaps_iterator*)calloc(1, sizeof(procmaps_iterator));
    if (pmparser_parse(pid, it) != PROCMAPS_SUCCESS) {
        free(it);
        return NULL;
    }
    return it;
}

procmaps_iterator* parse_maps_dump(const char *indir) {
    char maps_path[512];
    snprintf(maps_path, sizeof(maps_path), "%s/maps.txt", indir);
    procmaps_iterator *it = (procmaps_iterator*)calloc(1, sizeof(procmaps_iterator));
    if (pmparser_parse_file(maps_path, it) != PROCMAPS_SUCCESS) {
        free(it);
        return NULL;
    }
    return it;
}

int prot_for_range_live(pid_t pid, uint64_t start, uint64_t end) {
    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) return 0;
    procmaps_struct *map;
    int prot = 0;
    while ((map = pmparser_next(it)) != NULL) {
        if ((uint64_t)map->addr_start <= start && (uint64_t)map->addr_end >= end) {
            prot = pmparser_get_prot(map);
            break;
        }
    }
    pmparser_free(it);
    return prot;
}

static bool pm_iter_wrapper(procmaps_struct *map, void *arg) {
    pm_iter_ctx_t *ctx = (pm_iter_ctx_t *)arg;
    return ctx->callback((uint64_t)map->addr_start, (uint64_t)map->addr_end,
                         pmparser_get_prot(map), map->pathname, ctx->arg);
}

void for_each_map_live(pid_t pid, bool (*cb)(uint64_t start, uint64_t end, int prot, const char *pathname, void *arg), void *arg) {
    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) return;
    pm_iter_ctx_t ctx = { .callback = cb, .arg = arg };
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        if (!pm_iter_wrapper(map, &ctx)) break;
    }
    pmparser_free(it);
}

void for_each_map_dump(const char *indir, bool (*cb)(uint64_t start, uint64_t end, int prot, const char *pathname, void *arg), void *arg) {
    procmaps_iterator *it = parse_maps_dump(indir);
    if (!it) return;
    pm_iter_ctx_t ctx = { .callback = cb, .arg = arg };
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        if (!pm_iter_wrapper(map, &ctx)) break;
    }
    pmparser_free(it);
}

bool for_each_mapping(pid_t pid, bool (*cb)(pid_t, uint64_t, uint64_t, const char*, const char*, void*), void *ud) {
    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) return false;
    procmaps_struct *map;
    char perms[5];
    while ((map = pmparser_next(it)) != NULL) {
        get_perms_string(map, perms);
        if (!cb(pid, (uint64_t)map->addr_start, (uint64_t)map->addr_end, perms, map->pathname ? map->pathname : "", ud)) {
            pmparser_free(it);
            return true;
        }
    }
    pmparser_free(it);
    return true;
}

bool mapping_matches_seg_perms(const char *perms, const char *seg) {
    if (!seg || !seg[0] || !strcmp(seg, "any")) return true;
    bool is_text = (perms[2] == 'x');
    bool is_data = (perms[2] != 'x') && (perms[1] == 'w' || perms[0] == 'r');
    if (!strcmp(seg, "text")) return is_text;
    if (!strcmp(seg, "data")) return is_data;
    return true;
}

void get_perms_string(const procmaps_struct *map, char *perms) {
    perms[0] = map->is_r ? 'r' : '-';
    perms[1] = map->is_w ? 'w' : '-';
    perms[2] = map->is_x ? 'x' : '-';
    perms[3] = map->is_p ? 'p' : '-';
    perms[4] = '\0';
}

bool mapping_matches_seg(const char *perms, const char *path, const char *seg) {
    if (!seg || !seg[0] || !strcmp(seg, "any")) return true;
    bool is_text = (perms[2] == 'x');
    bool is_data = (perms[2] != 'x') && (perms[1] == 'w' || perms[0] == 'r');
    if (!strcmp(seg, "text")) return is_text;
    if (!strcmp(seg, "data")) return is_data;
    return true;
}

bool read_bytes_from_pid(pid_t pid, uintptr_t addr, void *data, size_t len) {
    struct iovec local = { .iov_base = data, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = len };
    ssize_t n = process_vm_readv(pid, &local, 1, &remote, 1, 0);
    if (n >= 0 && (size_t)n == len) return true;
    int memfd = get_memfd(pid, O_RDONLY);
    if (memfd < 0) return false;
    n = pread(memfd, data, len, (off_t)addr);
    close(memfd);
    return (n >= 0 && (size_t)n == len);
}

bool write_bytes_to_pid(pid_t pid, uint64_t addr, const void *buf, size_t len) {
    struct iovec local = { .iov_base = (void*)buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)addr, .iov_len = len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n >= 0 && (size_t)n == len) return true;
    int memfd = get_memfd(pid, O_RDWR);
    if (memfd < 0) return false;
    n = pwrite(memfd, buf, len, (off_t)addr);
    close(memfd);
    return (n >= 0 && (size_t)n == len);
}

int get_memfd(pid_t pid, int flags) {
    char memp[256];
    snprintf(memp, sizeof(memp), "/proc/%d/mem", pid);
    return open(memp, flags);
}

static size_t dump_bytes_from_mem(pid_t pid, int memfd, uint64_t start, void *buf, size_t len) {
    (void)pid;
    ssize_t n = pread(memfd, buf, len, (off_t)start);
    if (n < 0) {
        fprintf(stderr, "[warn] pread mem failed at 0x%llx (len=0x%zx): %s\n",
                (unsigned long long)start, len, strerror(errno));
        memset(buf, 0, len);
        return 0;
    }
    return (size_t)n;
}

static size_t dump_region_bin(const char *dir, const region_t *rg, const void *data, size_t len) {
    char name[512]; snprintf(name, sizeof(name), "%s/mem/%016llx-%016llx.bin", dir,
                             (unsigned long long)rg->start, (unsigned long long)rg->end);
    int fd = open(name, O_CREAT|O_TRUNC|O_WRONLY, 0644); if (fd < 0) DIE("open mem bin");
    write_all_or_die(fd, data, len);
    close(fd);
    return len;
}

void save_maps_and_memory(pid_t pid, const char *dir) {
    char maps_out[512]; snprintf(maps_out, sizeof(maps_out), "%s/maps.txt", dir);
    FILE *fout = fopen(maps_out, "w"); if (!fout) DIE("fopen maps.txt");

    char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", dir); mkpath_or_die(memdir);

    char mem_p[256]; snprintf(mem_p, sizeof(mem_p), "/proc/%d/mem", pid);
    int memfd = open(mem_p, O_RDONLY); if (memfd < 0) DIE("open /proc/pid/mem");

    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) DIE("parse_maps_live");
    procmaps_struct *map;
    char line[1024];
    while ((map = pmparser_next(it)) != NULL) {
        snprintf(line, sizeof(line), "%lx-%lx %c%c%c%c %lx %x:%x %llu %s\n",
                 (unsigned long)map->addr_start, (unsigned long)map->addr_end,
                 map->is_r ? 'r' : '-', map->is_w ? 'w' : '-', map->is_x ? 'x' : '-', map->is_p ? 'p' : '-',
                 (unsigned long)map->offset, map->dev_major, map->dev_minor,
                 map->inode, map->pathname ? map->pathname : "");
        fputs(line, fout);

        bool dumpit = region_is_minimal_target_pm(map);
        if (!dumpit) continue;

        size_t len = map->length;
        void *buf = malloc(len);
        size_t got = dump_bytes_from_mem(pid, memfd, (uint64_t)map->addr_start, buf, len);
        if (got == 0) {
            free(buf);
            continue;
        }
        if (got != len) {
            memset((char*)buf + got, 0, len - got);
        }

        region_t rg = { .start = (uint64_t)map->addr_start, .end = (uint64_t)map->addr_end, .prot = pmparser_get_prot(map), .dump = true };
        if (map->pathname) strncpy(rg.name, map->pathname, sizeof(rg.name)-1);
        dump_region_bin(dir, &rg, buf, len);
        free(buf);
    }
    pmparser_free(it);
    close(memfd);
    fclose(fout);
}

int find_chunk_for_addr(const char *memdir, uint64_t addr, size_t len, char *path, size_t path_sz, off_t *out_offset) {
    DIR *d = opendir(memdir);
    if (!d) return -1;
    struct dirent *de;
    int result = -1;
    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.') continue;
        unsigned long long s = 0, e = 0;
        if (sscanf(de->d_name, "%16llx-%16llx.bin", &s, &e) != 2) continue;
        if (s <= addr && addr + len <= e) {
            snprintf(path, path_sz, "%s/%s", memdir, de->d_name);
            *out_offset = (off_t)(addr - s);
            result = 0;
            break;
        }
    }
    closedir(d);
    return result;
}

void usage(const char *prog) {
    
    if (g_is_tty) fprintf(stderr, A_BOLD A_CYAN);
    fprintf(stderr, "\n  %s ckptmini - Process checkpoint/restore tool\n\n" A_RESET, prog);
    
    fprintf(stderr, A_WHITE A_BOLD "  %s\n", "Core Commands:" A_RESET);
    fprintf(stderr, "  %-24s %s\n", "save <pid> <outdir>", "Save process memory & regs to directory");
    fprintf(stderr, "  %-24s %s\n", "restore <pid> <dir>", "Restore saved state to process");
    fprintf(stderr, "  %-24s %s\n", "dump <pid|dir>", "Show memory regions with colors");
    fprintf(stderr, "  %-24s %s\n", "show <pid>", "Show maps and registers");
    fprintf(stderr, "  %-24s %s\n", "show_dump <dir>", "Show saved maps and registers");
    
    fprintf(stderr, A_WHITE A_BOLD "\n  %s\n" A_RESET, "Process Control:");
    fprintf(stderr, "  %-24s %s\n", "spawn <prog> [args]", "Launch program paused for restore");
    fprintf(stderr, "  %-24s %s\n", "spawn_show <prog>", "Spawn and show initial state");
    fprintf(stderr, "  %-24s %s\n", "resume <pid>", "Continue stopped process");
    fprintf(stderr, "  %-24s %s\n", "stop <pid>", "Stop process with SIGSTOP");
    fprintf(stderr, "  %-24s %s\n", "step <pid> [n]", "Step N instructions");
    fprintf(stderr, "  %-24s %s\n", "trace <pid>", "Single-step and print instructions");
    
    fprintf(stderr, A_WHITE A_BOLD "\n  %s\n" A_RESET, "Breakpoints:");
    fprintf(stderr, "  %-24s %s\n", "breakpoint <pid> <addr>", "Set execution breakpoint");
    fprintf(stderr, "  %-24s %s\n", "inject_shellcode <pid>", "Inject and run shellcode");
    
    fprintf(stderr, A_WHITE A_BOLD "\n  %s\n" A_RESET, "Memory Operations:");
    fprintf(stderr, "  %-24s %s\n", "read <pid> <addr> <len>", "Read memory (hexdump)");
    fprintf(stderr, "  %-24s %s\n", "write <pid> <addr> <hex>", "Write hex bytes to memory");
    fprintf(stderr, "  %-24s %s\n", "write_str <pid> <addr>", "Write string to memory");
    fprintf(stderr, "  %-24s %s\n", "read_dump <dir> <addr>", "Read from saved dump");
    fprintf(stderr, "  %-24s %s\n", "write_dump <dir> <addr>", "Write hex to saved dump");
    fprintf(stderr, "  %-24s %s\n", "write_dump_str <dir>", "Write string to saved dump");
    fprintf(stderr, "  %-24s %s\n", "mprotect <pid> <addr>", "Change memory protections");
    
    fprintf(stderr, A_WHITE A_BOLD "\n  %s\n" A_RESET, "Search:");
    fprintf(stderr, "  %-24s %s\n", "search_str <pid> <text>", "Search for string in memory");
    fprintf(stderr, "  %-24s %s\n", "search_bytes <pid> <hex>", "Search for bytes in memory");
    fprintf(stderr, "  %-24s %s\n", "search_all_str <pid> <text>", "Find all string occurrences");
    fprintf(stderr, "  %-24s %s\n", "search_all_bytes <pid>", "Find all byte occurrences");
    fprintf(stderr, "  %-24s %s\n", "search_dump_str <dir>", "Search in saved dump");
    fprintf(stderr, "  %-24s %s\n", "search_dump_bytes <dir>", "Search bytes in saved dump");
    fprintf(stderr, "  %-24s %s\n", "search_dump_all_str <dir>", "Find all in dump");
    fprintf(stderr, "  %-24s %s\n", "search_dump_all_bytes", "Find all bytes in dump");
    
    fprintf(stderr, A_WHITE A_BOLD "\n  %s\n" A_RESET, "Info:");
    fprintf(stderr, "  %-24s %s\n", "backtrace <pid>", "Show stack trace");
    fprintf(stderr, "  %-24s %s\n", "signals <pid>", "Show pending signals");
    fprintf(stderr, "  %-24s %s\n", "fds <pid>", "Show open file descriptors");
    fprintf(stderr, "  %-24s %s\n", "snapshot_diff <pid> <dir>", "Diff current vs saved memory");
    
    fprintf(stderr, A_WHITE A_BOLD "\n  %s\n" A_RESET, "Advanced:");
    fprintf(stderr, "  %-24s %s\n", "call <pid> <addr> [args]", "Call function in target");
    fprintf(stderr, "  %-24s %s\n", "load_so <pid> <path>", "Load shared library in process");
    fprintf(stderr, "  %-24s %s\n", "relocate <pid> <dir>", "Restore with address relocation");
    fprintf(stderr, "  %-24s %s\n", "replay <prog> <dir>", "Spawn and restore (bypass ASLR)");
    fprintf(stderr, "  %-24s %s\n", "setreg <pid> <name>", "Set register value");
    fprintf(stderr, "  %-24s %s\n", "setreg_dump <dir> <name>", "Set register in saved dump");
    fprintf(stderr, "  %-24s %s\n", "watch <pid> <addr>", "Watch memory changes");
}
