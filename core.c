#include "ckptmini.h"

void save_regs(pid_t pid, const char *dir) {
    char pth[512]; snprintf(pth, sizeof(pth), "%s/regs.bin", dir);
    int fd = open(pth, O_CREAT|O_TRUNC|O_WRONLY, 0644); if (fd < 0) DIE("open regs.bin");
    regs_t r; if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) DIE("PTRACE_GETREGS");
    write_all_or_die(fd, &r, sizeof(r));
    close(fd);
}

void save_meta(pid_t pid, const char *dir) {
    char pth[512];
    snprintf(pth, sizeof(pth), "%s/cmdline", dir);
    int fd = open(pth, O_CREAT|O_TRUNC|O_WRONLY, 0644); if (fd < 0) DIE("open cmdline");
    char proc[256]; snprintf(proc, sizeof(proc), "/proc/%d/cmdline", pid);
    int sfd = open(proc, O_RDONLY); if (sfd >= 0) {
        char buf[4096]; ssize_t n = read(sfd, buf, sizeof(buf)); if (n>0) write_all_or_die(fd, buf, (size_t)n);
        close(sfd);
    }
    close(fd);
    snprintf(pth, sizeof(pth), "%s/environ", dir);
    fd = open(pth, O_CREAT|O_TRUNC|O_WRONLY, 0644); if (fd < 0) DIE("open environ");
    snprintf(proc, sizeof(proc), "/proc/%d/environ", pid);
    sfd = open(proc, O_RDONLY); if (sfd >= 0) {
        char buf[65536]; ssize_t n = read(sfd, buf, sizeof(buf)); if (n>0) write_all_or_die(fd, buf, (size_t)n);
        close(sfd);
    }
    close(fd);
}

void checkpoint(pid_t pid, const char *outdir) {
    mkpath_or_die(outdir);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) DIE("PTRACE_ATTACH");
    waitpid(pid, NULL, 0);

    save_meta(pid, outdir);
    save_regs(pid, outdir);
    save_maps_and_memory(pid, outdir);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) DIE("PTRACE_DETACH");
    fprintf(stderr, "[ckpt] saved to %s\n", outdir);
}

/**
 * @brief Execute syscall in remote process using ptrace
 * 
 * This function executes a syscall in the target process by:
 * 1. Saving the original instruction at RIP
 * 2. Replacing it with "syscall; int3" (0x0f05 + 0xcc = 0xCC050F...)
 *    The int3 (0xCC) creates a breakpoint trap that stops execution
 * 3. Setting register values to syscall number and arguments
 * 4. Running the process until it hits the breakpoint
 * 5. Reading the return value from RAX
 * 6. Restoring the original instruction and registers
 * 
 * Note: This modifies the target process's memory temporarily!
 */
long remote_syscall_x64(pid_t pid, long nr,
                       unsigned long a1, unsigned long a2, unsigned long a3,
                       unsigned long a4, unsigned long a5, unsigned long a6) {
    regs_t saved, regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &saved) == -1) DIE("PTRACE_GETREGS remote_syscall");
    regs = saved;

    /* Save original instruction at RIP so we can restore it later */
    errno = 0;
    unsigned long orig_word = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip, NULL);
    if (orig_word == (unsigned long)-1 && errno) DIE("PTRACE_PEEKTEXT");

    /* 
     * Create syscall trap: "syscall; int3"
     *  - 0x0f05 = syscall instruction (x86_64)
     *  - 0xcc = int3 (breakpoint)
     * We keep upper bytes (likely REX prefix) and replace lower 3 bytes
     */
    unsigned long inj = orig_word;
    inj &= ~0xFFFFFFUL;  /* Clear lower 3 bytes */
    inj |= 0xCC050FUL;   /* syscall; int3 */
    if (ptrace(PTRACE_POKETEXT, pid, (void*)regs.rip, (void*)inj) == -1) DIE("PTRACE_POKETEXT");

    /* Set syscall number in RAX, arguments in RDI, RSI, RDX, R10, R8, R9 */
    regs.rax = (unsigned long)nr;
    regs.rdi = a1;
    regs.rsi = a2;
    regs.rdx = a3;
    regs.r10 = a4;
    regs.r8  = a5;
    regs.r9  = a6;
    #if defined(__x86_64__)
    regs.orig_rax = -1;
    #endif
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) DIE("PTRACE_SETREGS remote_syscall");

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) DIE("PTRACE_CONT remote_syscall");
    int status;
    if (waitpid(pid, &status, __WALL) == -1) DIE("waitpid remote_syscall");
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[remote_syscall] unexpected stop: status=0x%x\n", status);
    }

    regs_t after;
    if (ptrace(PTRACE_GETREGS, pid, 0, &after) == -1) DIE("PTRACE_GETREGS after syscall");
    long ret = (long)after.rax;

    if (ptrace(PTRACE_POKETEXT, pid, (void*)saved.rip, (void*)orig_word) == -1) DIE("restore POKETEXT");
    if (ptrace(PTRACE_SETREGS, pid, 0, &saved) == -1) DIE("restore SETREGS");

    return ret;
}

int remote_mmap_fixed(pid_t pid, uint64_t addr, size_t len, int prot, int flags) {
    long ret = remote_syscall_x64(pid, __NR_mmap,
                                  (unsigned long)addr,
                                  (unsigned long)len,
                                  (unsigned long)prot,
                                  (unsigned long)flags,
                                  (unsigned long)-1,
                                  0);
    if (ret < 0) {
        fprintf(stderr, "[remote_mmap] mmap(%016llx,%zu,0x%x,0x%x) -> %ld (%s)\n",
                (unsigned long long)addr, len, prot, flags, ret, strerror((int)-ret));
        return -1;
    }
    if ((uint64_t)ret != addr) {
        fprintf(stderr, "[remote_mmap] returned addr 0x%lx differs from requested 0x%llx\n",
                (unsigned long)ret, (unsigned long long)addr);
        return -1;
    }
    return 0;
}

int remote_mprotect(pid_t pid, uint64_t addr, size_t len, int prot) {
    long ret = remote_syscall_x64(pid, __NR_mprotect,
                                  (unsigned long)addr,
                                  (unsigned long)len,
                                  (unsigned long)prot,
                                  0, 0, 0);
    if (ret < 0) {
        fprintf(stderr, "[remote_mprotect] mprotect(%016llx,%zu,0x%x) -> %ld (%s)\n",
                (unsigned long long)addr, len, prot, ret, strerror((int)-ret));
        return -1;
    }
    return 0;
}

size_t load_saved_maps(const char *dir, saved_map_t **out) {
    *out = NULL; size_t cap = 0, count = 0;
    procmaps_iterator *it = parse_maps_dump(dir);
    if (!it) return 0;
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        if (count == cap) { cap = cap ? cap * 2 : 64; *out = (saved_map_t*)realloc(*out, cap * sizeof(**out)); }
        (*out)[count].start = (uint64_t)map->addr_start;
        (*out)[count].end   = (uint64_t)map->addr_end;
        (*out)[count].prot  = pmparser_get_prot(map);
        count++;
    }
    pmparser_free(it);
    return count;
}

int prot_for_range(saved_map_t *maps, size_t nmaps, uint64_t start, uint64_t end, int defprot) {
    for (size_t i=0;i<nmaps;i++) {
        if (maps[i].start <= start && maps[i].end >= end) return maps[i].prot;
    }
    return defprot;
}

static int live_maps_prot_for_range(pid_t pid, uint64_t start, uint64_t end, int *out_prot) {
    *out_prot = prot_for_range_live(pid, start, end);
    return (*out_prot != 0) ? 0 : -1;
}

bool mem_write_region(pid_t pid, uint64_t addr, const void *data, size_t len) {
    int prot = 0;
    if (live_maps_prot_for_range(pid, addr, addr + len, &prot) != 0) {
        fprintf(stderr, "[mw] address range %016llx-%016llx not mapped in pid %d\n",
                (unsigned long long)addr, (unsigned long long)(addr+len), (int)pid);
        return false;
    }
    bool need_temp = (prot & PROT_WRITE) == 0;
    if (need_temp) {
        if (remote_mprotect(pid, addr, len, prot | PROT_WRITE) != 0) {
            fprintf(stderr, "[mw] temp mprotect RW failed for %016llx-%016llx\n",
                    (unsigned long long)addr, (unsigned long long)(addr+len));
            return false;
        }
    }
    bool ok = write_bytes_to_pid(pid, addr, data, len);
    if (!ok) perror("process write");
    if (need_temp) (void)remote_mprotect(pid, addr, len, prot);
    return ok;
}

void load_regs(pid_t pid, const char *dir) {
    char pth[512]; snprintf(pth, sizeof(pth), "%s/regs.bin", dir);
    int fd = open(pth, O_RDONLY); if (fd < 0) DIE("open regs.bin");
    regs_t r; read_all_or_die(fd, &r, sizeof(r)); close(fd);

#if defined(__x86_64__)
    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) DIE("parse_maps_live in load_regs");

    bool rip_ok = false, rsp_ok = false;
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        if ((uint64_t)map->addr_start <= r.rip && (uint64_t)map->addr_end > r.rip && map->is_x) rip_ok = true;
        if ((uint64_t)map->addr_start <= r.rsp && (uint64_t)map->addr_end > r.rsp) rsp_ok = true;
    }
    pmparser_free(it);

    if (!rip_ok || !rsp_ok) {
        fprintf(stderr,
            "[restore] Saved registers point outside current mappings (rip=%016llx ok=%d, rsp=%016llx ok=%d).\n"
            "          Likely address layout mismatch. Use same binary, disable ASLR, and restore into a paused clone.\n",
            (unsigned long long)r.rip, rip_ok, (unsigned long long)r.rsp, rsp_ok);
        return;
    }
#endif

    if (ptrace(PTRACE_SETREGS, pid, 0, &r) == -1) DIE("PTRACE_SETREGS");
}

bool map_and_fill_region(pid_t pid, int memfd, uint64_t start, uint64_t end, int prot,
                        const char *binfile) {
    (void)prot;

    size_t len = (size_t)(end - start);

    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) DIE("parse_maps_live");

    bool covered = false;
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        if ((uint64_t)map->addr_start <= start && (uint64_t)map->addr_end >= end) { covered = true; break; }
    }
    pmparser_free(it);

    if (!covered) {
        size_t need = len;
        int mmprot = prot ? prot : (PROT_READ | PROT_WRITE);
        int mmflags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED;
        if (remote_mmap_fixed(pid, start, need, mmprot, mmflags) != 0) {
            fprintf(stderr,
                    "[restore] target pid %d missing mapping for %016llx-%016llx and remote mmap failed. Skipping.\n",
                    (int)pid, (unsigned long long)start, (unsigned long long)end);
            return false;
        }
    }

    int fd = open(binfile, O_RDONLY); if (fd < 0) DIE("open region bin");
    char *buf = (char*)malloc(len);
    read_all_or_die(fd, buf, len);
    close(fd);

    struct iovec local = { .iov_base = buf, .iov_len = len };
    struct iovec remote = { .iov_base = (void*)start, .iov_len = len };
    ssize_t n = process_vm_writev(pid, &local, 1, &remote, 1, 0);
    if (n < 0 || (size_t)n != len) {
        n = pwrite(memfd, buf, len, (off_t)start);
        if (n < 0 || (size_t)n != len) {
            fprintf(stderr,
                    "[restore] write failed for %016llx-%016llx from %s: ",
                    (unsigned long long)start, (unsigned long long)end, binfile);
            perror("write into target");
            free(buf);
            return false;
        }
    }
    char *verify = (char*)malloc(len);
    struct iovec rlocal = { .iov_base = verify, .iov_len = len };
    struct iovec rremote = { .iov_base = (void*)start, .iov_len = len };
    ssize_t vr = process_vm_readv(pid, &rlocal, 1, &rremote, 1, 0);
    bool ok = (vr >= 0 && (size_t)vr == len && memcmp(buf, verify, len) == 0);
    if (!ok) {
        fprintf(stderr, "[restore] verify mismatch for %016llx-%016llx\n",
                (unsigned long long)start, (unsigned long long)end);
    }
    free(verify);
    free(buf);
    return ok;
}

bool restore_regions(pid_t pid, const char *dir) {
    char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", dir);
    DIR *d = opendir(memdir); if (!d) DIE("opendir memdir");
    char memp[256]; snprintf(memp, sizeof(memp), "/proc/%d/mem", pid);
    int memfd = open(memp, O_RDWR); if (memfd < 0) DIE("open /proc/pid/mem for write");

    struct dirent *de;
    size_t total = 0, okcount = 0;
    saved_map_t *smaps = NULL; size_t nsmaps = load_saved_maps(dir, &smaps);
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        uint64_t start = 0, end = 0;
        if (sscanf(de->d_name, "%16llx-%16llx.bin", (unsigned long long*)&start, (unsigned long long*)&end) != 2) continue;
        int prot = prot_for_range(smaps, nsmaps, start, end, PROT_READ | PROT_WRITE);
        char path[1024]; snprintf(path, sizeof(path), "%s/%s", memdir, de->d_name);
        total++;
        bool ok = map_and_fill_region(pid, memfd, start, end, prot, path);
        if (ok) {
            okcount++;
            (void)remote_mprotect(pid, start, (size_t)(end-start), prot);
        fprintf(stderr, "[restore] mapped %016llx-%016llx from %s\n",
                (unsigned long long)start, (unsigned long long)end, de->d_name);
        }
    }
    close(memfd);
    closedir(d);
    free(smaps);
    if (total == 0) return false;
    if (okcount != total) {
        fprintf(stderr, "[restore] restored %zu/%zu regions. Registers will not be set due to partial restore.\n", okcount, total);
        return false;
    }
    return true;
}

void restore_into(pid_t pid, const char *dir) {
    bool full = restore_regions(pid, dir);
    if (full) {
        load_regs(pid, dir);
    }
    fprintf(stderr, "[restore] restored regions into PID %d and kept attached. Use 'resume' to continue.\n", pid);
}

void relocate_into(pid_t pid, const char *indir) {
    procmaps_iterator *it_proc = parse_maps_live(pid);
    procmaps_iterator *it_dump = parse_maps_dump(indir);
    if (!it_proc || !it_dump) { perror("fopen maps"); if(it_proc) pmparser_free(it_proc); if(it_dump) pmparser_free(it_dump); return; }

    typedef struct { uint64_t start, end; int prot; char name[256]; } mapent_t;
    mapent_t proc_maps_arr[128], dump_maps_arr[128];
    size_t n_proc = 0, n_dump = 0;
    
    procmaps_struct *map;
    while ((map = pmparser_next(it_proc)) != NULL && n_proc < 128) {
        proc_maps_arr[n_proc].start = (uint64_t)map->addr_start;
        proc_maps_arr[n_proc].end = (uint64_t)map->addr_end;
        proc_maps_arr[n_proc].prot = pmparser_get_prot(map);
        if (map->pathname) strncpy(proc_maps_arr[n_proc].name, map->pathname, sizeof(proc_maps_arr[n_proc].name)-1);
        else proc_maps_arr[n_proc].name[0] = '\0';
        n_proc++;
    }
    pmparser_free(it_proc);
    
    while ((map = pmparser_next(it_dump)) != NULL && n_dump < 128) {
        dump_maps_arr[n_dump].start = (uint64_t)map->addr_start;
        dump_maps_arr[n_dump].end = (uint64_t)map->addr_end;
        dump_maps_arr[n_dump].prot = pmparser_get_prot(map);
        if (map->pathname) strncpy(dump_maps_arr[n_dump].name, map->pathname, sizeof(dump_maps_arr[n_dump].name)-1);
        else dump_maps_arr[n_dump].name[0] = '\0';
        n_dump++;
    }
    pmparser_free(it_dump);

    size_t matched = 0;
    uint64_t offsets[128] = {0};
    int proc_used[128] = {0};
    int dump_matched[128] = {0};
    for (size_t i = 0; i < n_dump; ++i) {
        uint64_t dsize = dump_maps_arr[i].end - dump_maps_arr[i].start;
        int found = 0;
        for (size_t j = 0; j < n_proc; ++j) {
            uint64_t psize = proc_maps_arr[j].end - proc_maps_arr[j].start;
            if (dsize == psize && dump_maps_arr[i].prot == proc_maps_arr[j].prot && !proc_used[j]) {
                if (dump_maps_arr[i].name[0] && proc_maps_arr[j].name[0] &&
                    strcmp(dump_maps_arr[i].name, proc_maps_arr[j].name) != 0) {
                    continue;
                }
                int overlap = 0;
                uint64_t tstart = proc_maps_arr[j].start, tend = proc_maps_arr[j].end;
                for (size_t k = 0; k < i; ++k) {
                    uint64_t prev_tstart = dump_maps_arr[k].start + offsets[k];
                    uint64_t prev_tend = dump_maps_arr[k].end + offsets[k];
                    if ((tstart < prev_tend) && (tend > prev_tstart)) {
                        overlap = 1;
                        break;
                    }
                }
                if (overlap) continue;
                offsets[i] = proc_maps_arr[j].start - dump_maps_arr[i].start;
                proc_used[j] = 1;
                dump_matched[i] = 1;
                matched++;
                found = 1;
                fprintf(stderr, "[relocate] mapping dump %016llx-%016llx (prot=%x name=%s) -> target %016llx-%016llx (prot=%x name=%s)\n",
                    (unsigned long long)dump_maps_arr[i].start, (unsigned long long)dump_maps_arr[i].end, dump_maps_arr[i].prot, dump_maps_arr[i].name,
                    (unsigned long long)tstart, (unsigned long long)tend, proc_maps_arr[j].prot, proc_maps_arr[j].name);
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "[relocate] WARNING: Could not match dump region %016llx-%016llx (prot=%x name=%s)\n",
                (unsigned long long)dump_maps_arr[i].start, (unsigned long long)dump_maps_arr[i].end, dump_maps_arr[i].prot, dump_maps_arr[i].name);
        }
    }
    if (matched == 0) {
        fprintf(stderr, "[relocate] No regions could be matched.\n");
        return;
    }

    char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", indir);
    char memp[256]; snprintf(memp, sizeof(memp), "/proc/%d/mem", pid);
    int memfd = open(memp, O_RDWR); if (memfd < 0) DIE("open /proc/pid/mem for write");
    for (size_t i = 0; i < n_dump; ++i) {
        if (!dump_matched[i]) {
            continue;
        }
        char binfile[512];
        snprintf(binfile, sizeof(binfile), "%s/%016llx-%016llx.bin", memdir, (unsigned long long)dump_maps_arr[i].start, (unsigned long long)dump_maps_arr[i].end);
        size_t len = dump_maps_arr[i].end - dump_maps_arr[i].start;
        void *buf = malloc(len);
        int fd = open(binfile, O_RDONLY);
        if (fd < 0) {
            fprintf(stderr, "[relocate] WARNING: missing binfile for %016llx-%016llx\n",
                (unsigned long long)dump_maps_arr[i].start, (unsigned long long)dump_maps_arr[i].end);
            free(buf);
            continue;
        }
        read_all_or_die(fd, buf, len); close(fd);

        int patched = 0;
        for (size_t off_in_buf = 0; off_in_buf + 8 <= len; off_in_buf += 8) {
            uint64_t *ptr = (uint64_t*)((char*)buf + off_in_buf);
            for (size_t k = 0; k < n_dump; k++) {
                if (dump_matched[k]) {
                    if (*ptr >= dump_maps_arr[k].start && *ptr < dump_maps_arr[k].end) {
                        *ptr += offsets[k];
                        patched++;
                        break;
                    }
                }
            }
        }
        if (patched > 0) {
            fprintf(stderr, "  └─ [relocate] patched %d pointers in this block\n", patched);
        }

        uint64_t new_addr = dump_maps_arr[i].start + offsets[i];
        if (pwrite(memfd, buf, len, new_addr) != (ssize_t)len) {
            perror("pwrite relocate");
        } else {
            fprintf(stderr, "[relocate] wrote %016llx-%016llx -> %016llx-%016llx\n",
                (unsigned long long)dump_maps_arr[i].start, (unsigned long long)dump_maps_arr[i].end,
                (unsigned long long)new_addr, (unsigned long long)(new_addr+len));
        }
        free(buf);
    }
    close(memfd);

    char regfile[512]; snprintf(regfile, sizeof(regfile), "%s/regs.bin", indir);
    FILE *rf = fopen(regfile, "rb");
    if (!rf) { perror("fopen regs.bin"); return; }
    regs_t regs; if (fread(&regs, 1, sizeof(regs), rf) != sizeof(regs)) { perror("fread regs.bin"); fclose(rf); return; }
    fclose(rf);
    int reg_relocated = 0;
    for (size_t i = 0; i < n_dump; ++i) {
        if (!dump_matched[i]) continue;
        uint64_t orig_start = dump_maps_arr[i].start, orig_end = dump_maps_arr[i].end, off = offsets[i];
        #define RELOC_REG(reg) \
            if (regs.reg >= orig_start && regs.reg < orig_end) { \
                regs.reg += off; reg_relocated = 1; \
                fprintf(stderr, "[relocate] register %s relocated to 0x%llx\n", #reg, (unsigned long long)regs.reg); \
            }
        RELOC_REG(rip); RELOC_REG(rsp); RELOC_REG(rbp); RELOC_REG(rax); RELOC_REG(rbx);
        RELOC_REG(rcx); RELOC_REG(rdx); RELOC_REG(rsi); RELOC_REG(rdi);
        RELOC_REG(r8); RELOC_REG(r9); RELOC_REG(r10); RELOC_REG(r11);
        RELOC_REG(r12); RELOC_REG(r13); RELOC_REG(r14); RELOC_REG(r15);
        #if defined(__x86_64__)
        regs.orig_rax = -1;
        #endif
        #undef RELOC_REG
    }
    if (reg_relocated) {
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) DIE("PTRACE_SETREGS relocate");
    } else {
        fprintf(stderr, "[relocate] No registers relocated. Skipping register set.\n");
    }
}

void spawn_paused_and_print(char **argv) {
    int pipefd[2];
    if (pipe(pipefd) < 0) DIE("pipe");

    pid_t c = fork();
    if (c < 0) DIE("fork");

    if (c == 0) {
        close(pipefd[0]);
        if (fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) < 0)
            perror("fcntl(FD_CLOEXEC)");

        setsid();
        prctl(PR_SET_PDEATHSIG, 0);

        execvp(argv[0], argv);

        perror("execvp");
        (void)write(pipefd[1], "X", 1);
        _exit(127);
    } else {
        close(pipefd[1]);

        char buf;
        ssize_t n = read(pipefd[0], &buf, 1);
        close(pipefd[0]);

        if (n > 0) {
            fprintf(stderr, "spawn: exec failed for %s\n", argv[0]);
            return;
        }

        if (kill(c, SIGSTOP) != 0) DIE("kill(SIGSTOP)");
        usleep(50000);

        fprintf(stderr, "spawned paused pid=%d\n", (int)c);
        fflush(stderr);
    }
}

void spawn_show_then_pause(char **argv, useconds_t run_us) {
    int pipefd[2];
    if (pipe(pipefd) < 0) DIE("pipe");

    pid_t c = fork();
    if (c < 0) DIE("fork");

    if (c == 0) {
        close(pipefd[0]);
        if (fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) < 0)
            perror("fcntl(FD_CLOEXEC)");
        setsid();
        prctl(PR_SET_PDEATHSIG, 0);
        execvp(argv[0], argv);
        perror("execvp");
        (void)write(pipefd[1], "X", 1);
        _exit(127);
    } else {
        close(pipefd[1]);
        char buf; ssize_t n = read(pipefd[0], &buf, 1);
        close(pipefd[0]);
        if (n > 0) {
            fprintf(stderr, "spawn_show: exec failed for %s\n", argv[0]);
            return;
        }
        usleep(run_us);
        if (kill(c, SIGSTOP) != 0) DIE("kill(SIGSTOP)");
        usleep(50000);
        fprintf(stderr, "spawned (after %u ms) paused pid=%d\n", (unsigned)(run_us/1000), (int)c);
        fflush(stderr);
    }
}

void stop_pid(pid_t pid) {
    if (kill(pid, SIGSTOP) != 0) DIE("kill(SIGSTOP) stop");
}

void cont_pid(pid_t pid) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno != EPERM) {
        if (errno == ESRCH) {
            fprintf(stderr, "PTRACE_ATTACH: No such process (pid=%d)\n", pid);
            exit(EXIT_FAILURE);
            }
            DIE("PTRACE_ATTACH in resume");
        }
    }
    (void)ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT));
    int status;
    if (waitpid(pid, &status, __WALL) == -1) DIE("waitpid resume attach");
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[resume] warning: pid %d not stopped after attach (status=0x%x).\n", pid, status);
    }

    (void)kill(pid, SIGCONT);
    for (int attempt = 0; attempt < 4; attempt++) {
        int cont_sig = 0;
        if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGSTOP) cont_sig = SIGCONT;
        if (ptrace(PTRACE_CONT, pid, NULL, (void *)(long)cont_sig) == -1) {
            if (errno == ESRCH) {
                if (kill(pid, 0) == 0) {
                    fprintf(stderr, "[resume] continued; tracer lost track (ESRCH). Target appears to be running.\n");
                    return;
                } else {
                    fprintf(stderr, "[resume] PTRACE_CONT ESRCH and target not alive.\n");
                }
            }
            DIE("PTRACE_CONT");
        }
        if (waitpid(pid, &status, __WALL) == -1) DIE("waitpid resume");

        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGSTOP) {
                (void)kill(pid, SIGCONT);
                continue;
            }
            if (sig == SIGCONT) {
                if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) DIE("PTRACE_CONT after SIGCONT");
                continue;
            }
            regs_t r; if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) DIE("GETREGS after resume");
            fprintf(stderr, "[resume] stopped with signal %d at rip=%016llx\n", sig, (unsigned long long)r.rip);
            if (sig == SIGSEGV) {
                siginfo_t si; if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == -1) { perror("PTRACE_GETSIGINFO"); }
                else {
                    fprintf(stderr, "[resume] SIGSEGV si_addr=%p si_code=%d\n", si.si_addr, si.si_code);
                }
            }
            unsigned char code[32]; memset(code, 0, sizeof(code));
            for (int i=0;i<32;i+=8) {
                errno=0; unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)(r.rip+i), NULL);
                if (w==(unsigned long)-1 && errno) break; memcpy(code+i, &w, 8);
            }
            fprintf(stderr, "[resume] bytes:");
            for (int i=0;i<32;i++) fprintf(stderr, " %02x", code[i]);
            fprintf(stderr, "\n");
            return;
        } else if (WIFEXITED(status)) {
            fprintf(stderr, "[resume] process exited code=%d\n", WEXITSTATUS(status));
            return;
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "[resume] process terminated by signal %d\n", WTERMSIG(status));
            return;
        }
    }
    fprintf(stderr, "[resume] gave up after repeated SIGSTOPs; process may be job-controlled.\n");
}

static void dump_regs_and_bytes(pid_t pid, const regs_t *r) {
    fprintf(stderr, "[trace] rip=%016llx rsp=%016llx rbp=%016llx rax=%016llx rbx=%016llx rcx=%016llx rdx=%016llx\n",
            (unsigned long long)r->rip, (unsigned long long)r->rsp, (unsigned long long)r->rbp,
            (unsigned long long)r->rax, (unsigned long long)r->rbx, (unsigned long long)r->rcx, (unsigned long long)r->rdx);
    unsigned char code[32]; memset(code, 0, sizeof(code));
    for (int i=0;i<32;i+=8) {
        errno=0; unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)(r->rip+i), NULL);
        if (w==(unsigned long)-1 && errno) break; memcpy(code+i, &w, 8);
    }
    fprintf(stderr, "[trace] bytes:");
    for (int i=0;i<32;i++) fprintf(stderr, " %02x", code[i]);
    fprintf(stderr, "\n");
}

void step_pid(pid_t pid, int max_steps) {
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno != EPERM) DIE("PTRACE_ATTACH in step");
    }
    int status; if (waitpid(pid, &status, __WALL) == -1) DIE("waitpid step attach");
    (void)ptrace(PTRACE_SETOPTIONS, pid, 0, (void *)(long)(PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT));
    (void)kill(pid, SIGCONT);

    for (int i=0; i<max_steps || max_steps<=0; i++) {
        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) DIE("PTRACE_SINGLESTEP");
        if (waitpid(pid, &status, __WALL) == -1) DIE("waitpid step");
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            regs_t r; if (ptrace(PTRACE_GETREGS, pid, 0, &r) == -1) DIE("GETREGS after step");
            if (sig == SIGTRAP) {
                dump_regs_and_bytes(pid, &r);
                if (max_steps>0 && i+1>=max_steps) return;
                continue;
            }
            if (sig == SIGSTOP || sig == SIGCONT) { (void)kill(pid, SIGCONT); continue; }
            fprintf(stderr, "[step] stopped with signal %d at rip=%016llx\n", sig, (unsigned long long)r.rip);
            if (sig == SIGSEGV) {
                siginfo_t si; if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0)
                    fprintf(stderr, "[step] SIGSEGV si_addr=%p si_code=%d\n", si.si_addr, si.si_code);
            }
            dump_regs_and_bytes(pid, &r);
            return;
        } else if (WIFEXITED(status)) {
            fprintf(stderr, "[step] process exited code=%d\n", WEXITSTATUS(status));
            return;
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "[step] process terminated by signal %d\n", WTERMSIG(status));
            return;
        }
    }
}

void show_maps_and_regs(show_mode_t mode, const char *arg) {
    procmaps_iterator *it;
    if (mode == SHOW_LIVE) {
        it = parse_maps_live((pid_t)atoi(arg));
    } else {
        it = parse_maps_dump(arg);
    }
    if (!it) { perror("fopen maps/maps.txt"); return; }
    printf("%-18s %-18s %-5s %-8s %-8s %-8s %s\n", "START", "END", "PERM", "OFFSET", "DEV", "INODE", "PATH");
    procmaps_struct *map;
    char perms[5];
    while ((map = pmparser_next(it)) != NULL) {
        perms[0] = map->is_r ? 'r' : '-';
        perms[1] = map->is_w ? 'w' : '-';
        perms[2] = map->is_x ? 'x' : '-';
        perms[3] = map->is_p ? 'p' : '-';
        perms[4] = '\0';
        printf("%016lx %016lx %-5s %08lx %02x:%02x %-8llu %s\n",
               (unsigned long)map->addr_start, (unsigned long)map->addr_end,
               perms, (unsigned long)map->offset,
               map->dev_major, map->dev_minor,
               map->inode, map->pathname ? map->pathname : "");
    }
    pmparser_free(it);

    struct user_regs_struct regs;
    if (mode == SHOW_LIVE) {
        pid_t pid = (pid_t)atoi(arg);
        if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) { perror("PTRACE_ATTACH"); return; }
        waitpid(pid, NULL, 0);
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) { perror("PTRACE_GETREGS"); ptrace(PTRACE_DETACH, pid, NULL, NULL); return; }
        printf("\nRegisters:\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
    } else {
        char rpath[512]; snprintf(rpath, sizeof(rpath), "%s/regs.bin", arg);
        FILE *rf = fopen(rpath, "rb");
        if (!rf) { perror("fopen regs.bin"); return; }
        if (fread(&regs, 1, sizeof(regs), rf) != sizeof(regs)) { perror("fread regs.bin"); fclose(rf); return; }
        fclose(rf);
        printf("\nRegisters (from dump):\n");
    }
    printf("RIP: %016llx\n", (unsigned long long)regs.rip);
    printf("RSP: %016llx\n", (unsigned long long)regs.rsp);
    printf("RBP: %016llx\n", (unsigned long long)regs.rbp);
    printf("RAX: %016llx\n", (unsigned long long)regs.rax);
    printf("RBX: %016llx\n", (unsigned long long)regs.rbx);
    printf("RCX: %016llx\n", (unsigned long long)regs.rcx);
    printf("RDX: %016llx\n", (unsigned long long)regs.rdx);
    printf("RSI: %016llx\n", (unsigned long long)regs.rsi);
    printf("RDI: %016llx\n", (unsigned long long)regs.rdi);
    printf("R8 : %016llx\n", (unsigned long long)regs.r8);
    printf("R9 : %016llx\n", (unsigned long long)regs.r9);
    printf("R10: %016llx\n", (unsigned long long)regs.r10);
    printf("R11: %016llx\n", (unsigned long long)regs.r11);
    printf("R12: %016llx\n", (unsigned long long)regs.r12);
    printf("R13: %016llx\n", (unsigned long long)regs.r13);
    printf("R14: %016llx\n", (unsigned long long)regs.r14);
    printf("R15: %016llx\n", (unsigned long long)regs.r15);
}

thread_info_t* get_thread_list(pid_t pid, size_t *count) {
    char taskdir[256];
    snprintf(taskdir, sizeof(taskdir), "/proc/%d/task", pid);
    DIR *dir = opendir(taskdir);
    if (!dir) {
        perror("opendir /proc/pid/task");
        *count = 0;
        return NULL;
    }

    size_t cap = 16;
    size_t n = 0;
    thread_info_t *threads = calloc(cap, sizeof(thread_info_t));
    if (!threads) {
        closedir(dir);
        *count = 0;
        return NULL;
    }

    struct dirent *de;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.') continue;
        pid_t tid = (pid_t)atoi(de->d_name);
        if (tid == 0) continue;

        if (n >= cap) {
            cap *= 2;
            threads = realloc(threads, cap * sizeof(thread_info_t));
            if (!threads) {
                closedir(dir);
                *count = 0;
                return NULL;
            }
        }

        threads[n].tid = tid;
        threads[n].stack_start = 0;
        threads[n].stack_end = 0;

        char maps_path[512];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", tid);
        FILE *maps = fopen(maps_path, "r");
        if (maps) {
            char line[1024];
            while (fgets(line, sizeof(line), maps)) {
                unsigned long start, end;
                char perms[5];
                if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
                    if (strstr(line, "[stack]") || (perms[0] == 'r' && perms[1] == 'w' && perms[2] == '-' && start < 0x7fff00000000ULL)) {
                        threads[n].stack_start = start;
                        threads[n].stack_end = end;
                        break;
                    }
                }
            }
            fclose(maps);
        }

        n++;
    }
    closedir(dir);
    *count = n;
    return threads;
}

void save_thread_regs(pid_t tid, const char *dir) {
    char thrdir[512];
    snprintf(thrdir, sizeof(thrdir), "%s/threads", dir);
    mkpath_or_die(thrdir);

    char tidpath[512];
    snprintf(tidpath, sizeof(tidpath), "%s/%d", thrdir, (int)tid);
    mkpath_or_die(tidpath);

    char regfile[512];
    snprintf(regfile, sizeof(regfile), "%s/regs.bin", tidpath);

    if (ptrace(PTRACE_ATTACH, tid, NULL, NULL) == -1) {
        fprintf(stderr, "[save_thread] PTRACE_ATTACH failed for tid %d: %s\n", (int)tid, strerror(errno));
        return;
    }
    waitpid(tid, NULL, 0);

    int fd = open(regfile, O_CREAT|O_TRUNC|O_WRONLY, 0644);
    if (fd >= 0) {
        regs_t r;
        if (ptrace(PTRACE_GETREGS, tid, 0, &r) == -1) {
            fprintf(stderr, "[save_thread] PTRACE_GETREGS failed for tid %d: %s\n", (int)tid, strerror(errno));
        } else {
            write_all_or_die(fd, &r, sizeof(r));
        }
        close(fd);
    }

    ptrace(PTRACE_DETACH, tid, NULL, NULL);
}

static void save_thread_stack(pid_t tid, const char *dir, uint64_t stack_start, uint64_t stack_end) {
    if (stack_start == 0 || stack_end == 0) return;

    char thrdir[512];
    snprintf(thrdir, sizeof(thrdir), "%s/threads/%d", dir, (int)tid);

    size_t len = stack_end - stack_start;
    void *buf = malloc(len);
    if (!buf) return;

    int memfd = open("/proc/self/mem", O_RDONLY);
    if (memfd < 0) {
        free(buf);
        return;
    }

    ssize_t got = pread(memfd, buf, len, (off_t)stack_start);
    close(memfd);

    if (got > 0) {
        char stackfile[512];
        snprintf(stackfile, sizeof(stackfile), "%s/stack.bin", thrdir);
        int fd = open(stackfile, O_CREAT|O_TRUNC|O_WRONLY, 0644);
        if (fd >= 0) {
            write_all_or_die(fd, buf, (size_t)got);
            close(fd);
            fprintf(stderr, "[save_thread] saved stack %016llx-%016llx for tid %d\n",
                    (unsigned long long)stack_start, (unsigned long long)stack_end, (int)tid);
        }
    }
    free(buf);
}

void save_all_threads(pid_t pid, const char *dir) {
    size_t count = 0;
    thread_info_t *threads = get_thread_list(pid, &count);
    if (!threads || count == 0) {
        fprintf(stderr, "[save_threads] no threads found for pid %d\n", (int)pid);
        if (threads) free(threads);
        return;
    }

    char threads_file[512];
    snprintf(threads_file, sizeof(threads_file), "%s/threads.txt", dir);
    FILE *f = fopen(threads_file, "w");
    if (!f) {
        perror("fopen threads.txt");
        free(threads);
        return;
    }

    for (size_t i = 0; i < count; i++) {
        fprintf(f, "%d %llx %llx\n", (int)threads[i].tid,
                (unsigned long long)threads[i].stack_start,
                (unsigned long long)threads[i].stack_end);
    }
    fclose(f);

    fprintf(stderr, "[save_threads] found %zu threads for pid %d\n", count, (int)pid);

    for (size_t i = 0; i < count; i++) {
        pid_t tid = threads[i].tid;

        if (tid == pid) {
            fprintf(stderr, "[save_threads] skipping main thread %d (already saved)\n", (int)tid);
            continue;
        }

        fprintf(stderr, "[save_threads] saving thread %d\n", (int)tid);

        save_thread_regs(tid, dir);
        save_thread_stack(tid, dir, threads[i].stack_start, threads[i].stack_end);
    }

    free(threads);
}

pid_t* load_thread_list(const char *dir, size_t *count) {
    char threads_file[512];
    snprintf(threads_file, sizeof(threads_file), "%s/threads.txt", dir);

    FILE *f = fopen(threads_file, "r");
    if (!f) {
        *count = 0;
        return NULL;
    }

    size_t cap = 16;
    size_t n = 0;
    pid_t *threads = calloc(cap, sizeof(pid_t));
    if (!threads) {
        fclose(f);
        *count = 0;
        return NULL;
    }

    char line[256];
    while (fgets(line, sizeof(line), f)) {
        pid_t tid;
        unsigned long long stack_start, stack_end;
        if (sscanf(line, "%d %llx %llx", &tid, &stack_start, &stack_end) >= 1) {
            if (n >= cap) {
                cap *= 2;
                threads = realloc(threads, cap * sizeof(pid_t));
                if (!threads) {
                    fclose(f);
                    *count = 0;
                    return NULL;
                }
            }
            threads[n++] = tid;
        }
    }
    fclose(f);
    *count = n;
    return threads;
}

regs_t load_thread_regs(pid_t tid, const char *dir) {
    regs_t r = {0};

    char regfile[512];
    snprintf(regfile, sizeof(regfile), "%s/threads/%d/regs.bin", dir, (int)tid);

    int fd = open(regfile, O_RDONLY);
    if (fd >= 0) {
        read_all_or_die(fd, &r, sizeof(r));
        close(fd);
    } else {
        fprintf(stderr, "[load_thread_regs] could not open %s: %s\n", regfile, strerror(errno));
    }

    return r;
}

void restore_threads(pid_t pid, const char *dir) {
    size_t count = 0;
    pid_t *threads = load_thread_list(dir, &count);
    if (!threads || count <= 1) {
        fprintf(stderr, "[restore_threads] no additional threads to restore (count=%zu)\n", count);
        if (threads) free(threads);
        return;
    }

    fprintf(stderr, "[restore_threads] restoring %zu threads\n", count);

    for (size_t i = 1; i < count; i++) {
        pid_t tid = threads[i];
        fprintf(stderr, "[restore_threads] restoring thread %d\n", (int)tid);

        regs_t r = load_thread_regs(tid, dir);

        pid_t clone_pid = fork();
        if (clone_pid < 0) {
            perror("fork for thread");
            continue;
        }

        if (clone_pid == 0) {
            if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
                perror("PTRACE_ATTACH in child");
                _exit(1);
            }
            waitpid(pid, NULL, 0);

            if (ptrace(PTRACE_SETREGS, pid, 0, &r) == -1) {
                perror("PTRACE_SETREGS");
            }

            ptrace(PTRACE_DETACH, pid, NULL, NULL);
            _exit(0);
        }

        waitpid(clone_pid, NULL, 0);
    }

    free(threads);
}

void checkpoint_with_threads(pid_t pid, const char *outdir) {
    mkpath_or_die(outdir);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) DIE("PTRACE_ATTACH");
    waitpid(pid, NULL, 0);

    save_meta(pid, outdir);
    save_regs(pid, outdir);
    save_maps_and_memory(pid, outdir);
    save_all_threads(pid, outdir);

    if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1) DIE("PTRACE_DETACH");
    fprintf(stderr, "[ckpt] saved to %s (with threads)\n", outdir);
}

void restore_with_threads(pid_t pid, const char *dir) {
    bool full = restore_regions(pid, dir);
    if (full) {
        load_regs(pid, dir);
    }
    restore_threads(pid, dir);
    fprintf(stderr, "[restore] restored into PID %d with threads\n", pid);
}

void show_threads(pid_t pid) {
    size_t count = 0;
    thread_info_t *threads = get_thread_list(pid, &count);
    if (!threads) {
        fprintf(stderr, "Could not get thread list for pid %d\n", (int)pid);
        return;
    }

    printf("Threads for PID %d (%zu threads):\n", (int)pid, count);
    printf("%-10s %-18s %-18s\n", "TID", "Stack Start", "Stack End");
    for (size_t i = 0; i < count; i++) {
        printf("%-10d 0x%016llx 0x%016llx\n",
               (int)threads[i].tid,
               (unsigned long long)threads[i].stack_start,
               (unsigned long long)threads[i].stack_end);
    }
    free(threads);
}

void show_threads_dump(const char *dir) {
    size_t count = 0;
    pid_t *threads = load_thread_list(dir, &count);
    if (!threads) {
        fprintf(stderr, "Could not load thread list from %s\n", dir);
        return;
    }

    printf("Threads in checkpoint (%zu threads):\n", count);
    printf("%-10s\n", "TID");
    for (size_t i = 0; i < count; i++) {
        printf("%-10d\n", (int)threads[i]);
    }
    free(threads);
}
