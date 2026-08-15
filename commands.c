#include "ckptmini.h"
#include "parasite.h"
#include <capstone/capstone.h>
#include <ctype.h>

static void print_perms_colored(const char *perms, bool tty) {
    if (!tty) { printf("%-4s", perms); return; }
    char r = perms[0], w = perms[1], x = perms[2], p = perms[3];
    printf("%s%c%s", r=='r' ? A_GREEN  : A_DIM, r, A_RESET);
    printf("%s%c%s", w=='w' ? A_YELLOW : A_DIM, w, A_RESET);
    printf("%s%c%s", x=='x' ? A_RED    : A_DIM, x, A_RESET);
    printf("%s%c%s", p=='p' ? A_DIM    : A_CYAN, p, A_RESET);
}

static const char *map_tag(const char *name) {
    if (!name || !name[0])          return "anon";
    if (strstr(name, "[heap]"))     return "heap";
    if (strstr(name, "[stack]"))    return "stack";
    if (strstr(name, "[vvar]"))     return "vvar";
    if (strstr(name, "[vdso]"))     return "vdso";
    if (strstr(name, "[vsyscall]")) return "vsys";
    const char *sl = strrchr(name, '/');
    return sl ? sl+1 : name;
}

void cmd_dump(const char *arg) {
    
    bool is_live = true;
    for (const char *p = arg; *p; p++) {
        if (*p < '0' || *p > '9') { is_live = false; break; }
    }

    if (g_is_tty) printf(A_BGBLUE A_WHITE A_BOLD);
    if (is_live) {
        pid_t pid = (pid_t)atoi(arg);
        char cpath[64], cmdline[256] = ""; int cfd;
        snprintf(cpath, sizeof(cpath), "/proc/%d/cmdline", pid);
        if ((cfd = open(cpath, O_RDONLY)) >= 0) {
            ssize_t n = read(cfd, cmdline, sizeof(cmdline)-1); close(cfd);
            if (n > 0) { cmdline[n] = 0;
                for (ssize_t i = 0; i < n-1; i++) if (!cmdline[i]) cmdline[i] = ' ';
            }
        }
        printf("  PID %d  %-40s", pid, cmdline);
    } else {
        printf("  DUMP  %-47s", arg);
    }
    if (g_is_tty) printf(A_RESET);
    printf("\n");

    procmaps_iterator *it = is_live ? parse_maps_live((pid_t)atoi(arg)) : parse_maps_dump(arg);
    if (!it) { perror("fopen maps"); return; }

    if (g_is_tty) printf(A_BOLD A_CYAN);
    printf("  %-18s %-18s  %-4s  %8s  %s\n", "START", "END", "PERM", "SIZE", "NAME");
    if (g_is_tty) printf(A_RESET A_DIM);
    printf("  %-18s %-18s  %-4s  %8s  %s\n",
           "──────────────────", "──────────────────", "────", "────────", "──────────────────────");
    if (g_is_tty) printf(A_RESET);

    uint64_t total_bytes = 0; size_t region_count = 0;
    procmaps_struct *map;
    char perms[5];
    while ((map = pmparser_next(it)) != NULL) {
        uint64_t s = (uint64_t)map->addr_start;
        uint64_t e = (uint64_t)map->addr_end;
        uint64_t sz = e - s; total_bytes += sz; region_count++;

        printf("  %016lx %016lx  ", (unsigned long)s, (unsigned long)e);
        
        get_perms_string(map, perms);
        print_perms_colored(perms, g_is_tty);

        char szbuf[16]; hr_size(sz, szbuf, sizeof(szbuf));
        printf("  %8s  ", szbuf);

        const char *tag = map->pathname ? map->pathname : "";
        if (g_is_tty) {
            if (strstr(tag,"heap"))       printf(A_YELLOW);
            else if (strstr(tag,"stack")) printf(A_RED);
            else if (tag[0]=='[')         printf(A_DIM);
            else if (!tag[0])              printf(A_DIM);
            else                          printf(A_GREEN);
        }
        if (map->pathname && map->pathname[0]) {
            printf("%.63s", map->pathname);
        } else {
            printf("[anon]");
        }
        if (g_is_tty) printf(A_RESET);
        printf("\n");
    }
    pmparser_free(it);

    char totbuf[16]; hr_size(total_bytes, totbuf, sizeof(totbuf));
    if (g_is_tty) printf(A_DIM);
    printf("  %-18s %-18s  %-4s  %8s  %zu region(s)\n",
           "──────────────────", "──────────────────", "────", totbuf, region_count);
    if (g_is_tty) printf(A_RESET);

    struct user_regs_struct regs;
    bool got_regs = false;

    if (is_live) {
        pid_t pid = (pid_t)atoi(arg);
        bool attached = (tracee_attach(pid) == 0);
        if (attached) {
            int st; tracee_wait(pid, &st);
        }
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) got_regs = true;
        if (attached) {
            tracee_detach(pid, NULL);
        }
    } else {
        char rpath[512]; snprintf(rpath, sizeof(rpath), "%s/regs.bin", arg);
        FILE *rf = fopen(rpath, "rb");
        if (rf) {
            if (fread(&regs, 1, sizeof(regs), rf) == sizeof(regs)) got_regs = true;
            fclose(rf);
        }
    }

    printf("\n");
    if (g_is_tty) printf(A_BOLD A_CYAN);
    printf("  %-14s %-18s    %-14s %-18s\n", "REGISTER", "VALUE", "REGISTER", "VALUE");
    if (g_is_tty) printf(A_RESET A_DIM);
    printf("  %-14s %-18s    %-14s %-18s\n",
           "──────────────", "──────────────────", "──────────────", "──────────────────");
    if (g_is_tty) printf(A_RESET);

    if (!got_regs) {
        if (g_is_tty) printf(A_DIM);
        printf("  (registers unavailable)\n");
        if (g_is_tty) printf(A_RESET);
    } else {
        typedef struct { const char *name; uint64_t val; } rv_t;
        rv_t left[]  = {
            {"rip", regs.rip}, {"rsp", regs.rsp}, {"rbp", regs.rbp},
            {"rflags", regs.eflags}, {"cs", regs.cs}, {"ss", regs.ss},
            {"fs_base", regs.fs_base}, {"gs_base", regs.gs_base},
        };
        rv_t right[] = {
            {"rax", regs.rax}, {"rbx", regs.rbx}, {"rcx", regs.rcx}, {"rdx", regs.rdx},
            {"rsi", regs.rsi}, {"rdi", regs.rdi},
            {"r8",  regs.r8 }, {"r9",  regs.r9 },
            {"r10", regs.r10}, {"r11", regs.r11},
            {"r12", regs.r12}, {"r13", regs.r13},
            {"r14", regs.r14}, {"r15", regs.r15},
        };
        size_t nleft  = sizeof(left)/sizeof(left[0]);
        size_t nright = sizeof(right)/sizeof(right[0]);
        size_t nrows  = nleft > nright ? nleft : nright;
        for (size_t i = 0; i < nrows; i++) {
            if (i < nleft) {
                if (g_is_tty) printf(A_BOLD);
                printf("  %-14s", left[i].name);
                if (g_is_tty) printf(A_RESET);
                printf(" %016llx", (unsigned long long)left[i].val);
            } else {
                printf("  %-14s %-18s", "", "");
            }
            printf("    ");
            if (i < nright) {
                if (g_is_tty) printf(A_BOLD);
                printf("%-14s", right[i].name);
                if (g_is_tty) printf(A_RESET);
                printf(" %016llx", (unsigned long long)right[i].val);
            }
            printf("\n");
        }
    }
    printf("\n");
}

void cmd_watch(pid_t pid, uint64_t addr, size_t len, unsigned int interval_ms) {
    unsigned char *prev = (unsigned char *)calloc(1, len);
    unsigned char *curr = (unsigned char *)malloc(len);
    bool first = true;

    if (g_is_tty) {
        printf(A_BOLD A_CYAN);
        printf("Watching PID %d  addr=0x%016llx  len=%zu  interval=%ums  (Ctrl-C to stop)\n",
               pid, (unsigned long long)addr, len, interval_ms);
        printf(A_RESET);
    }

    for (;;) {
        if (!read_bytes_from_pid(pid, addr, curr, len)) {
            fprintf(stderr, "\n[watch] read failed (process may have exited)\n");
            break;
        }

        if (first || memcmp(prev, curr, len) != 0) {
            if (!first) {
                size_t fc = 0;
                while (fc < len && prev[fc] == curr[fc]) fc++;
                print_timestamp();
                if (g_is_tty) printf(A_YELLOW A_BOLD);
                printf("CHANGED at +0x%zx", fc);
                if (g_is_tty) printf(A_RESET);
                printf("\n");
            } else {
                print_timestamp();
                printf("initial\n");
                first = false;
            }

            for (size_t off = 0; off < len; off += 16) {
                size_t row = len - off < 16 ? len - off : 16;
                bool changed = !first && (memcmp(prev + off, curr + off, row) != 0);
                if (g_is_tty && changed) printf(A_YELLOW);
                hexdump_line(addr + off, curr + off, row);
                if (g_is_tty && changed) printf(A_RESET);
            }
            fflush(stdout);
            memcpy(prev, curr, len);
        }

        usleep(interval_ms * 1000u);
    }

    free(prev);
    free(curr);
}

void cmd_snapshot_diff(pid_t pid, const char *indir) {
    

    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "snapshot_diff: permission denied (need root)\n"); return; }
        else if (errno == ESRCH) { fprintf(stderr, "snapshot_diff: no such process %d\n", pid); return; }
        else DIE("PTRACE_ATTACH snapshot_diff");
    }
    int st; tracee_wait(pid, &st);

    char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", indir);
    DIR *d = opendir(memdir);
    if (!d) { tracee_detach(pid, NULL); perror("opendir mem"); return; }

    if (g_is_tty) printf(A_BOLD A_CYAN);
    printf("  Snapshot diff: PID %d  vs  %s\n", pid, indir);
    if (g_is_tty) printf(A_RESET A_DIM);
    printf("  %-34s  %-10s  %-10s  %s\n", "REGION", "SAVED SZ", "CHANGED", "RANGES");
    printf("  %-34s  %-10s  %-10s  %s\n",
           "──────────────────────────────────", "──────────", "──────────", "───────────────────────");
    if (g_is_tty) printf(A_RESET);

    size_t total_diff = 0, total_regions = 0, changed_regions = 0;
    struct dirent *de;

    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        uint64_t rs = 0, re = 0;
        if (sscanf(de->d_name, "%16llx-%16llx.bin",
                   (unsigned long long*)&rs,
                   (unsigned long long*)&re) != 2) continue;
        total_regions++;
        size_t len = (size_t)(re - rs);

        char binpath[1024]; snprintf(binpath, sizeof(binpath), "%s/%s", memdir, de->d_name);
        int fd = open(binpath, O_RDONLY); if (fd < 0) continue;
        unsigned char *saved = (unsigned char*)malloc(len);
        ssize_t nr = 0;
        { size_t rem = len; while (rem > 0) { ssize_t n = read(fd, saved + (len-rem), rem); if (n <= 0) break; rem -= (size_t)n; } nr = (ssize_t)(len - 0); }
        close(fd);

        unsigned char *live = (unsigned char*)malloc(len);
        if (!read_bytes_from_pid(pid, rs, live, len)) {
            if (g_is_tty) printf(A_DIM);
            printf("  %016llx-%016llx  %8zuB  %-10s  (unreadable in live process)\n",
                   (unsigned long long)rs, (unsigned long long)re, len, "--");
            if (g_is_tty) printf(A_RESET);
            free(saved); free(live); continue;
        }

        size_t diff_bytes = 0;
        typedef struct { size_t start; size_t end; } run_t;
        run_t runs[64]; size_t nruns = 0;
        size_t i = 0;
        while (i < len) {
            if (saved[i] != live[i]) {
                size_t j = i;
                while (j < len && saved[j] != live[j]) j++;
                diff_bytes += j - i;
                if (nruns < 64) { runs[nruns].start = i; runs[nruns].end = j; nruns++; }
                i = j;
            } else { i++; }
        }
        total_diff += diff_bytes;

        char szbuf[16]; hr_size((uint64_t)len, szbuf, sizeof(szbuf));
        if (diff_bytes > 0) {
            changed_regions++;
            char diffbuf[16]; hr_size((uint64_t)diff_bytes, diffbuf, sizeof(diffbuf));

            if (g_is_tty) printf(A_YELLOW);
            printf("  %016llx-%016llx  %8s  %8s  ",
                   (unsigned long long)rs, (unsigned long long)re, szbuf, diffbuf);
            for (size_t r = 0; r < nruns && r < 4; r++) {
                printf("+0x%zx..+0x%zx", runs[r].start, runs[r].end);
                if (r + 1 < nruns && r + 1 < 4) printf(", ");
            }
            if (nruns > 4) printf(", …(%zu more)", nruns - 4);
            if (g_is_tty) printf(A_RESET);
            printf("\n");

            if (nruns > 0) {
                size_t show = runs[0].end - runs[0].start;
                if (show > 32) show = 32;
                if (g_is_tty) printf(A_DIM);
                printf("    saved: ");
                for (size_t k = 0; k < show; k++) printf("%02x ", saved[runs[0].start + k]);
                printf("\n");
                printf("    live:  ");
                for (size_t k = 0; k < show; k++) {
                    if (g_is_tty && saved[runs[0].start+k] != live[runs[0].start+k]) printf(A_RESET A_RED A_BOLD);
                    printf("%02x ", live[runs[0].start + k]);
                    if (g_is_tty && saved[runs[0].start+k] != live[runs[0].start+k]) printf(A_RESET A_DIM);
                }
                printf("\n");
                if (g_is_tty) printf(A_RESET);
            }
        } else {
            if (g_is_tty) printf(A_DIM);
            printf("  %016llx-%016llx  %8s  %10s  (identical)\n",
                   (unsigned long long)rs, (unsigned long long)re, szbuf, "0B");
            if (g_is_tty) printf(A_RESET);
        }

        free(saved); free(live);
    }
    closedir(d);
    tracee_detach(pid, NULL);

    char totbuf[16]; hr_size((uint64_t)total_diff, totbuf, sizeof(totbuf));
    printf("\n");
    if (g_is_tty) printf(A_BOLD);
    printf("  Summary: %zu/%zu regions changed,  %s total bytes differ\n",
           changed_regions, total_regions, totbuf);
    if (g_is_tty) printf(A_RESET);
    printf("\n");
}

void cmd_breakpoint(pid_t pid, uint64_t addr) {
    
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "breakpoint: permission denied (need root)\n"); return; }
        else if (errno == ESRCH) { fprintf(stderr, "breakpoint: no such process %d\n", pid); return; }
        else DIE("PTRACE_ATTACH breakpoint");
    }
    int st; waitpid(pid, &st, __WALL);

    errno = 0;
    long orig_word = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
    if (orig_word == -1 && errno) {
        tracee_detach(pid, NULL);
        fprintf(stderr, "breakpoint: could not read address 0x%016llx\n", (unsigned long long)addr);
        return;
    }
    unsigned char orig_byte = (unsigned char)(orig_word & 0xFF); (void)orig_byte;

    long bp_word = (orig_word & ~0xFFL) | 0xCCL;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)bp_word) == -1) {
        tracee_detach(pid, NULL);
        fprintf(stderr, "breakpoint: could not write INT3 at 0x%016llx (is it read-only?)\n", (unsigned long long)addr);
        return;
    }

    if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Breakpoint set at 0x%016llx. Continuing...\n" A_RESET, (unsigned long long)addr);
    else printf("Breakpoint set at 0x%016llx. Continuing...\n", (unsigned long long)addr);

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) DIE("PTRACE_CONT");

    waitpid(pid, &st, __WALL);

    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
        regs_t regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) DIE("PTRACE_GETREGS");

        regs.rip -= 1;
        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) DIE("PTRACE_SETREGS");
        if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)orig_word) == -1) DIE("PTRACE_POKETEXT restore");

        if (g_is_tty) printf(A_BOLD A_GREEN "\n  ★ Breakpoint HIT at 0x%016llx\n" A_RESET, (unsigned long long)regs.rip);
        else printf("\nBreakpoint HIT at 0x%016llx\n", (unsigned long long)regs.rip);

        tracee_detach(pid, (void*)SIGSTOP);

        char pidstr[32]; snprintf(pidstr, sizeof(pidstr), "%d", pid);
        cmd_dump(pidstr);
        return;
    } else {
        if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)orig_word) == -1) {
        }
        printf("Process stopped for non-trap reason (status=0x%x, sig=%d). Original byte restored.\n", st, WIFSTOPPED(st) ? WSTOPSIG(st) : 0);
    }

        tracee_detach(pid, (void*)((WIFSTOPPED(st) && WSTOPSIG(st) != SIGTRAP) ? (long)WSTOPSIG(st) : 0));
}

/**
 * @brief Inject and execute shellcode in a running process
 * 
 * This function performs runtime code injection:
 * 1. Attach to target process via ptrace
 * 2. Allocate executable memory using mmap (via remote_syscall_x64)
 * 3. Write shellcode to the allocated memory
 * 4. Verify the write succeeded (read back and compare)
 * 5. Hijack RIP to point to our shellcode
 * 6. Run until breakpoint trap (SIGTRAP)
 * 7. Restore original registers and clean up
 * 
 * The shellcode is followed by 0xCC (int3) to act as a "stop" breakpoint.
 * This allows us to detect when the shellcode finishes execution.
 */
void cmd_inject_shellcode(pid_t pid, const char *hex) {
    size_t slen = 0;
    unsigned char *shellcode = parse_hex(hex, &slen);
    if (!shellcode) { fprintf(stderr, "inject_shellcode: invalid hex strings\n"); return; }

    /* Attach to target process */
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "inject: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "inject: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH inject");
        free(shellcode); return;
    }
    int st; waitpid(pid, &st, __WALL);

    regs_t saved_regs, regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &saved_regs) == -1) DIE("PTRACE_GETREGS inject");
    regs = saved_regs;

    /* Step 1: Allocate executable memory in target process
     * We use mmap with PROT_READ|PROT_WRITE|PROT_EXEC to create
     * a region where we can write and execute our shellcode */
    uint64_t pocket = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)pocket < 0) {
        fprintf(stderr, "inject: remote mmap failed (ret=%ld)\n", (long)pocket);
        tracee_detach(pid, NULL); free(shellcode); return;
    }

    /* Step 2: Copy shellcode to buffer, append int3 breakpoint */
    unsigned char *payload = (unsigned char*)malloc(slen + 1);
    memcpy(payload, shellcode, slen);
    payload[slen] = 0xCC;  /* int3 - acts as our "done" breakpoint */

    /* Step 3: Write shellcode to allocated memory */
    if (!write_bytes_to_pid(pid, pocket, payload, slen + 1)) {
        fprintf(stderr, "inject: write failed at 0x%016llx\n", (unsigned long long)pocket);
    } else {
        /* Verify the write succeeded by reading back */
        unsigned char *verify = (unsigned char*)malloc(slen + 1);
        if (read_bytes_from_pid(pid, pocket, verify, slen + 1)) {
            if (memcmp(payload, verify, slen + 1) != 0) {
                 fprintf(stderr, "inject: [warn] verification failed! Bytes at 0x%016llx don't match.\n", (unsigned long long)pocket);
            }
        }
        free(verify);

        if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Injecting %zu bytes at 0x%016llx. Running...\n" A_RESET, slen, (unsigned long long)pocket);
        else printf("Injecting %zu bytes at 0x%016llx. Running...\n", slen, (unsigned long long)pocket);

        /* Step 4: Hijack execution - set RIP to our shellcode */
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) DIE("PTRACE_GETREGS hijack");
        regs.rip = pocket;
        #if defined(__x86_64__)
        regs.rax = -1;       /* Clear return value so syscall returns work */
        regs.orig_rax = -1;  /* Mark as syscall instruction */
        #endif

        if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) DIE("PTRACE_SETREGS hijack");
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) DIE("PTRACE_CONT hijack");

        /* Wait for shellcode to hit our int3 breakpoint */
        waitpid(pid, &st, __WALL);
        if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
            if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Shellcode hit TRAP. Restoring state.\n" A_RESET);
            else printf("Shellcode hit TRAP. Restoring state.\n");
        } else {
            /* Shellcode crashed or was interrupted */
            int sig = WIFSTOPPED(st) ? WSTOPSIG(st) : (WIFSIGNALED(st) ? WTERMSIG(st) : 0);
            printf("  ⚠ Shellcode stopped for non-trap reason (status=0x%x, sig=%d).\n", st, sig);
            regs_t crashed_regs;
            if (ptrace(PTRACE_GETREGS, pid, 0, &crashed_regs) == 0) {
                printf("    RIP was at 0x%016llx\n", (unsigned long long)crashed_regs.rip);
                char pstr[32]; snprintf(pstr, sizeof(pstr), "%d", pid);
                cmd_dump(pstr);
            }
        }
    }

    /* Step 5: Restore original registers */
    if (ptrace(PTRACE_SETREGS, pid, 0, &saved_regs) == -1) DIE("PTRACE_SETREGS restore");
    
    /* Step 6: Free the allocated memory */
    (void)remote_syscall_x64(pid, __NR_munmap, pocket, 4096, 0, 0, 0, 0);

    /* Step 7: Detach, preserving signal state if needed */
        tracee_detach(pid, (void*)((WIFSTOPPED(st) && WSTOPSIG(st) != SIGTRAP) ? (long)WSTOPSIG(st) : 0));
    free(shellcode); free(payload);
}

void cmd_trace(pid_t pid) {
    
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "trace: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "trace: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH trace");
        return;
    }
    int st; waitpid(pid, &st, __WALL);

    if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void*)PTRACE_O_TRACESYSGOOD) == -1) DIE("PTRACE_SETOPTIONS");

    if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Tracing syscalls for PID %d. Press Ctrl+C to stop.\n" A_RESET, pid);
    else printf("Tracing syscalls for PID %d...\n", pid);

    bool in_syscall = false;
    while (!g_interrupt) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        if (waitpid_eintr(pid, &st) == -1) break;

        if (WIFEXITED(st)) {
            printf("Process %d exited.\n", pid);
            break;
        }
        if (WIFSIGNALED(st)) {
            printf("Process %d killed by signal %d.\n", pid, WTERMSIG(st));
            break;
        }

        if (WIFSTOPPED(st) && WSTOPSIG(st) == (SIGTRAP | 0x80)) {
            regs_t regs;
            errno = 0;
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) { fprintf(stderr, "[dbg] GETREGS err=%d %s (in_syscall=%d)\n", errno, strerror(errno), in_syscall); break; }

            if (!in_syscall) {
                if (g_is_tty) printf(A_CYAN "  [entry]" A_RESET " syscall(%lld) args: %016llx %016llx %016llx\n",
                       (long long)regs.orig_rax, (long long)regs.rdi, (long long)regs.rsi, (long long)regs.rdx);
                else printf("[entry] syscall(%lld) args: %016llx %016llx %016llx\n",
                       (long long)regs.orig_rax, (long long)regs.rdi, (long long)regs.rsi, (long long)regs.rdx);
                in_syscall = true;
            } else {
                if (g_is_tty) printf(A_GREEN "  [exit] " A_RESET " result: %lld\n", (long long)regs.rax);
                else printf("[exit] result: %lld\n", (long long)regs.rax);
                in_syscall = false;
            }
            fflush(stdout);
        } else if (WIFSTOPPED(st)) {
            if (g_is_tty) printf(A_DIM "  (stopped by signal %d)\n" A_RESET, WSTOPSIG(st));
            else printf("(stopped by signal %d)\n", WSTOPSIG(st));
        }
    }
    tracee_detach(pid, NULL);
}

/* ---------------- instruction (single-step) tracing ---------------- */

/* Pad the raw-byte column (3 chars per byte) so mnemonics align. */
static void pad_bytes_col(size_t nbytes) {
    size_t w = nbytes * 3;
    for (; w < 46; w++) putchar(' ');
}

static bool disas_open(csh *handle) {
    return cs_open(CS_ARCH_X86, CS_MODE_64, handle) == CS_ERR_OK;
}

/* Tracks the last printed symbol so a header is only emitted on change. */
typedef struct {
    uint64_t last_sym_start;
    bool has_last;
} symstate_t;

/* Print a "sym+0xN:" header when the resolved symbol changes. */
static void sym_header(symstate_t *st, uint64_t addr) {
    symres_t r = elfsym_resolve(addr);
    if (!r.found) return;
    uint64_t start = addr - r.delta;
    if (st->has_last && st->last_sym_start == start) return;
    st->has_last = true;
    st->last_sym_start = start;
    if (g_is_tty) printf(A_DIM A_BOLD);
    if (r.delta) printf("%s+0x%llx:\n", r.name, (unsigned long long)r.delta);
    else printf("%s:\n", r.name);
    if (g_is_tty) printf(A_RESET);
}

/* Annotate a ret instruction with the value in rax (the value being returned). */
static void print_retval(uint64_t rax) {
    if (g_is_tty) printf(A_DIM);
    printf("    rax=0x%llx", (unsigned long long)rax);
    if (g_is_tty) printf(A_RESET);
}

void cmd_itrace(pid_t pid, bool disasm, bool syms) {
    
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "itrace: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "itrace: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH itrace");
        return;
    }
    int st;
    if (waitpid_eintr(pid, &st) == -1) {
        perror("itrace: waitpid attach");
        tracee_detach(pid, NULL);
        return;
    }

    /* Catch SIGINT so Ctrl+C stops the trace instead of killing us.
       If we died while the tracee is stopped at a single-step SIGTRAP,
       the kernel would deliver that SIGTRAP and kill the target with
       "Trace/breakpoint trap (core dumped)". */
    install_sigint_stop();

    if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Tracing instructions for PID %d. Press Ctrl+C to stop.\n" A_RESET, pid);
    else printf("Tracing instructions for PID %d...\n", pid);

    csh handle;
    if (disasm && !disas_open(&handle)) {
        fprintf(stderr, "itrace: capstone init failed\n");
        disasm = false;
    }
    if (syms && elfsym_init(pid) != 0) {
        fprintf(stderr, "itrace: could not load symbols\n");
        syms = false;
    }

    symstate_t symst = { 0 };
    unsigned long long count = 0;
    while (!g_interrupt) {
        regs_t regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) break;

        if (syms) sym_header(&symst, regs.rip);

        /* Read bytes at RIP: -d mode needs up to 15 bytes (max x86
           instruction length); normal mode reads a single 8-byte word. */
        unsigned char code[15];
        size_t nbytes = 0;
        size_t cap = disasm ? sizeof(code) : 8;
        for (size_t off = 0; off < cap; off += 8) {
            errno = 0;
            unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip + off), NULL);
            if (w == (unsigned long)-1 && errno) break;
            size_t n = (cap - off < 8) ? cap - off : 8;
            memcpy(code + off, &w, n);
            nbytes += n;
        }

        /* Decode first: in -d mode only the instruction's own bytes are shown,
           not the lookahead that will be executed on later steps. */
        cs_insn *insn = NULL;
        size_t nins = 0;
        size_t shown = nbytes;
        if (disasm) {
            nins = cs_disasm(handle, code, nbytes, regs.rip, 1, &insn);
            shown = nins > 0 ? insn[0].size : 0;
        }

        if (g_is_tty) printf(A_CYAN "[%06llu]" A_RESET " 0x%016llx:", count, (unsigned long long)regs.rip);
        else printf("[%06llu] 0x%016llx:", count, (unsigned long long)regs.rip);
        for (size_t i = 0; i < shown; i++) printf(" %02x", code[i]);
        if (disasm) {
            pad_bytes_col(shown);
            if (nins > 0) {
                printf("  %s %s", insn[0].mnemonic, insn[0].op_str);
                if (!strncmp(insn[0].mnemonic, "ret", 3)) print_retval(regs.rax);
                cs_free(insn, nins);
            } else {
                printf("  <invalid>");
            }
        }
        printf("\n");
        fflush(stdout);
        count++;

        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) break;
        if (waitpid_eintr(pid, &st) == -1) break;

        if (WIFSTOPPED(st)) {
            int sig = WSTOPSIG(st);
            if (sig == SIGTRAP) continue;
            if (sig == SIGSTOP || sig == SIGCONT) { (void)kill(pid, SIGCONT); continue; }
            if (g_is_tty) printf(A_DIM "  (stopped by signal %d)\n" A_RESET, sig);
            else printf("(stopped by signal %d)\n", sig);
            if (sig == SIGSEGV) {
                siginfo_t si;
                if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0)
                    fprintf(stderr, "  SIGSEGV si_addr=%p si_code=%d\n", si.si_addr, si.si_code);
                break;
            }
            continue;
        }
        if (WIFEXITED(st)) {
            printf("Process %d exited (status %d).\n", pid, WEXITSTATUS(st));
            break;
        }
        if (WIFSIGNALED(st)) {
            printf("Process %d killed by signal %d.\n", pid, WTERMSIG(st));
            break;
        }
    }

    /* Detach with signal 0: the tracee resumes without any pending SIGTRAP. */
    tracee_detach(pid, NULL);

    if (g_interrupt) {
        if (g_is_tty) printf(A_GREEN "  ★ Stopped tracing PID %d (detached; process continues).\n" A_RESET, pid);
        else printf("Stopped tracing PID %d (detached; process continues).\n", pid);
    }

    if (disasm) cs_close(&handle);
    if (syms) elfsym_free();
}

void cmd_disas(pid_t pid, uint64_t addr, size_t len, bool syms) {
    if (len == 0) { fprintf(stderr, "disas: len must be > 0\n"); return; }
    unsigned char *buf = (unsigned char*)malloc(len);
    if (!buf) DIE("malloc disas");
    if (!read_bytes_from_pid(pid, (uintptr_t)addr, buf, len)) {
        if (g_is_tty) printf(A_BOLD A_RED);
        printf("  %s Failed to read %zu bytes at 0x%016llx from PID %d\n", S_ERR, len, (unsigned long long)addr, pid);
        if (g_is_tty) printf(A_RESET);
        free(buf);
        return;
    }

    csh handle;
    if (!disas_open(&handle)) {
        fprintf(stderr, "disas: capstone init failed\n");
        free(buf);
        return;
    }
    if (syms && elfsym_init(pid) != 0) {
        fprintf(stderr, "disas: could not load symbols\n");
        syms = false;
    }

    if (g_is_tty) printf(A_BOLD A_CYAN);
    printf("  Disassembling %zu bytes at 0x%016llx (PID %d)\n", len, (unsigned long long)addr, pid);
    if (g_is_tty) printf(A_RESET);

    symstate_t symst = { 0 };
    size_t off = 0;
    while (off < len) {
        if (syms) sym_header(&symst, addr + off);
        cs_insn *insn = NULL;
        size_t count = cs_disasm(handle, buf + off, len - off, addr + off, 1, &insn);
        if (count == 0) {
            if (g_is_tty) printf(A_DIM);
            printf("  0x%016llx:  %02x", (unsigned long long)(addr + off), buf[off]);
            pad_bytes_col(1);
            if (g_is_tty) printf(A_RESET);
            printf("<invalid>\n");
            off++;
            continue;
        }
        printf("  0x%016llx:  ", (unsigned long long)(addr + off));
        for (size_t i = 0; i < insn[0].size; i++) printf("%02x ", buf[off + i]);
        pad_bytes_col(insn[0].size);
        if (g_is_tty) printf(A_GREEN);
        printf("%s", insn[0].mnemonic);
        if (g_is_tty) printf(A_RESET);
        if (insn[0].op_str[0]) printf(" %s", insn[0].op_str);
        printf("\n");
        off += insn[0].size;
        cs_free(insn, count);
    }

    cs_close(&handle);
    if (syms) elfsym_free();
    free(buf);
}

/* ---------------- call/jmp/ret flow tracing ---------------- */

static void print_calltrace_line(unsigned long long count, int depth,
                                 const cs_insn *insn, uint64_t rip, uint64_t rax, bool syms) {
    if (g_is_tty) printf(A_CYAN "[%06llu]" A_RESET " depth=%d  ", count, depth);
    else printf("[%06llu] depth=%d  ", count, depth);

    if (syms) {
        symres_t r = elfsym_resolve(rip);
        if (r.found) {
            if (g_is_tty) printf(A_DIM A_BOLD);
            if (r.delta) printf("%s+0x%llx: ", r.name, (unsigned long long)r.delta);
            else printf("%s: ", r.name);
            if (g_is_tty) printf(A_RESET);
        } else {
            printf("0x%016llx: ", (unsigned long long)rip);
        }
    } else {
        printf("0x%016llx: ", (unsigned long long)rip);
    }

    if (g_is_tty) printf(A_GREEN);
    printf("%s %s", insn->mnemonic, insn->op_str);
    if (g_is_tty) printf(A_RESET);

    /* For a ret, rax holds the value being returned. */
    if (!strncmp(insn->mnemonic, "ret", 3)) print_retval(rax);

    /* For direct calls/jumps, annotate the resolved callee with -s. */
    if (syms && insn->detail && insn->detail->x86.op_count > 0 &&
        (!strncmp(insn->mnemonic, "call", 4) || !strncmp(insn->mnemonic, "jmp", 3))) {
        const cs_x86_op *op = &insn->detail->x86.operands[0];
        if (op->type == X86_OP_IMM) {
            symres_t t = elfsym_resolve((uint64_t)op->imm);
            if (t.found) {
                if (g_is_tty) printf(A_DIM);
                if (t.delta) printf("  -> %s+0x%llx", t.name, (unsigned long long)t.delta);
                else printf("  -> %s", t.name);
                if (g_is_tty) printf(A_RESET);
            }
        }
    }
    printf("\n");
}

void cmd_calltrace(pid_t pid, bool syms) {
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "calltrace: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "calltrace: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH calltrace");
        return;
    }
    int st;
    if (waitpid_eintr(pid, &st) == -1) {
        perror("calltrace: waitpid attach");
        tracee_detach(pid, NULL);
        return;
    }

    /* Catch SIGINT so Ctrl+C stops the trace instead of killing us. */
    install_sigint_stop();

    if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Tracing call/jmp/ret flow for PID %d. Press Ctrl+C to stop.\n" A_RESET, pid);
    else printf("Tracing call/jmp/ret flow for PID %d...\n", pid);

    csh handle;
    if (!disas_open(&handle)) {
        fprintf(stderr, "calltrace: capstone init failed\n");
        tracee_detach(pid, NULL);
        return;
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
    if (syms && elfsym_init(pid) != 0) {
        fprintf(stderr, "calltrace: could not load symbols\n");
        syms = false;
    }

    int depth = 0;
    unsigned long long count = 0;
    while (!g_interrupt) {
        regs_t regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) break;

        unsigned char code[15];
        size_t nbytes = 0;
        for (size_t off = 0; off < sizeof(code); off += 8) {
            errno = 0;
            unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)(regs.rip + off), NULL);
            if (w == (unsigned long)-1 && errno) break;
            size_t n = (sizeof(code) - off < 8) ? sizeof(code) - off : 8;
            memcpy(code + off, &w, n);
            nbytes += n;
        }

        cs_insn *insn = NULL;
        size_t nins = cs_disasm(handle, code, nbytes, regs.rip, 1, &insn);
        if (nins > 0) {
            const char *m = insn[0].mnemonic;
            if (!strncmp(m, "call", 4) || !strncmp(m, "ret", 3) || !strncmp(m, "jmp", 3)) {
                print_calltrace_line(count, depth, &insn[0], regs.rip, regs.rax, syms);
                if (!strncmp(m, "call", 4)) depth++;
                else if (!strncmp(m, "ret", 3) && depth > 0) depth--;
                count++;
            }
            cs_free(insn, nins);
        }

        if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) break;
        if (waitpid_eintr(pid, &st) == -1) break;

        if (WIFSTOPPED(st)) {
            int sig = WSTOPSIG(st);
            if (sig == SIGTRAP) continue;
            if (sig == SIGSTOP || sig == SIGCONT) { (void)kill(pid, SIGCONT); continue; }
            if (g_is_tty) printf(A_DIM "  (stopped by signal %d)\n" A_RESET, sig);
            else printf("(stopped by signal %d)\n", sig);
            if (sig == SIGSEGV) {
                siginfo_t si;
                if (ptrace(PTRACE_GETSIGINFO, pid, 0, &si) == 0)
                    fprintf(stderr, "  SIGSEGV si_addr=%p si_code=%d\n", si.si_addr, si.si_code);
                break;
            }
            continue;
        }
        if (WIFEXITED(st)) {
            printf("Process %d exited (status %d).\n", pid, WEXITSTATUS(st));
            break;
        }
        if (WIFSIGNALED(st)) {
            printf("Process %d killed by signal %d.\n", pid, WTERMSIG(st));
            break;
        }
    }

    /* Detach with signal 0: the tracee resumes without any pending SIGTRAP. */
    tracee_detach(pid, NULL);

    if (g_interrupt) {
        if (g_is_tty) printf(A_GREEN "  ★ Stopped tracing PID %d (detached; process continues).\n" A_RESET, pid);
        else printf("Stopped tracing PID %d (detached; process continues).\n", pid);
    }

    cs_close(&handle);
    if (syms) elfsym_free();
}

/* ---------------- function (symbol) tracing ---------------- */

typedef struct {
    const char *name;
    const char *sig;   /* s=string, i=int, u=uint, x/p=pointer, c=char, v=va_list, F<n>=printf-family fmt at arg n */
} fspec_t;

static const fspec_t g_fspecs[] = {
    /* printf family: F<n> = format string is argument n, remaining args are varargs */
    { "printf",    "F0" },
    { "fprintf",   "F1" },
    { "sprintf",   "F1" },
    { "snprintf",  "F2" },
    { "dprintf",   "F1" },
    { "asprintf",  "F1" },
    { "vprintf",   "s v" },
    { "vfprintf",  "p s v" },
    { "vsprintf",  "s s v" },
    { "vsnprintf", "s i s v" },
    { "vasprintf", "p s v" },
    /* strings */
    { "puts",    "s" },
    { "strlen",  "s" },
    { "strcmp",  "s s" },
    { "strncmp", "s s i" },
    { "strchr",  "s c" },
    { "strstr",  "s s" },
    { "strdup",  "s" },
    { "strcpy",  "p s" },
    { "strncpy", "p s i" },
    { "strcat",  "p s" },
    { "strncat", "p s i" },
    { "getenv",  "s" },
    { "atoi",    "s" },
    { "atol",    "s" },
    { "strtol",  "s p i" },
    { "system",  "s" },
    { "execve",  "s p p" },
    /* memory */
    { "malloc",  "i" },
    { "calloc",  "i i" },
    { "realloc", "p i" },
    { "free",    "p" },
    { "memcpy",  "p p i" },
    { "memmove", "p p i" },
    { "memset",  "p i i" },
    /* file io */
    { "open",    "s i i" },
    { "openat",  "i s i i" },
    { "creat",   "s i" },
    { "close",   "i" },
    { "read",    "i p i" },
    { "write",   "i p i" },
    { "lseek",   "i i i" },
    { "access",  "s i" },
    { "stat",    "s p" },
    { "lstat",   "s p" },
    { "fstat",   "i p" },
    { "opendir", "s" },
    { "readlink","s p i" },
    /* misc */
    { "getpid",  "" },
    { "rand",    "" },
    { "srand",   "u" },
    { "time",    "p" },
    { "sleep",   "u" },
    { "usleep",  "u" },
    { "exit",    "i" },
    { "abort",   "" },
};
#define N_FSPECS (sizeof(g_fspecs)/sizeof(g_fspecs[0]))

static const char *fspec_for(const char *name) {
    for (size_t i = 0; i < N_FSPECS; i++)
        if (!strcmp(name, g_fspecs[i].name)) return g_fspecs[i].sig;
    return NULL;
}

/* Per-function breakpoint record */
typedef struct {
    uint64_t addr;
    char name[128];
    const char *sig;
    unsigned char orig_byte;
    bool armed;
} fbp_t;

static fbp_t g_fbps[128];
static int g_nfbps = 0;

/* Return-value capture (-r): breakpoint armed at a traced function's return
   address, plus a LIFO stack of pending returns used to correlate each
   return with its call. Returns are strictly LIFO, so the stack top is
   always the next return to fire. */
typedef struct {
    uint64_t addr;
    unsigned char orig_byte;
    bool armed;
} rbp_t;

typedef struct {
    uint64_t addr;                  /* return address (instruction after call) */
    int fbp_idx;                    /* which traced function this call belongs to */
    unsigned long long call_no;
} retentry_t;

static rbp_t g_rbps[256];
static int g_nrbps = 0;
static retentry_t g_retstack[1024];
static int g_retdepth = 0;
static bool g_retval_enabled = false;

/* Get the n-th argument (0-based) of the current call.
   Args 0..5 live in GP registers, args 6+ on the stack above the return address. */
static uint64_t get_arg_val(pid_t pid, const regs_t *regs, int n) {
    switch (n) {
    case 0: return regs->rdi;
    case 1: return regs->rsi;
    case 2: return regs->rdx;
    case 3: return regs->rcx;
    case 4: return regs->r8;
    case 5: return regs->r9;
    default: {
        uint64_t v = 0;
        uint64_t sp = regs->rsp + 8 + (uint64_t)(n - 6) * 8;
        if (!read_bytes_from_pid(pid, sp, &v, 8)) return 0;
        return v;
    }}
}

/* Read the n-th SSE (XMM) register as a double. */
static bool get_fp_arg(pid_t pid, int xmm_idx, double *out) {
    struct user_fpregs_struct fp;
    if (ptrace(PTRACE_GETFPREGS, pid, 0, &fp) == -1) return false;
    memcpy(out, &fp.xmm_space[xmm_idx * 4], sizeof(double));
    return true;
}

/* Read a NUL-terminated string from the target into buf (cap bytes). */
static size_t read_pid_cstr(pid_t pid, uint64_t addr, unsigned char *buf, size_t cap) {
    size_t got = 0;
    uint64_t pos = addr;
    while (got < cap) {
        size_t want = cap - got;
        size_t to_page = 0x1000 - ((size_t)pos & 0xfff);
        if (to_page < want) want = to_page;
        if (want == 0) want = 1;
        if (!read_bytes_from_pid(pid, pos, buf + got, want)) {
            if (want == 1) break;
            want = 1;
            if (!read_bytes_from_pid(pid, pos, buf + got, 1)) break;
        }
        got += want;
        if (memchr(buf + got - want, '\0', want)) break;
        pos += want;
    }
    if (got == 0) return 0;
    if (buf[got - 1] != '\0') {
        if (got < cap) buf[got] = '\0';
        else buf[got - 1] = '\0';
    }
    return got;
}

static void print_pid_str(pid_t pid, uint64_t addr) {
    unsigned char raw[256];
    size_t got = read_pid_cstr(pid, addr, raw, sizeof(raw) - 1);
    if (got == 0) { printf("0x%llx", (unsigned long long)addr); return; }
    bool truncated = (memchr(raw, '\0', got) == NULL);
    size_t len = strnlen((char*)raw, got);
    printf("\"");
    size_t shown = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = raw[i];
        if (shown >= 80) break;
        switch (c) {
        case '"':  printf("\\\""); shown++; break;
        case '\\': printf("\\\\"); shown++; break;
        case '\n': printf("\\n"); shown++; break;
        case '\t': printf("\\t"); shown++; break;
        default:
            if (c >= 0x20 && c < 0x7f) { putchar(c); shown++; }
            else { printf("\\x%02x", c); shown += 4; }
            break;
        }
    }
    if (truncated || len > 80) printf("...");
    printf("\"");
}

/* Print a single argument given its type tag (see fspec_t). */
static void print_arg(pid_t pid, const regs_t *regs, char t, int arg_idx) {
    switch (t) {
    case 's': {
        uint64_t a = get_arg_val(pid, regs, arg_idx);
        print_pid_str(pid, a);
        break;
    }
    case 'p': case 'x': {
        uint64_t a = get_arg_val(pid, regs, arg_idx);
        printf("0x%llx", (unsigned long long)a);
        break;
    }
    case 'c': {
        uint64_t a = get_arg_val(pid, regs, arg_idx);
        unsigned char c = (unsigned char)a;
        if (c >= 0x20 && c < 0x7f) printf("'%c'", c);
        else printf("'\\x%02x'", c);
        break;
    }
    case 'i': {
        uint64_t a = get_arg_val(pid, regs, arg_idx);
        printf("%lld", (long long)a);
        break;
    }
    case 'u': {
        uint64_t a = get_arg_val(pid, regs, arg_idx);
        printf("%llu", (unsigned long long)a);
        break;
    }
    case 'v': {
        uint64_t a = get_arg_val(pid, regs, arg_idx);
        printf("va_list 0x%llx", (unsigned long long)a);
        break;
    }
    default:
        break;
    }
}

/* Print a printf-family call: the format string plus the varargs it consumes.
   base_gp = GP-register index of the first variadic argument (named args use rdi..). */
static void print_fmt_variadic(pid_t pid, const regs_t *regs, uint64_t fmt_addr, int base_gp) {
    unsigned char fmt[256];
    size_t got = read_pid_cstr(pid, fmt_addr, fmt, sizeof(fmt) - 1);
    if (got == 0) { printf("0x%llx", (unsigned long long)fmt_addr); return; }
    bool truncated = (memchr(fmt, '\0', got) == NULL);
    size_t flen = strnlen((char*)fmt, got);

    printf("\"");
    for (size_t i = 0; i < flen; i++) {
        unsigned char c = fmt[i];
        if (c == '"') printf("\\\"");
        else if (c == '\\') printf("\\\\");
        else if (c == '\n') printf("\\n");
        else if (c >= 0x20 && c < 0x7f) putchar(c);
        else printf("\\x%02x", c);
    }
    if (truncated) printf("...");
    printf("\"");

    /* Parse conversions to determine how many/which varargs to print. */
    int gp = 0, fp = 0;
    size_t i = 0;
    while (i < flen) {
        if (fmt[i] != '%') { i++; continue; }
        i++;  /* skip '%' */
        while (i < flen && strchr("-+ #0'", fmt[i])) i++;            /* flags */
        if (i < flen && fmt[i] == '*') {                             /* width */
            (void)get_arg_val(pid, regs, base_gp + gp); gp++;
            i++;
        } else {
            while (i < flen && isdigit(fmt[i])) i++;
        }
        if (i < flen && fmt[i] == '.') {                             /* precision */
            i++;
            if (i < flen && fmt[i] == '*') {
                (void)get_arg_val(pid, regs, base_gp + gp); gp++;
                i++;
            } else {
                while (i < flen && isdigit(fmt[i])) i++;
            }
        }
        while (i < flen && strchr("hlLzjt", fmt[i])) {               /* length */
            if ((fmt[i] == 'l' || fmt[i] == 'h') && i + 1 < flen && fmt[i + 1] == fmt[i]) i++;
            i++;
        }
        if (i >= flen) break;
        char conv = fmt[i];
        if (conv == '%') { i++; continue; }
        uint64_t a;
        switch (conv) {
        case 's': a = get_arg_val(pid, regs, base_gp + gp); gp++; printf(", "); print_pid_str(pid, a); break;
        case 'c': a = get_arg_val(pid, regs, base_gp + gp); gp++; printf(", '%c'", (unsigned char)a); break;
        case 'p': case 'n': a = get_arg_val(pid, regs, base_gp + gp); gp++; printf(", 0x%llx", (unsigned long long)a); break;
        case 'd': case 'i': a = get_arg_val(pid, regs, base_gp + gp); gp++; printf(", %lld", (long long)a); break;
        case 'u': a = get_arg_val(pid, regs, base_gp + gp); gp++; printf(", %llu", (unsigned long long)a); break;
        case 'o': a = get_arg_val(pid, regs, base_gp + gp); gp++; printf(", %llo", (unsigned long long)a); break;
        case 'x': case 'X': a = get_arg_val(pid, regs, base_gp + gp); gp++; printf(", 0x%llx", (unsigned long long)a); break;
        case 'e': case 'E': case 'f': case 'F': case 'g': case 'G': case 'a': case 'A': {
            double d = 0;
            if (get_fp_arg(pid, fp, &d)) printf(", %g", d);
            else printf(", <unreadable fp>");
            fp++;
            break;
        }
        default: break;
        }
        i++;
    }
}

/* Arm an int3 breakpoint at a traced function's return address and record the
   pending return so we can correlate the later hit with its call. ret_addr was
   captured from the stack at function entry (before the prologue ran). */
static void arm_return_bp(pid_t pid, uint64_t ret_addr, int fbp_idx, unsigned long long call_no) {
    if (ret_addr == 0) return;

    int ridx = -1;
    for (int i = 0; i < g_nrbps; i++)
        if (g_rbps[i].addr == ret_addr) { ridx = i; break; }
    if (ridx < 0) {
        if (g_nrbps >= (int)(sizeof(g_rbps)/sizeof(g_rbps[0]))) return;   /* table full */
        ridx = g_nrbps++;
        g_rbps[ridx].addr = ret_addr;
        g_rbps[ridx].orig_byte = 0;
        g_rbps[ridx].armed = false;
    }
    rbp_t *r = &g_rbps[ridx];

    if (!r->armed) {
        errno = 0;
        unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)ret_addr, NULL);
        if (w == (unsigned long)-1 && errno) return;
        r->orig_byte = (unsigned char)(w & 0xff);
        if (ptrace(PTRACE_POKETEXT, pid, (void*)ret_addr, (void*)((w & ~0xffUL) | 0xccUL)) == -1) return;
        r->armed = true;
    }

    if (g_retdepth < (int)(sizeof(g_retstack)/sizeof(g_retstack[0]))) {
        g_retstack[g_retdepth].addr = ret_addr;
        g_retstack[g_retdepth].fbp_idx = fbp_idx;
        g_retstack[g_retdepth].call_no = call_no;
        g_retdepth++;
    }
}

/* Handle a return-address breakpoint hit: pop the matching pending return,
   print the value in rax, then restore-single-step-rearm like handle_fbp_hit.
   Registers keep the post-return state; only RIP is rewound past the int3. */
static int handle_rbp_hit(pid_t pid, int ridx) {
    rbp_t *r = &g_rbps[ridx];

    regs_t regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) return 0;
    uint64_t rax = regs.rax;

    int fbp_idx = 0;
    unsigned long long call_no = 0;
    if (g_retdepth > 0 && g_retstack[g_retdepth - 1].addr == r->addr) {
        g_retdepth--;
        fbp_idx = g_retstack[g_retdepth].fbp_idx;
        call_no = g_retstack[g_retdepth].call_no;
    } else {
        for (int i = g_retdepth - 1; i >= 0; i--) {
            if (g_retstack[i].addr == r->addr) {
                fbp_idx = g_retstack[i].fbp_idx;
                call_no = g_retstack[i].call_no;
                memmove(&g_retstack[i], &g_retstack[i + 1],
                        (size_t)(g_retdepth - i - 1) * sizeof(g_retstack[0]));
                g_retdepth--;
                break;
            }
        }
    }

    const char *name = g_fbps[fbp_idx].name;
    symres_t sr = elfsym_resolve(rax);
    if (g_is_tty) {
        printf(A_CYAN "[%06llu]" A_RESET " %s() -> 0x%llx", call_no, name, (unsigned long long)rax);
        if (sr.found) printf(A_DIM "  (%s+0x%llx)" A_RESET, sr.name, (unsigned long long)sr.delta);
    } else {
        printf("[%06llu] %s() -> 0x%llx", call_no, name, (unsigned long long)rax);
        if (sr.found) printf("  (%s+0x%llx)", sr.name, (unsigned long long)sr.delta);
    }
    printf("\n");
    fflush(stdout);

    /* Restore the original byte and re-point RIP at the return site: the int3
       advanced RIP past the breakpoint byte, so step back to re-execute the
       real instruction. Other registers already hold the post-return state. */
    uint64_t addr = r->addr;
    regs.rip -= 1;
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) return 0;

    errno = 0;
    unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
    if (!(w == (unsigned long)-1 && errno)) {
        unsigned long nw = (w & ~0xffUL) | (unsigned long)r->orig_byte;
        ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)nw);
    }

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) return 0;

    int st;
    int deliver = 0;
    while (1) {
        if (waitpid_eintr(pid, &st) == -1) break;
        if (!WIFSTOPPED(st)) break;
        int sig = WSTOPSIG(st);
        if (sig == SIGTRAP) break;                      /* done stepping */
        if (sig == SIGSTOP || sig == SIGCONT) { (void)kill(pid, SIGCONT); continue; }
        deliver = sig;                                  /* interrupted by a real signal */
        break;
    }

    /* Re-arm only while another pending return still targets this address. */
    bool still_pending = false;
    for (int i = 0; i < g_retdepth; i++)
        if (g_retstack[i].addr == r->addr) { still_pending = true; break; }
    if (still_pending) {
        errno = 0;
        w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
        if (!(w == (unsigned long)-1 && errno)) {
            unsigned long nw = (w & ~0xffUL) | 0xccUL;
            ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)nw);
        }
        r->armed = true;
    } else {
        r->armed = false;
    }
    return deliver;
}

/* Handle a breakpoint hit at function g_fbps[idx]: print args, then do the
   restore-single-step-rearm dance. Returns a signal to deliver on the next
   PTRACE_CONT (0 = none). */
static int handle_fbp_hit(pid_t pid, int idx, unsigned long long call_no) {
    fbp_t *b = &g_fbps[idx];

    regs_t regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) return 0;
    regs.rip -= 1;  /* point back at the function entry */

    /* Capture the return address now: rsp still points at it here, but the
       single-step below runs the prologue (e.g. push rbp) and moves rsp. */
    uint64_t ret_addr = 0;
    if (g_retval_enabled) (void)read_bytes_from_pid(pid, regs.rsp, &ret_addr, 8);

    if (g_is_tty) printf(A_CYAN "[%06llu]" A_RESET " %s(", call_no, b->name);
    else printf("[%06llu] %s(", call_no, b->name);

    if (b->sig && b->sig[0] == 'F') {
        int fmt_idx = b->sig[1] - '0';
        uint64_t fmt_addr = get_arg_val(pid, &regs, fmt_idx);
        print_fmt_variadic(pid, &regs, fmt_addr, fmt_idx + 1);
    } else if (b->sig) {
        int arg = 0;
        bool first = true;
        for (const char *s = b->sig; *s; s++) {
            if (*s == ' ') continue;
            if (!first) printf(", ");
            print_arg(pid, &regs, *s, arg);
            first = false;
            arg++;
        }
    } else {
        /* unknown function: show the raw GP args as hex */
        for (int i = 0; i < 6; i++) {
            if (i) printf(", ");
            printf("0x%llx", (unsigned long long)get_arg_val(pid, &regs, i));
        }
    }
    printf(")\n");
    fflush(stdout);

    /* Restore the original first instruction and single-step over it. */
    uint64_t addr = b->addr;
    errno = 0;
    unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
    if (!(w == (unsigned long)-1 && errno)) {
        unsigned long nw = (w & ~0xffUL) | (unsigned long)b->orig_byte;
        ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)nw);
    }
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) return 0;

    if (ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL) == -1) return 0;

    int st;
    int deliver = 0;
    while (1) {
        if (waitpid_eintr(pid, &st) == -1) break;
        if (!WIFSTOPPED(st)) break;
        int sig = WSTOPSIG(st);
        if (sig == SIGTRAP) break;                      /* done stepping */
        if (sig == SIGSTOP || sig == SIGCONT) { (void)kill(pid, SIGCONT); continue; }
        deliver = sig;                                  /* interrupted by a real signal */
        break;
    }

    /* Re-arm the breakpoint. */
    errno = 0;
    w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
    if (!(w == (unsigned long)-1 && errno)) {
        unsigned long nw = (w & ~0xffUL) | 0xccUL;
        ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)nw);
    }
    b->armed = true;

    if (g_retval_enabled) arm_return_bp(pid, ret_addr, idx, call_no);
    return deliver;
}

void cmd_ftrace(pid_t pid, int nnames, char **names, bool retval) {
    g_nfbps = 0;
    g_nrbps = 0;
    g_retdepth = 0;
    g_retval_enabled = retval;

    /* Symbol table for the static-symbol fallback: dlsym cannot see .symtab
       symbols, so ftrace uses it to resolve names like main/deep_function. */
    bool have_syms = (elfsym_init(pid) == 0);

    /* Resolve each requested symbol: dlsym first (honors interposition),
       then the static symbol table. */
    for (int i = 0; i < nnames && g_nfbps < (int)(sizeof(g_fbps)/sizeof(g_fbps[0])); i++) {
        uint64_t a = cmd_resolve(pid, names[i], true);
        if (a == 0 && have_syms) a = elfsym_lookup(names[i]);
        if (a == 0) {
            fprintf(stderr, "ftrace: unresolved symbol '%s'\n", names[i]);
            continue;
        }
        fbp_t *b = &g_fbps[g_nfbps];
        b->addr = a;
        snprintf(b->name, sizeof(b->name), "%s", names[i]);
        b->sig = fspec_for(names[i]);
        b->armed = false;
        g_nfbps++;
    }
    if (g_nfbps == 0) { fprintf(stderr, "ftrace: no resolvable symbols\n"); return; }

    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "ftrace: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "ftrace: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH ftrace");
        return;
    }
    int st;
    if (waitpid_eintr(pid, &st) == -1) {
        perror("ftrace: waitpid attach");
        tracee_detach(pid, NULL);
        return;
    }

    /* Ctrl+C stops the trace cleanly instead of killing us while the tracee
       is stopped at a breakpoint (which would deliver SIGTRAP on detach). */
    install_sigint_stop();

    /* Arm a breakpoint at each function entry. */
    int armed = 0;
    for (int i = 0; i < g_nfbps; i++) {
        fbp_t *b = &g_fbps[i];
        errno = 0;
        unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)b->addr, NULL);
        if (w == (unsigned long)-1 && errno) continue;
        b->orig_byte = (unsigned char)(w & 0xff);
        unsigned long nw = (w & ~0xffUL) | 0xccUL;
        if (ptrace(PTRACE_POKETEXT, pid, (void*)b->addr, (void*)nw) == -1) continue;
        b->armed = true;
        armed++;
    }
    if (armed == 0) {
        fprintf(stderr, "ftrace: could not arm any breakpoints\n");
        tracee_detach(pid, NULL);
        return;
    }

    if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Tracing %d function(s) in PID %d. Press Ctrl+C to stop.\n" A_RESET, armed, pid);
    else printf("Tracing %d function(s) in PID %d...\n", armed, pid);

    unsigned long long calls = 0;
    int deliver = 0;
    while (!g_interrupt) {
        if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)deliver) == -1) break;
        deliver = 0;
        if (waitpid_eintr(pid, &st) == -1) break;

        if (WIFEXITED(st)) {
            printf("Process %d exited (status %d).\n", pid, WEXITSTATUS(st));
            break;
        }
        if (WIFSIGNALED(st)) {
            printf("Process %d killed by signal %d.\n", pid, WTERMSIG(st));
            break;
        }
        if (!WIFSTOPPED(st)) continue;

        int sig = WSTOPSIG(st);
        if (sig == SIGSTOP || sig == SIGCONT) { (void)kill(pid, SIGCONT); continue; }

        if (sig != SIGTRAP) {
            if (g_is_tty) printf(A_DIM "  (stopped by signal %d)\n" A_RESET, sig);
            else printf("(stopped by signal %d)\n", sig);
            deliver = sig;   /* let the target's handler see it */
            continue;
        }

        regs_t regs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) break;
        uint64_t bp = regs.rip - 1;

        /* Return-address breakpoints first: a pending return is more specific
           than a function entry at the same address. */
        int ridx = -1;
        for (int i = 0; i < g_nrbps; i++) {
            if (g_rbps[i].armed && g_rbps[i].addr == bp) { ridx = i; break; }
        }
        if (ridx >= 0) {
            deliver = handle_rbp_hit(pid, ridx);
            if (g_interrupt) break;   /* Ctrl+C landed during the single-step dance */
            continue;
        }

        int idx = -1;
        for (int i = 0; i < g_nfbps; i++) {
            if (g_fbps[i].addr == bp) { idx = i; break; }
        }

        if (idx < 0) {
            /* not one of ours: deliver the stray SIGTRAP */
            if (g_is_tty) printf(A_DIM "  (unexpected SIGTRAP at 0x%llx, delivered)\n" A_RESET,
                                 (unsigned long long)regs.rip);
            else printf("(unexpected SIGTRAP at 0x%llx, delivered)\n", (unsigned long long)regs.rip);
            deliver = SIGTRAP;
            continue;
        }

        calls++;
        deliver = handle_fbp_hit(pid, idx, calls);
        if (g_interrupt) break;   /* Ctrl+C landed during the single-step dance */
    }

    /* Restore all breakpoints and detach cleanly. */
    for (int i = 0; i < g_nfbps; i++) {
        if (!g_fbps[i].armed) continue;
        errno = 0;
        unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)g_fbps[i].addr, NULL);
        if (w == (unsigned long)-1 && errno) continue;
        unsigned long nw = (w & ~0xffUL) | (unsigned long)g_fbps[i].orig_byte;
        ptrace(PTRACE_POKETEXT, pid, (void*)g_fbps[i].addr, (void*)nw);
        g_fbps[i].armed = false;
    }
    /* Restore any return-address breakpoints. */
    for (int i = 0; i < g_nrbps; i++) {
        if (!g_rbps[i].armed) continue;
        errno = 0;
        unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)g_rbps[i].addr, NULL);
        if (w == (unsigned long)-1 && errno) continue;
        unsigned long nw = (w & ~0xffUL) | (unsigned long)g_rbps[i].orig_byte;
        ptrace(PTRACE_POKETEXT, pid, (void*)g_rbps[i].addr, (void*)nw);
        g_rbps[i].armed = false;
    }
    tracee_detach(pid, NULL);

    if (g_interrupt) {
        if (g_is_tty) printf(A_GREEN "  ★ Stopped tracing PID %d (detached; process continues).\n" A_RESET, pid);
        else printf("Stopped tracing PID %d (detached; process continues).\n", pid);
    }
}

/* Finish / step-out: run until the current function returns.
   Reuses the return-address breakpoint machinery from ftrace's -r capture:
   a single int3 is armed at the current frame's return address (read from
   [rbp+8]) and, when it fires, the value in rax is printed and the process is
   detached just past the return, inside the caller. Ctrl+C aborts and detaches
   cleanly (never SIGTERM, which would leak the armed int3 into the tracee). */
static bool exec_addr_in(uint64_t addr, const uint64_t (*exec)[2], int nexec) {
    for (int i = 0; i < nexec; i++)
        if (addr >= exec[i][0] && addr < exec[i][1]) return true;
    return false;
}

/* Find the return address of the frame we are currently stopped in.
   Frame-pointer functions keep it at [rbp+8], but frameless (-O2 leaf)
   functions leave it somewhere above rsp, so scan the stack up from rsp for
   the first slot whose value lands in an executable mapping.  When that slot
   sits at or above a valid in-stack rbp, [rbp+8] is authoritative. */
static uint64_t find_return_address(pid_t pid, const regs_t *regs) {
    uint64_t rsp = regs->rsp, rbp = regs->rbp;
    uint64_t exec[128][2];
    int nexec = 0;
    uint64_t stack_end = 0;

    procmaps_iterator *it = parse_maps_live(pid);
    if (!it) return 0;
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        uint64_t s = (uint64_t)map->addr_start, e = (uint64_t)map->addr_end;
        if (stack_end == 0 && rsp >= s && rsp < e) stack_end = e;
        if (map->is_x && nexec < (int)(sizeof(exec) / sizeof(exec[0]))) {
            exec[nexec][0] = s;
            exec[nexec][1] = e;
            nexec++;
        }
    }
    pmparser_free(it);
    if (stack_end == 0 || nexec == 0) return 0;

    uint64_t limit = stack_end;
    if (limit - rsp > 0x10000) limit = rsp + 0x10000;

    uint64_t scan_pos = 0, scan_val = 0;
    for (uint64_t a = rsp & ~7ULL; a + 8 <= limit; a += 8) {
        uint64_t v = 0;
        if (!read_bytes_from_pid(pid, a, &v, 8)) break;
        if (exec_addr_in(v, exec, nexec)) { scan_pos = a; scan_val = v; break; }
    }

    /* If the slot is at/above a frame base, prefer [rbp+8] when it also points
       into an executable mapping. */
    if (scan_val && rbp > rsp && rbp < stack_end && scan_pos >= rbp) {
        uint64_t r8 = 0;
        if (read_bytes_from_pid(pid, rbp + 8, &r8, 8) && exec_addr_in(r8, exec, nexec))
            return r8;
    }
    return scan_val;
}

void cmd_finish(pid_t pid) {
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "finish: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "finish: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH finish");
        return;
    }
    int st;
    if (waitpid_eintr(pid, &st) == -1) {
        perror("finish: waitpid attach");
        tracee_detach(pid, NULL);
        return;
    }

    /* Ctrl+C aborts the wait instead of killing us while the tracee is
       stopped at the return breakpoint (which would leak SIGTRAP on detach). */
    install_sigint_stop();

    regs_t regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        perror("finish: PTRACE_GETREGS");
        tracee_detach(pid, NULL);
        return;
    }

    uint64_t ret_addr = find_return_address(pid, &regs);
    if (ret_addr == 0) {
        fprintf(stderr, "finish: could not find the current frame's return address on the stack\n");
        tracee_detach(pid, NULL);
        return;
    }

    char fname[128];
    symres_t cur = { 0 };
    if (elfsym_init(pid) == 0) {
        cur = elfsym_resolve(regs.rip);
        if (cur.found) snprintf(fname, sizeof(fname), "%s", cur.name);
        else snprintf(fname, sizeof(fname), "<unknown@0x%llx>", (unsigned long long)regs.rip);
    } else {
        snprintf(fname, sizeof(fname), "<unknown@0x%llx>", (unsigned long long)regs.rip);
    }

    if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Finish" A_RESET);
    else printf("Finish");
    if (cur.found && cur.delta)
        printf(": running %s+0x%llx", fname, (unsigned long long)cur.delta);
    else
        printf(": running %s", fname);
    printf(" until it returns (ret addr 0x%016llx). Ctrl+C to abort.\n",
           (unsigned long long)ret_addr);

    /* Arm a single return-address breakpoint through the same machinery ftrace's
       -r uses: one pending return, reported via g_fbps[0].name. */
    g_nfbps = 1;
    g_nrbps = 0;
    g_retdepth = 0;
    g_retval_enabled = false;
    g_fbps[0].addr = 0;
    g_fbps[0].armed = false;
    snprintf(g_fbps[0].name, sizeof(g_fbps[0].name), "%s", fname);
    arm_return_bp(pid, ret_addr, 0, 1);
    if (g_nrbps == 0 || !g_rbps[0].armed) {
        fprintf(stderr, "finish: could not arm return-address breakpoint at 0x%llx\n",
                (unsigned long long)ret_addr);
        tracee_detach(pid, NULL);
        return;
    }

    int deliver = 0;
    bool running = false;
    while (!g_interrupt) {
        if (ptrace(PTRACE_CONT, pid, NULL, (void*)(long)deliver) == -1) break;
        deliver = 0;
        running = true;
        pid_t r;
        do {
            r = waitpid(pid, &st, __WALL);
        } while (r == -1 && errno == EINTR && !g_interrupt);
        if (r == -1) break;   /* Ctrl+C while the tracee is running, or error */
        running = false;

        if (WIFEXITED(st)) {
            printf("Process %d exited (status %d).\n", pid, WEXITSTATUS(st));
            break;
        }
        if (WIFSIGNALED(st)) {
            printf("Process %d killed by signal %d.\n", pid, WTERMSIG(st));
            break;
        }
        if (!WIFSTOPPED(st)) continue;

        int sig = WSTOPSIG(st);
        if (sig == SIGSTOP || sig == SIGCONT) { (void)kill(pid, SIGCONT); continue; }

        if (sig != SIGTRAP) {
            if (g_is_tty) printf(A_DIM "  (stopped by signal %d)\n" A_RESET, sig);
            else printf("(stopped by signal %d)\n", sig);
            deliver = sig;   /* let the target's handler see it */
            continue;
        }

        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) break;
        uint64_t bp = regs.rip - 1;

        int ridx = -1;
        for (int i = 0; i < g_nrbps; i++) {
            if (g_rbps[i].armed && g_rbps[i].addr == bp) { ridx = i; break; }
        }
        if (ridx >= 0) {
            /* Function returned: print the value in rax, then restore/single-step. */
            (void)handle_rbp_hit(pid, ridx);
            break;
        }

        /* Not one of ours: deliver the stray SIGTRAP. */
        if (g_is_tty) printf(A_DIM "  (unexpected SIGTRAP at 0x%llx, delivered)\n" A_RESET,
                             (unsigned long long)regs.rip);
        else printf("(unexpected SIGTRAP at 0x%llx, delivered)\n", (unsigned long long)regs.rip);
        deliver = SIGTRAP;
    }

    /* On Ctrl+C the tracee may still be running with the return breakpoint
       armed: stop it so the byte can be restored before detaching. */
    if (running) {
        (void)kill(pid, SIGSTOP);
        pid_t r;
        do { r = waitpid(pid, &st, __WALL); } while (r == -1 && errno == EINTR);
    }

    /* Restore any still-armed return breakpoint and detach cleanly. */
    for (int i = 0; i < g_nrbps; i++) {
        if (!g_rbps[i].armed) continue;
        errno = 0;
        unsigned long w = (unsigned long)ptrace(PTRACE_PEEKTEXT, pid, (void*)g_rbps[i].addr, NULL);
        if (w == (unsigned long)-1 && errno) continue;
        unsigned long nw = (w & ~0xffUL) | (unsigned long)g_rbps[i].orig_byte;
        ptrace(PTRACE_POKETEXT, pid, (void*)g_rbps[i].addr, (void*)nw);
        g_rbps[i].armed = false;
    }
    tracee_detach(pid, NULL);

    if (g_interrupt) {
        if (g_is_tty) printf(A_GREEN "  ★ Aborted finish on PID %d (detached; process continues).\n" A_RESET, pid);
        else printf("Aborted finish on PID %d (detached; process continues).\n", pid);
    } else {
        if (g_is_tty) printf(A_GREEN "  ★ Finished %s in PID %d (detached; process continues).\n" A_RESET, fname, pid);
        else printf("Finished %s in PID %d (detached; process continues).\n", fname, pid);
    }
}

void cmd_mprotect(pid_t pid, uint64_t addr, size_t len, const char *perms_str) {
    int prot = parse_perms(perms_str);
    if (prot < 0) { fprintf(stderr, "mprotect: invalid perms '%s'\n", perms_str); return; }

    
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "mprotect: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "mprotect: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH mprotect");
        return;
    }
    int st; waitpid(pid, &st, __WALL);

    long ret = remote_syscall_x64(pid, __NR_mprotect, addr, len, prot, 0, 0, 0);

    if (ret == 0) {
        if (g_is_tty) printf(A_BOLD A_GREEN "  ★ mprotect(0x%016llx, %zu, %s) SUCCESS\n" A_RESET,
                        (unsigned long long)addr, len, perms_str);
        else printf("mprotect(0x%016llx, %zu, %s) SUCCESS\n", (unsigned long long)addr, len, perms_str);
    } else {
        fprintf(stderr, "mprotect failed: %ld\n", ret);
    }

    tracee_detach(pid, NULL);
}

void cmd_backtrace(pid_t pid, bool pause) {
    
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "backtrace: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "backtrace: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH backtrace");
        return;
    }
    int st; tracee_wait(pid, &st);

    regs_t regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        perror("backtrace: PTRACE_GETREGS");
        tracee_detach(pid, NULL);
        return;
    }

    if (g_is_tty) printf(A_BOLD A_CYAN "  ◆ Backtrace for PID %d\n" A_RESET, pid);
    else printf("Backtrace for PID %d\n", pid);

    uint64_t rbp = regs.rbp;
    uint64_t rip = regs.rip;
    int frame = 0;

    while (frame < 20) {
        printf("  #%-2d %016llx", frame++, (unsigned long long)rip);
        procmaps_iterator *it = parse_maps_live(pid);
        if (it) {
            procmaps_struct *map;
            while ((map = pmparser_next(it)) != NULL) {
                if (rip >= (uint64_t)map->addr_start && rip < (uint64_t)map->addr_end) {
                    printf(" in %s", map->pathname && map->pathname[0] ? map->pathname : "[anon]");
                    break;
                }
            }
            pmparser_free(it);
        }
        printf("\n");

        if (rbp == 0) break;

        uint64_t next_rbp = 0;
        uint64_t next_rip = 0;
        if (!read_bytes_from_pid(pid, rbp, &next_rbp, 8)) break;
        if (!read_bytes_from_pid(pid, rbp + 8, &next_rip, 8)) break;

        if (next_rbp <= rbp) break;
        rbp = next_rbp;
        rip = next_rip;
    }

    tracee_detach(pid, (void*)(pause ? (long)SIGSTOP : 0));
}

/**
 * @brief Upload data to remote process by allocating memory and writing to it
 * 
 * Uses mmap to allocate memory in the target process, then writes the provided
 * data to that memory. Useful for uploading strings, shellcode, or any data
 * that needs to exist in the remote process's address space.
 * 
 * @param pid Target process ID
 * @param data Data to write
 * @param len Number of bytes to write
 * @param prot Protection flags (default: PROT_READ|PROT_WRITE)
 * @return Remote address where data was written, or 0 on failure
 */
uint64_t cmd_upload(pid_t pid, const void *data, size_t len, int prot) {
    if (prot == 0) prot = PROT_READ | PROT_WRITE;

    bool was_attached = false;
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM || errno == EBUSY) was_attached = true;
        else { perror("upload: ATTACH"); return 0; }
    }
    if (!was_attached) { int st; waitpid(pid, &st, __WALL); }

    uint64_t remote_addr = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, len,
        prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)remote_addr < 0) {
        fprintf(stderr, "upload: mmap failed (ret=%ld)\n", (long)remote_addr);
        if (!was_attached) tracee_detach(pid, NULL);
        return 0;
    }

    if (!write_bytes_to_pid(pid, remote_addr, data, len)) {
        fprintf(stderr, "upload: write failed at 0x%016llx\n", (unsigned long long)remote_addr);
        remote_syscall_x64(pid, __NR_munmap, remote_addr, len, 0, 0, 0, 0);
        if (!was_attached) tracee_detach(pid, NULL);
        return 0;
    }

    if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Uploaded %zu bytes to 0x%016llx\n" A_RESET,
            len, (unsigned long long)remote_addr);
    else printf("Uploaded %zu bytes to 0x%016llx\n", len, (unsigned long long)remote_addr);

    if (!was_attached) tracee_detach(pid, NULL);
    return remote_addr;
}

/**
 * @brief Resolve a symbol address in a remote process using dlsym
 * 
 * Resolves a symbol by:
 * 1. Finding libc base in both local and remote processes
 * 2. Calculating offset to dlsym in libc
 * 3. Uploading the symbol name string to remote process
 * 4. Calling dlsym(RTLD_DEFAULT, symbol_name) in remote process
 * 
 * @param pid Target process ID
 * @param symbol_name Symbol name to resolve (e.g., "printf", "system")
 * @return Resolved symbol address, or 0 on failure
 */
uint64_t cmd_resolve(pid_t pid, const char *symbol_name, bool quiet) {
    char line[1024];

    uint64_t local_libc = 0;
    FILE *lf = fopen("/proc/self/maps", "r");
    while (lf && fgets(line, sizeof(line), lf)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            if (sscanf(line, "%lx-", &local_libc) == 1) break;
        }
    }
    if (lf) fclose(lf);

    uint64_t remote_libc = 0;
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *rf = fopen(maps_path, "r");
    while (rf && fgets(line, sizeof(line), rf)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            if (sscanf(line, "%lx-", &remote_libc) == 1) break;
        }
    }
    if (rf) fclose(rf);

    if (local_libc == 0 || remote_libc == 0) {
        fprintf(stderr, "resolve: couldn't find libc\n");
        return 0;
    }

    void *local_dlsym = dlsym(RTLD_DEFAULT, "dlsym");
    if (!local_dlsym) {
        fprintf(stderr, "resolve: couldn't find local dlsym\n");
        return 0;
    }

    uint64_t dlsym_offset = (uint64_t)local_dlsym - local_libc;
    uint64_t remote_dlsym = remote_libc + dlsym_offset;

    bool was_attached = false;
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM || errno == EBUSY) was_attached = true;
        else { perror("resolve: ATTACH"); return 0; }
    }
    if (!was_attached) { int st; waitpid(pid, &st, __WALL); }

    size_t name_len = strlen(symbol_name) + 1;
    uint64_t name_addr = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, name_len,
        PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)name_addr < 0) {
        fprintf(stderr, "resolve: mmap failed\n");
        if (!was_attached) tracee_detach(pid, NULL);
        return 0;
    }

    if (!write_bytes_to_pid(pid, name_addr, symbol_name, name_len)) {
        fprintf(stderr, "resolve: write symbol name failed\n");
        remote_syscall_x64(pid, __NR_munmap, name_addr, name_len, 0, 0, 0, 0);
        if (!was_attached) tracee_detach(pid, NULL);
        return 0;
    }

    char arg0[32], arg1[32];
    snprintf(arg0, sizeof(arg0), "0x0");       // RTLD_DEFAULT
    snprintf(arg1, sizeof(arg1), "0x%lx", name_addr);
    char *dlsym_argv[] = { arg0, arg1 };
    uint64_t result = 0;

    cmd_call_ret(pid, remote_dlsym, 2, dlsym_argv, false, &result, quiet);

    remote_syscall_x64(pid, __NR_munmap, name_addr, name_len, 0, 0, 0, 0);

    if (result == 0) {
        if (!quiet) fprintf(stderr, "resolve: dlsym failed for '%s'\n", symbol_name);
    } else {
        if (!quiet) {
            if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Resolved '%s' -> 0x%016llx\n" A_RESET,
                    symbol_name, (unsigned long long)result);
            else printf("Resolved '%s' -> 0x%016llx\n", symbol_name, (unsigned long long)result);
        }
    }

    if (!was_attached) tracee_detach(pid, NULL);
    return result;
}

void cmd_signals(pid_t pid) {
    char path[512]; snprintf(path, sizeof(path), "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    if (!f) { perror("signals: fopen status"); return; }

    if (g_is_tty) printf(A_BOLD A_CYAN "  ◆ Signal State for PID %d\n" A_RESET, pid);
    else printf("Signal State for PID %d\n", pid);

    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Sig", 3) == 0 || strncmp(line, "ShdPnd", 6) == 0) {
            printf("  %s", line);
        }
    }
    fclose(f);
    printf("\nNote: SigPnd (Pending), SigBlk (Blocked), SigIgn (Ignored), SigCgt (Caught)\n");
}

void cmd_fds(pid_t pid) {
    
    char fd_path[512];
    snprintf(fd_path, sizeof(fd_path), "/proc/%d/fd", pid);
    DIR *d = opendir(fd_path);
    if (!d) {
        if (errno == ENOENT) fprintf(stderr, "fds: process %d not found\n", pid);
        else perror("fds: opendir");
        return;
    }

    if (g_is_tty) printf(A_BOLD A_CYAN "  ◆ Open File Descriptors for PID %d\n" A_RESET, pid);
    else printf("Open File Descriptors for PID %d\n", pid);
    printf("  %-4s  %-10s  %s\n", "FD", "OFFSET", "TARGET");
    printf("  ────  ──────────  ──────────────────────\n");

    struct dirent *de;
    while ((de = readdir(d))) {
        if (de->d_name[0] == '.') continue;
        int fd = atoi(de->d_name);
        char link[1024];
        char link_path[512];
        snprintf(link_path, sizeof(link_path), "/proc/%d/fd/%d", pid, fd);
        ssize_t len = readlink(link_path, link, sizeof(link)-1);
        if (len != -1) {
            link[len] = '\0';
            
            long long offset = 0;
            char info_path[512];
            snprintf(info_path, sizeof(info_path), "/proc/%d/fdinfo/%d", pid, fd);
            FILE *finfo = fopen(info_path, "r");
            if (finfo) {
                char line[256];
                while (fgets(line, sizeof(line), finfo)) {
                    if (strncmp(line, "pos:", 4) == 0) {
                        sscanf(line + 4, "%lld", &offset);
                        break;
                    }
                }
                fclose(finfo);
            }
            
            printf("  %-4d  %-10lld  %s\n", fd, offset, link);
        }
    }
    closedir(d);
}

uintptr_t cmd_call_ret(pid_t pid, uint64_t addr, int argc, char **argv, bool detach, uint64_t *ret_val, bool quiet) {
    
    bool already_attached = false;

    if (tracee_attach(pid) == -1) {
        if (errno == EPERM || errno == EBUSY) already_attached = true;
        else { perror("call: ATTACH"); return 0; }
    }
    
    if (!already_attached) {
        int st; waitpid(pid, &st, __WALL);
    }

    regs_t saved_regs, regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &saved_regs) == -1) {
        perror("call: GETREGS");
        if (!already_attached) tracee_detach(pid, NULL);
        return 0;
    }
    regs = saved_regs;

    uintptr_t orig_rsp = regs.rsp;
    
    uintptr_t trap_pocket = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, 4096, 
        PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)trap_pocket < 0) {
        fprintf(stderr, "call: trap mmap failed\n");
        tracee_detach(pid, NULL); return 0;
    }
    unsigned char int3 = 0xCC;
    if (!write_bytes_to_pid(pid, trap_pocket, &int3, 1)) {
        fprintf(stderr, "call: failed to write INT3 to pocket\n");
        remote_syscall_x64(pid, __NR_munmap, trap_pocket, 4096, 0, 0, 0, 0);
        tracee_detach(pid, NULL); return 0;
    }
    
    if (argc >= 1) regs.rdi = strtoull(argv[0], NULL, 0);
    if (argc >= 2) regs.rsi = strtoull(argv[1], NULL, 0);
    if (argc >= 3) regs.rdx = strtoull(argv[2], NULL, 0);
    if (argc >= 4) regs.rcx = strtoull(argv[3], NULL, 0);
    if (argc >= 5) regs.r8  = strtoull(argv[4], NULL, 0);
    if (argc >= 6) regs.r9  = strtoull(argv[5], NULL, 0);

    regs.rsp = orig_rsp;
    regs.rsp -= 8;
    if (!write_bytes_to_pid(pid, regs.rsp, &trap_pocket, 8)) {
        fprintf(stderr, "call: failed to push return address\n");
        remote_syscall_x64(pid, __NR_munmap, trap_pocket, 4096, 0, 0, 0, 0);
        tracee_detach(pid, NULL); return 0;
    }

    regs.rip = addr;
    regs.rax = 0; 
#if defined(__x86_64__)
    regs.orig_rax = -1;
#endif

    ptrace(PTRACE_SETREGS, pid, 0, &regs);

    if (!quiet) {
        if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Calling function at 0x%016llx (orig stack).\n" A_RESET, (unsigned long long)addr);
        else printf("Calling function at 0x%016llx (orig stack).\n", (unsigned long long)addr);
    }

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    int st; waitpid(pid, &st, __WALL);
    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        if (!quiet) {
            if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Call finished. RAX: 0x%llx\n" A_RESET, (unsigned long long)regs.rax);
            else printf("Call finished. RAX: 0x%llx\n", (unsigned long long)regs.rax);
        }
    } else {
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        printf("  ⚠ Call stopped unexpectedly: status=0x%x, sig=%d\n", st, WIFSTOPPED(st) ? WSTOPSIG(st) : 0);
        printf("  RIP: %016llx, RSP: %016llx\n", (unsigned long long)regs.rip, (unsigned long long)regs.rsp);
        fflush(stdout);
    }

    uintptr_t ret = regs.rax;
    if (ret_val) *ret_val = ret;

    ptrace(PTRACE_SETREGS, pid, 0, &saved_regs);
    (void)remote_syscall_x64(pid, __NR_munmap, trap_pocket, 4096, 0, 0, 0, 0);

    if (detach && !already_attached) tracee_detach(pid, NULL);
    return ret;
}

uintptr_t cmd_call(pid_t pid, uint64_t addr, int argc, char **argv, bool detach) {
    return cmd_call_ret(pid, addr, argc, argv, detach, NULL, false);
}

/**
 * @brief Load a shared library (.so) into a running process
 * 
 * This function dynamically loads a shared library into a target process:
 * 1. Resolve the .so path to absolute path
 * 2. Attach to process if not already attached
 * 3. Find libc.so addresses in both local and remote processes
 *    (we need this because ASLR means addresses differ)
 * 4. Calculate offset to dlopen within libc
 * 5. Call dlopen in remote process via remote_syscall_x64
 * 
 * This is powerful for runtime instrumentation, debugging, or
 * extending functionality without restarting the target.
 */
void cmd_load_so(pid_t pid, const char *so_path) {
    char resolved_path[1024];
    if (!realpath(so_path, resolved_path)) {
        fprintf(stderr, "load_so: couldn't resolve path: %s\n", so_path);
        return;
    }
    so_path = resolved_path;
    size_t path_len = strlen(so_path) + 1;

    bool was_attached = false;
    if (tracee_attach(pid) == -1) {
        if (errno == EPERM || errno == EBUSY) was_attached = true;
        else { perror("load_so: ATTACH"); return; }
    }
    if (!was_attached) { int st; waitpid(pid, &st, __WALL); }

    uint64_t local_libc = 0;
    FILE *lf = fopen("/proc/self/maps", "r");
    char line[1024];
    while (lf && fgets(line, sizeof(line), lf)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            if (sscanf(line, "%lx-", &local_libc) == 1) break;
        }
    }
    if (lf) fclose(lf);

    uint64_t remote_libc = 0;
    char maps_path[256];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
    FILE *rf = fopen(maps_path, "r");
    while (rf && fgets(line, sizeof(line), rf)) {
        if (strstr(line, "libc.so") && strstr(line, "r-xp")) {
            if (sscanf(line, "%lx-", &remote_libc) == 1) break;
        }
    }
    if (rf) fclose(rf);

    if (local_libc == 0 || remote_libc == 0) {
        fprintf(stderr, "load_so: couldn't find libc\n");
        if (!was_attached) tracee_detach(pid, NULL);
        return;
    }

    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen) {
        fprintf(stderr, "load_so: couldn't find local symbols\n");
        if (!was_attached) tracee_detach(pid, NULL);
        return;
    }

    uint64_t dlopen_offset = (uint64_t)local_dlopen - local_libc;
    uint64_t remote_dlopen = remote_libc + dlopen_offset;

    uint64_t path_addr = cmd_upload(pid, so_path, path_len, PROT_READ);
    if (path_addr == 0) {
        fprintf(stderr, "load_so: failed to upload path\n");
        if (!was_attached) tracee_detach(pid, NULL);
        return;
    }

    char arg0[32], arg1[32];
    snprintf(arg0, sizeof(arg0), "0x%lx", path_addr);
    snprintf(arg1, sizeof(arg1), "0x102");
    char *dlopen_argv[] = { arg0, arg1 };
    uint64_t dlopen_result = 0;

    cmd_call_ret(pid, remote_dlopen, 2, dlopen_argv, false, &dlopen_result, false);

    if (dlopen_result == 0) {
        fprintf(stderr, "load_so: dlopen failed\n");
    } else {
        fprintf(stderr, "load_so: loaded library successfully\n");
    }

    remote_syscall_x64(pid, __NR_munmap, path_addr, path_len, 0, 0, 0, 0);

    if (!was_attached) tracee_detach(pid, NULL);
}

size_t search_all_in_dumped_maps(const char *indir, const unsigned char *needle, size_t nlen, const char *seg, size_t count) {
    procmaps_iterator *it = parse_maps_dump(indir);
    if (!it) return 0;
    size_t found = 0;
    
    procmaps_struct *map;
    char perms[5];

    while ((map = pmparser_next(it)) != NULL) {
        perms[0] = map->is_r ? 'r' : '-';
        perms[1] = map->is_w ? 'w' : '-';
        perms[2] = map->is_x ? 'x' : '-';
        perms[3] = map->is_p ? 'p' : '-';
        perms[4] = '\0';
        
        if (!mapping_matches_seg_perms(perms, seg)) continue;
        char cpath[1024]; snprintf(cpath, sizeof(cpath), "%s/mem/%016lx-%016lx.bin", 
                indir, (unsigned long)map->addr_start, (unsigned long)map->addr_end);
        int fd = open(cpath, O_RDONLY); if (fd < 0) continue;
        size_t len = map->length;
        unsigned char *buf = (unsigned char*)malloc(len);
        size_t pos = 0; while (pos < len) { ssize_t nrd = read(fd, buf + pos, len - pos); if (nrd <= 0) break; pos += (size_t)nrd; }
        close(fd);
        if (pos > 0) {
            size_t scan_len = pos;
            for (size_t i=0; i+nlen <= scan_len; i++) {
                if (memcmp(buf+i, needle, nlen) == 0) {
                    uint64_t addr = (uint64_t)map->addr_start + i;
                    if (g_is_tty) printf(A_BOLD A_GREEN);
                    printf("%s offset=0x%zx addr=%016lx\n", cpath, i, (unsigned long)addr);
                    if (g_is_tty) printf(A_RESET);
                    size_t ctx_start = (i >= 16) ? i - 16 : 0;
                    size_t ctx_len = (i + nlen + 16 <= scan_len) ? 32 : scan_len - ctx_start;
                    hexdump_line((uint64_t)map->addr_start + ctx_start, buf + ctx_start, ctx_len);
                    found++; if (count > 0 && found >= count) { free(buf); pmparser_free(it); return found; }
                }
            }
        }
        free(buf);
    }
    pmparser_free(it);
    return found;
}

bool search_bytes_in_map_cb(pid_t pid, uint64_t start, uint64_t end, const char *perms, const char *path, void *ud) {
    search_ctx_t *ctx = (search_ctx_t*)ud;
    (void)path;
    if (!mapping_matches_seg_perms(perms, ctx->seg)) return true;
    size_t len = (size_t)(end - start);
    unsigned char *buf = (unsigned char*)malloc(len);
    if (!read_bytes_from_pid(pid, start, buf, len)) { free(buf); return true; }
    for (size_t i=0; i+ctx->nlen <= len; i++) {
        if (memcmp(buf+i, ctx->needle, ctx->nlen) == 0) {
            if (ctx->out_all) {
                fprintf(ctx->out_all, "%016llx\n", (unsigned long long)(start+i));
            } else {
                ctx->found = start + i;
                free(buf);
                return false;
            }
        }
    }
    free(buf);
    return true;
}

extern uint8_t _binary_parasite_bin_start[];
extern uint8_t _binary_parasite_bin_end[];

#define STACK_SIZE 65536

/**
 * @brief Restore checkpoint into a running process using parasite shellcode
 * 
 * This is the ASLR-safe restore mechanism that works regardless of the target
 * process's memory layout. Unlike the basic "restore" command which writes
 * directly to checkpoint addresses (failing if those addresses are occupied),
 * this approach:
 * 
 * 1. Injects position-independent parasite shellcode into the target process
 * 2. Uses int3 breakpoints + waitpid for communication (no pipes/FDs needed)
 * 3. Pre-allocates memory regions at the ORIGINAL checkpoint addresses
 * 4. Copies checkpoint data from scratch area to these regions
 * 5. Remaps regions with mprotect, then restores original protections
 * 6. Restores original registers and continues execution
 * 
 * The key advantage: it bypasses ASLR by creating fresh anonymous mappings
 * at the exact addresses from the checkpoint, then copying data into them.
 * 
 * @param pid   Target process PID (must be a running process, not spawned/STOPPED)
 * @param indir Checkpoint directory path
 */
void inject_and_restore(pid_t pid, const char *indir) {
    fprintf(stderr, "[parasite] Starting parasite restore for PID %d from %s\n", pid, indir);

    if (tracee_attach(pid) == -1) {
        perror("PTRACE_ATTACH");
        return;
    }
    int status;
    waitpid(pid, &status, __WALL);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[parasite] Unexpected initial status: 0x%x\n", status);
        tracee_detach(pid, NULL);
        return;
    }
    fprintf(stderr, "[parasite] Initial signal: %d\n", WSTOPSIG(status));

    uint8_t *parasite_start_ptr = _binary_parasite_bin_start;
    uint64_t parasite_code_size = _binary_parasite_bin_end - _binary_parasite_bin_start;
    fprintf(stderr, "[parasite] Parasite code size: %lu bytes\n", parasite_code_size);

    procmaps_iterator *it = parse_maps_dump(indir);
    if (!it) {
        fprintf(stderr, "[parasite] Failed to parse checkpoint maps\n");
        tracee_detach(pid, NULL);
        return;
    }

    size_t num_regions = 0;
    size_t regions_cap = 64;
    RegionDesc *regions = malloc(regions_cap * sizeof(RegionDesc));
    
    procmaps_struct *map;
    while ((map = pmparser_next(it)) != NULL) {
        uint64_t start = (uint64_t)map->addr_start;
        uint64_t end = (uint64_t)map->addr_end;
        uint64_t size = end - start;
        
        uint32_t flags = 0;
        if (strstr(map->pathname, "[vdso]")) flags |= IS_VDSO;
        else if (strstr(map->pathname, "[vsyscall]")) flags |= IS_VSYSCALL;
        
        if (flags & (IS_VDSO | IS_VSYSCALL)) continue;
        
        if (num_regions >= regions_cap) {
            regions_cap *= 2;
            regions = realloc(regions, regions_cap * sizeof(RegionDesc));
        }
        
        char perms[5] = {};
        get_perms_string(map, perms);
        uint32_t prot = 0;
        if (perms[0] == 'r') prot |= PROT_READ;
        if (perms[1] == 'w') prot |= PROT_WRITE;
        if (perms[2] == 'x') prot |= PROT_EXEC;
        
        regions[num_regions].start = start;
        regions[num_regions].size = size;
        regions[num_regions].prot = prot;
        regions[num_regions].flags = flags;
        num_regions++;
    }
    pmparser_free(it);
    fprintf(stderr, "[parasite] Collected %zu regions\n", num_regions);

    char regpath[512];
    snprintf(regpath, sizeof(regpath), "%s/regs.bin", indir);
    uint64_t restore_rip = 0, restore_rsp = 0;
    
    FILE *rf = fopen(regpath, "rb");
    if (rf) {
        regs_t saved_regs;
        if (fread(&saved_regs, 1, sizeof(saved_regs), rf) == sizeof(saved_regs)) {
            restore_rip = saved_regs.rip;
            restore_rsp = saved_regs.rsp;
            fprintf(stderr, "[parasite] Restore RIP: 0x%llx, RSP: 0x%llx\n",
                    (unsigned long long)restore_rip, (unsigned long long)restore_rsp);
        }
        fclose(rf);
    }

    uint64_t ctrl_off = parasite_code_size;
    uint64_t args_off = ctrl_off + sizeof(ControlBlock);
    uint64_t regions_off = args_off + sizeof(ParasiteArgs);
    uint64_t scratch_off = regions_off + num_regions * sizeof(RegionDesc);
    
    uint64_t max_data_size = 0;
    for (size_t i = 0; i < num_regions; i++) {
        RegionDesc *r = &regions[i];
        if (r->flags & (IS_VDSO | IS_VSYSCALL)) continue;
        if (r->size > 256 * 1024 * 1024) continue;  // Skip huge regions (>256MB)
        
        char binpath[512];
        snprintf(binpath, sizeof(binpath), "%s/mem/%016lx-%016lx.bin",
                indir, (unsigned long)r->start, (unsigned long)(r->start + r->size));
        struct stat st;
        if (stat(binpath, &st) == 0 && (uint64_t)st.st_size > max_data_size) {
            max_data_size = (uint64_t)st.st_size;
        }
    }
    uint64_t scratch_size = max_data_size > 0 ? max_data_size : (4 * 1024 * 1024);
    uint64_t stack_off = scratch_off + scratch_size;
    uint64_t total_size = stack_off + STACK_SIZE;
    
    fprintf(stderr, "[parasite] Total injection size: %lu bytes\n", total_size);

    uint64_t parasite_addr = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, total_size,
        PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    fprintf(stderr, "[parasite] mmap returned: 0x%llx\n", (unsigned long long)parasite_addr);
    
    if ((long)parasite_addr < 0) {
        fprintf(stderr, "[parasite] Failed to allocate memory in target\n");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }

    fprintf(stderr, "[parasite] Allocated parasite space at 0x%llx\n", (unsigned long long)parasite_addr);

    if (!write_bytes_to_pid(pid, parasite_addr, parasite_start_ptr, parasite_code_size)) {
        fprintf(stderr, "[parasite] Failed to write parasite blob\n");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }
    fprintf(stderr, "[parasite] Parasite blob written\n");

    ControlBlock ctrl = {0};
    ctrl.cmd = CMD_WAIT;
    uint64_t ctrl_addr = parasite_addr + ctrl_off;
    if (!write_bytes_to_pid(pid, ctrl_addr, &ctrl, sizeof(ctrl))) {
        fprintf(stderr, "[parasite] Failed to write ControlBlock\n");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }
    fprintf(stderr, "[parasite] ControlBlock written\n");

    ParasiteArgs args = {0};
    args.num_regions = num_regions;
    args.parasite_start = parasite_addr;
    args.parasite_size = total_size;
    args.ctrl_offset = ctrl_off;
    args.stack_offset = stack_off;
    args.scratch_offset = scratch_off;
    args.scratch_size = scratch_size;
    
    uint64_t args_addr = parasite_addr + args_off;
    if (!write_bytes_to_pid(pid, args_addr, &args, sizeof(args))) {
        fprintf(stderr, "[parasite] Failed to write ParasiteArgs\n");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }
    fprintf(stderr, "[parasite] ParasiteArgs written\n");

    uint64_t regions_addr = parasite_addr + regions_off;
    if (!write_bytes_to_pid(pid, regions_addr, regions, num_regions * sizeof(RegionDesc))) {
        fprintf(stderr, "[parasite] Failed to write RegionDescs\n");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }
    fprintf(stderr, "[parasite] RegionDescs written\n");

    uint64_t stack_top = parasite_addr + stack_off + STACK_SIZE - 8;

    regs_t regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        perror("PTRACE_GETREGS");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }

    regs.rip = parasite_addr;
    regs.r12 = args_addr;
    regs.rsp = stack_top;
    regs.rax = 0;
    regs.orig_rax = -1;

    fprintf(stderr, "[parasite] Setting target process registers...\n");
    if (ptrace(PTRACE_SETREGS, pid, 0, &regs) == -1) {
        perror("PTRACE_SETREGS");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }
    
    fprintf(stderr, "[parasite] Set registers: RIP=0x%llx R12=0x%llx RSP=0x%llx\n",
            (unsigned long long)regs.rip, (unsigned long long)regs.r12, (unsigned long long)regs.rsp);

    int stop_sig = WIFSTOPPED(status) ? WSTOPSIG(status) : 0;
    if (stop_sig == SIGSTOP) stop_sig = 0;
    fprintf(stderr, "[parasite] Passing signal %d to PTRACE_CONT\n", stop_sig);
    ptrace(PTRACE_CONT, pid, NULL, (void*)(long)stop_sig);

    waitpid(pid, &status, __WALL);
    fprintf(stderr, "[parasite] After continue: WIFSTOPPED=%d WSTOPSIG=%d status=0x%x\n",
            WIFSTOPPED(status), WIFSTOPPED(status) ? WSTOPSIG(status) : -1, status);
    
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[parasite] Failed to get initial int3\n");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }
    fprintf(stderr, "[parasite] Parasite ready (first int3 received)\n");

    fprintf(stderr, "[parasite] Pre-allocating %zu memory regions...\n", num_regions);
    for (size_t i = 0; i < num_regions; i++) {
        RegionDesc *r = &regions[i];
        if (r->flags & (IS_VDSO | IS_VSYSCALL)) continue;
        if (r->start == parasite_addr) continue;
        if (r->size > 256 * 1024 * 1024) {
            r->flags |= IS_SKIP;
            continue;
        }
        
        char binpath[512];
        snprintf(binpath, sizeof(binpath), "%s/mem/%016lx-%016lx.bin",
                indir, (unsigned long)r->start, (unsigned long)(r->start + r->size));
        struct stat st;
        uint64_t data_size = 0;
        if (stat(binpath, &st) == 0) {
            data_size = (uint64_t)st.st_size;
        }
        if (data_size == 0) continue;
        
        uint64_t new_addr = (uint64_t)remote_syscall_x64(pid, __NR_mmap, r->start, r->size,
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if ((long)new_addr < 0) {
            fprintf(stderr, "[parasite]   Warning: mmap at 0x%llx failed, trying without MAP_FIXED\n",
                    (unsigned long long)r->start);
            new_addr = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, r->size,
                PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if ((long)new_addr > 0) {
                r->start = new_addr;
                fprintf(stderr, "[parasite]   Allocated at new address 0x%llx\n", (unsigned long long)new_addr);
            }
        }
    }
    if (!write_bytes_to_pid(pid, regions_addr, regions, num_regions * sizeof(RegionDesc))) {
        fprintf(stderr, "[parasite] Failed to update RegionDescs with new addresses\n");
    }

    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int mem_fd = open(mem_path, O_RDWR);
    if (mem_fd < 0) {
        perror("open /proc/pid/mem");
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }

    for (size_t i = 0; i < num_regions; i++) {
        RegionDesc *r = &regions[i];
        
        if (r->flags & IS_VDSO) {
            fprintf(stderr, "[parasite] Skipping region %zu: vDSO\n", i);
            continue;
        }
        if (r->flags & IS_VSYSCALL) {
            fprintf(stderr, "[parasite] Skipping region %zu: vsyscall\n", i);
            continue;
        }
        if (r->start == parasite_addr) {
            fprintf(stderr, "[parasite] Skipping region %zu: parasite region\n", i);
            continue;
        }

        fprintf(stderr, "[parasite] Processing region %zu: 0x%llx size 0x%llx\n", 
                i, (unsigned long long)r->start, (unsigned long long)r->size);

        char binpath[512];
        snprintf(binpath, sizeof(binpath), "%s/mem/%016lx-%016lx.bin",
                 indir, (unsigned long)r->start, (unsigned long)(r->start + r->size));

        struct stat st;
        uint64_t data_size = 0;
        if (stat(binpath, &st) == 0) {
            data_size = (uint64_t)st.st_size;
        }

        if (data_size > 0) {
            fprintf(stderr, "[parasite]   Writing checkpoint data (0x%llx bytes) to scratch area\n",
                    (unsigned long long)data_size);
            int data_fd = open(binpath, O_RDONLY);
            if (data_fd >= 0) {
                char *buf = malloc(data_size);
                ssize_t rd = read(data_fd, buf, data_size);
                if (rd > 0) {
                    uint64_t scratch_addr = parasite_addr + args.scratch_offset;
                    if (!write_bytes_to_pid(pid, scratch_addr, buf, rd)) {
                        fprintf(stderr, "[parasite]   WARNING: Failed to write to scratch area\n");
                    }
                }
                free(buf);
                close(data_fd);
            }
        } else {
            fprintf(stderr, "[parasite]   No checkpoint data for this region (size=0)\n");
        }

        ctrl.cmd = CMD_NEXT;
        ctrl.region_index = i;
        ctrl.write_addr = r->start;
        ctrl.write_size = data_size;
        
        pwrite(mem_fd, &ctrl, sizeof(ctrl), ctrl_addr);
        
        ptrace(PTRACE_CONT, pid, NULL, NULL);

        waitpid(pid, &status, __WALL);
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
            fprintf(stderr, "[parasite]   ERROR: Region restore int3 not received, status=0x%x\n", status);
            break;
        }
        fprintf(stderr, "[parasite]   Region %zu fully restored\n", i);
    }

    fprintf(stderr, "[parasite] All regions processed, sending GO signal...\n");

    ctrl.cmd = CMD_GO;
    pwrite(mem_fd, &ctrl, sizeof(ctrl), ctrl_addr);

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    waitpid(pid, &status, __WALL);
    if (!WIFSTOPPED(status) || WSTOPSIG(status) != SIGTRAP) {
        fprintf(stderr, "[parasite] Final int3 not received, status=0x%x\n", status);
        close(mem_fd);
        free(regions);
        tracee_detach(pid, NULL);
        return;
    }
    fprintf(stderr, "[parasite] All done int3 received, unmapping parasite + restoring registers...\n");

    /* Unmap the parasite injection region BEFORE restoring the checkpointed
       register file. This is done host-side (not by the parasite's old
       self_unmap_and_jump stub, which only restored rsp/rip and would silently
       drop the other saved registers). We point the injected syscall at
       restore_rip (the real, still-mapped user code) so remote_syscall_x64's
       patch/restore cycle stays valid — the parasite region itself is about
       to vanish. */
    if (restore_rip != 0) {
        regs_t pregs;
        if (ptrace(PTRACE_GETREGS, pid, 0, &pregs) == -1) {
            perror("PTRACE_GETREGS (parasite pregs)");
        } else {
            pregs.rip = restore_rip;
            ptrace(PTRACE_SETREGS, pid, 0, &pregs);
        }
        long munmap_ret = remote_syscall_x64(pid, __NR_munmap, parasite_addr, total_size, 0, 0, 0, 0);
        if (munmap_ret != 0) {
            if (munmap_ret < 0)
                fprintf(stderr, "[parasite] WARNING: munmap of parasite region failed: %ld (%s)\n",
                        munmap_ret, strerror((int)-munmap_ret));
            else
                fprintf(stderr, "[parasite] WARNING: munmap of parasite region returned unexpected %ld\n", munmap_ret);
        } else {
            fprintf(stderr, "[parasite] Parasite region unmapped\n");
        }
    } else {
        fprintf(stderr, "[parasite] WARNING: no valid restore_rip; skipping parasite unmap\n");
    }

    rf = fopen(regpath, "rb");
    if (rf) {
        regs_t saved_regs;
        if (fread(&saved_regs, 1, sizeof(saved_regs), rf) == sizeof(saved_regs)) {
            if (ptrace(PTRACE_SETREGS, pid, 0, &saved_regs) == -1) {
                perror("PTRACE_SETREGS (restore)");
            }
            fprintf(stderr, "[parasite] Registers restored\n");
        }
        fclose(rf);
    }

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    close(mem_fd);
    free(regions);

    fprintf(stderr, "[parasite] Parasite restore complete\n");
}
