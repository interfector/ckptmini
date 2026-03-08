#include "ckptmini.h"
#include "parasite.h"

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
        bool attached = (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == 0);
        if (attached) {
            int st; waitpid(pid, &st, 0);
        }
        if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == 0) got_regs = true;
        if (attached) {
            ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
    

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "snapshot_diff: permission denied (need root)\n"); return; }
        else if (errno == ESRCH) { fprintf(stderr, "snapshot_diff: no such process %d\n", pid); return; }
        else DIE("PTRACE_ATTACH snapshot_diff");
    }
    int st; waitpid(pid, &st, __WALL);

    char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", indir);
    DIR *d = opendir(memdir);
    if (!d) { ptrace(PTRACE_DETACH, pid, NULL, NULL); perror("opendir mem"); return; }

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
    ptrace(PTRACE_DETACH, pid, NULL, NULL);

    char totbuf[16]; hr_size((uint64_t)total_diff, totbuf, sizeof(totbuf));
    printf("\n");
    if (g_is_tty) printf(A_BOLD);
    printf("  Summary: %zu/%zu regions changed,  %s total bytes differ\n",
           changed_regions, total_regions, totbuf);
    if (g_is_tty) printf(A_RESET);
    printf("\n");
}

void cmd_breakpoint(pid_t pid, uint64_t addr) {
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "breakpoint: permission denied (need root)\n"); return; }
        else if (errno == ESRCH) { fprintf(stderr, "breakpoint: no such process %d\n", pid); return; }
        else DIE("PTRACE_ATTACH breakpoint");
    }
    int st; waitpid(pid, &st, __WALL);

    errno = 0;
    long orig_word = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, NULL);
    if (orig_word == -1 && errno) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        fprintf(stderr, "breakpoint: could not read address 0x%016llx\n", (unsigned long long)addr);
        return;
    }
    unsigned char orig_byte = (unsigned char)(orig_word & 0xFF); (void)orig_byte;

    long bp_word = (orig_word & ~0xFFL) | 0xCCL;
    if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)bp_word) == -1) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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

        ptrace(PTRACE_DETACH, pid, NULL, (void*)SIGSTOP);

        char pidstr[32]; snprintf(pidstr, sizeof(pidstr), "%d", pid);
        cmd_dump(pidstr);
        return;
    } else {
        if (ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void*)orig_word) == -1) {
        }
        printf("Process stopped for non-trap reason (status=0x%x, sig=%d). Original byte restored.\n", st, WIFSTOPPED(st) ? WSTOPSIG(st) : 0);
    }

    ptrace(PTRACE_DETACH, pid, NULL, (void*)((WIFSTOPPED(st) && WSTOPSIG(st) != SIGTRAP) ? (long)WSTOPSIG(st) : 0));
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
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
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
        ptrace(PTRACE_DETACH, pid, NULL, NULL); free(shellcode); return;
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
    ptrace(PTRACE_DETACH, pid, NULL, (void*)((WIFSTOPPED(st) && WSTOPSIG(st) != SIGTRAP) ? (long)WSTOPSIG(st) : 0));
    free(shellcode); free(payload);
}

void cmd_trace(pid_t pid) {
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
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
    while (1) {
        if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1) break;
        waitpid(pid, &st, __WALL);

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
            if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) break;

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
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

void cmd_mprotect(pid_t pid, uint64_t addr, size_t len, const char *perms_str) {
    int prot = parse_perms(perms_str);
    if (prot < 0) { fprintf(stderr, "mprotect: invalid perms '%s'\n", perms_str); return; }

    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
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

    ptrace(PTRACE_DETACH, pid, NULL, NULL);
}

void cmd_backtrace(pid_t pid, bool pause) {
    
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno == EPERM)      { fprintf(stderr, "backtrace: permission denied\n"); }
        else if (errno == ESRCH) { fprintf(stderr, "backtrace: no such process %d\n", pid); }
        else DIE("PTRACE_ATTACH backtrace");
        return;
    }
    int st; waitpid(pid, &st, __WALL);

    regs_t regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        perror("backtrace: PTRACE_GETREGS");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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

    ptrace(PTRACE_DETACH, pid, NULL, (void*)(pause ? (long)SIGSTOP : 0));
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
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno == EPERM || errno == EBUSY) was_attached = true;
        else { perror("upload: ATTACH"); return 0; }
    }
    if (!was_attached) { int st; waitpid(pid, &st, __WALL); }

    uint64_t remote_addr = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, len,
        prot, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)remote_addr < 0) {
        fprintf(stderr, "upload: mmap failed (ret=%ld)\n", (long)remote_addr);
        if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    if (!write_bytes_to_pid(pid, remote_addr, data, len)) {
        fprintf(stderr, "upload: write failed at 0x%016llx\n", (unsigned long long)remote_addr);
        remote_syscall_x64(pid, __NR_munmap, remote_addr, len, 0, 0, 0, 0);
        if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Uploaded %zu bytes to 0x%016llx\n" A_RESET,
            len, (unsigned long long)remote_addr);
    else printf("Uploaded %zu bytes to 0x%016llx\n", len, (unsigned long long)remote_addr);

    if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
uint64_t cmd_resolve(pid_t pid, const char *symbol_name) {
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
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno == EPERM || errno == EBUSY) was_attached = true;
        else { perror("resolve: ATTACH"); return 0; }
    }
    if (!was_attached) { int st; waitpid(pid, &st, __WALL); }

    size_t name_len = strlen(symbol_name) + 1;
    uint64_t name_addr = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, name_len,
        PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)name_addr < 0) {
        fprintf(stderr, "resolve: mmap failed\n");
        if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    if (!write_bytes_to_pid(pid, name_addr, symbol_name, name_len)) {
        fprintf(stderr, "resolve: write symbol name failed\n");
        remote_syscall_x64(pid, __NR_munmap, name_addr, name_len, 0, 0, 0, 0);
        if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }

    char arg0[32], arg1[32];
    snprintf(arg0, sizeof(arg0), "0x0");       // RTLD_DEFAULT
    snprintf(arg1, sizeof(arg1), "0x%lx", name_addr);
    char *dlsym_argv[] = { arg0, arg1 };
    uint64_t result = 0;

    cmd_call_ret(pid, remote_dlsym, 2, dlsym_argv, false, &result);

    remote_syscall_x64(pid, __NR_munmap, name_addr, name_len, 0, 0, 0, 0);

    if (result == 0) {
        fprintf(stderr, "resolve: dlsym failed for '%s'\n", symbol_name);
    } else {
        if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Resolved '%s' -> 0x%016llx\n" A_RESET,
                symbol_name, (unsigned long long)result);
        else printf("Resolved '%s' -> 0x%016llx\n", symbol_name, (unsigned long long)result);
    }

    if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
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

uintptr_t cmd_call_ret(pid_t pid, uint64_t addr, int argc, char **argv, bool detach, uint64_t *ret_val) {
    
    bool already_attached = false;

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        if (errno == EPERM || errno == EBUSY) already_attached = true;
        else { perror("call: ATTACH"); return 0; }
    }
    
    if (!already_attached) {
        int st; waitpid(pid, &st, __WALL);
    }

    regs_t saved_regs, regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &saved_regs) == -1) {
        perror("call: GETREGS");
        if (!already_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 0;
    }
    regs = saved_regs;

    uintptr_t orig_rsp = regs.rsp;
    
    uintptr_t trap_pocket = (uint64_t)remote_syscall_x64(pid, __NR_mmap, 0, 4096, 
        PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if ((long)trap_pocket < 0) {
        fprintf(stderr, "call: trap mmap failed\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL); return 0;
    }
    unsigned char int3 = 0xCC;
    if (!write_bytes_to_pid(pid, trap_pocket, &int3, 1)) {
        fprintf(stderr, "call: failed to write INT3 to pocket\n");
        remote_syscall_x64(pid, __NR_munmap, trap_pocket, 4096, 0, 0, 0, 0);
        ptrace(PTRACE_DETACH, pid, NULL, NULL); return 0;
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
        ptrace(PTRACE_DETACH, pid, NULL, NULL); return 0;
    }

    regs.rip = addr;
    regs.rax = 0; 
#if defined(__x86_64__)
    regs.orig_rax = -1;
#endif

    ptrace(PTRACE_SETREGS, pid, 0, &regs);

    if (g_is_tty) printf(A_BOLD A_YELLOW "  ◆ Calling function at 0x%016llx (orig stack).\n" A_RESET, (unsigned long long)addr);
    else printf("Calling function at 0x%016llx (orig stack).\n", (unsigned long long)addr);    

    ptrace(PTRACE_CONT, pid, NULL, NULL);

    int st; waitpid(pid, &st, __WALL);
    if (WIFSTOPPED(st) && WSTOPSIG(st) == SIGTRAP) {
        ptrace(PTRACE_GETREGS, pid, 0, &regs);
        if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Call finished. RAX: 0x%llx\n" A_RESET, (unsigned long long)regs.rax);
        else printf("Call finished. RAX: 0x%llx\n", (unsigned long long)regs.rax);
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

    if (detach && !already_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return ret;
}

uintptr_t cmd_call(pid_t pid, uint64_t addr, int argc, char **argv, bool detach) {
    return cmd_call_ret(pid, addr, argc, argv, detach, NULL);
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
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
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
        if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    void *local_dlopen = dlsym(RTLD_DEFAULT, "dlopen");
    if (!local_dlopen) {
        fprintf(stderr, "load_so: couldn't find local symbols\n");
        if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    uint64_t dlopen_offset = (uint64_t)local_dlopen - local_libc;
    uint64_t remote_dlopen = remote_libc + dlopen_offset;

    uint64_t path_addr = cmd_upload(pid, so_path, path_len, PROT_READ);
    if (path_addr == 0) {
        fprintf(stderr, "load_so: failed to upload path\n");
        if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    char arg0[32], arg1[32];
    snprintf(arg0, sizeof(arg0), "0x%lx", path_addr);
    snprintf(arg1, sizeof(arg1), "0x102");
    char *dlopen_argv[] = { arg0, arg1 };
    uint64_t dlopen_result = 0;

    cmd_call_ret(pid, remote_dlopen, 2, dlopen_argv, false, &dlopen_result);

    if (dlopen_result == 0) {
        fprintf(stderr, "load_so: dlopen failed\n");
    } else {
        fprintf(stderr, "load_so: loaded library successfully\n");
    }

    remote_syscall_x64(pid, __NR_munmap, path_addr, path_len, 0, 0, 0, 0);

    if (!was_attached) ptrace(PTRACE_DETACH, pid, NULL, NULL);
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

    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) {
        perror("PTRACE_ATTACH");
        return;
    }
    int status;
    waitpid(pid, &status, __WALL);
    if (!WIFSTOPPED(status)) {
        fprintf(stderr, "[parasite] Unexpected initial status: 0x%x\n", status);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }
    fprintf(stderr, "[parasite] Initial signal: %d\n", WSTOPSIG(status));

    uint8_t *parasite_start_ptr = _binary_parasite_bin_start;
    uint64_t parasite_code_size = _binary_parasite_bin_end - _binary_parasite_bin_start;
    fprintf(stderr, "[parasite] Parasite code size: %lu bytes\n", parasite_code_size);

    procmaps_iterator *it = parse_maps_dump(indir);
    if (!it) {
        fprintf(stderr, "[parasite] Failed to parse checkpoint maps\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }

    fprintf(stderr, "[parasite] Allocated parasite space at 0x%llx\n", (unsigned long long)parasite_addr);

    if (!write_bytes_to_pid(pid, parasite_addr, parasite_start_ptr, parasite_code_size)) {
        fprintf(stderr, "[parasite] Failed to write parasite blob\n");
        free(regions);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }
    fprintf(stderr, "[parasite] Parasite blob written\n");

    ControlBlock ctrl = {0};
    ctrl.cmd = CMD_WAIT;
    uint64_t ctrl_addr = parasite_addr + ctrl_off;
    if (!write_bytes_to_pid(pid, ctrl_addr, &ctrl, sizeof(ctrl))) {
        fprintf(stderr, "[parasite] Failed to write ControlBlock\n");
        free(regions);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
    args.restore_rip = restore_rip;
    args.restore_rsp = restore_rsp;
    
    uint64_t args_addr = parasite_addr + args_off;
    if (!write_bytes_to_pid(pid, args_addr, &args, sizeof(args))) {
        fprintf(stderr, "[parasite] Failed to write ParasiteArgs\n");
        free(regions);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }
    fprintf(stderr, "[parasite] ParasiteArgs written\n");

    uint64_t regions_addr = parasite_addr + regions_off;
    if (!write_bytes_to_pid(pid, regions_addr, regions, num_regions * sizeof(RegionDesc))) {
        fprintf(stderr, "[parasite] Failed to write RegionDescs\n");
        free(regions);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }
    fprintf(stderr, "[parasite] RegionDescs written\n");

    uint64_t stack_top = parasite_addr + stack_off + STACK_SIZE - 8;

    regs_t regs;
    if (ptrace(PTRACE_GETREGS, pid, 0, &regs) == -1) {
        perror("PTRACE_GETREGS");
        free(regions);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
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
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return;
    }
    fprintf(stderr, "[parasite] All done int3 received, restoring registers...\n");

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
