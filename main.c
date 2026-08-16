#include "ckptmini.h"

bool g_json = false;

/* Emit a JSON string literal for buf[0..len) (escapes quotes/backslashes,
   renders non-printables as '.'). */
static void json_print_escaped(const unsigned char *buf, size_t len) {
    putchar('"');
    for (size_t i = 0; i < len; i++) {
        unsigned char c = buf[i];
        if (c == '"')       fputs("\\\"", stdout);
        else if (c == '\\') fputs("\\\\", stdout);
        else if (c >= 0x20 && c < 0x7f) putchar(c);
        else putchar('.');
    }
    putchar('"');
}

static void json_err(const char *cmd, const char *msg) {
    printf("{\"ok\":false,\"command\":\"%s\",\"error\":\"%s\"}\n", cmd, msg);
}

int dispatch(int argc, char **argv) {
    if (argc < 2) { usage(argv[0]); return EXIT_FAILURE; }

    /* Global --json flag: strip it anywhere in argv (it may appear before or
       after the command name) so the remaining args belong to the command. */
    g_json = false;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) {
            g_json = true;
            for (int j = i; j + 1 < argc; j++) argv[j] = argv[j + 1];
            argc--;
            i--;
        }
    }

    if (!strcmp(argv[1], "setreg")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *regname = argv[3];
        uint64_t value = strtoull(argv[4], NULL, 0);
        int ret = setreg(SETREG_LIVE, &pid, regname, value);
        return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "setreg_dump")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        const char *regname = argv[3];
        uint64_t value = strtoull(argv[4], NULL, 0);
        int ret = setreg(SETREG_DUMP, (void*)indir, regname, value);
        return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "show")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        show_maps_and_regs(SHOW_LIVE, argv[2]);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "show_dump")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        show_maps_and_regs(SHOW_DUMP, argv[2]);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "dump")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_dump(argv[2]);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "watch")) {
        if (argc < 5) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid      = (pid_t)strtoull(argv[2], NULL, 0);
        uint64_t addr  = strtoull(argv[3], NULL, 16);
        size_t len     = (size_t)strtoul(argv[4], NULL, 10);
        unsigned int interval_ms = (argc >= 6) ? (unsigned int)atoi(argv[5]) : 500;
        if (len == 0) { fprintf(stderr, "watch: len must be > 0\n"); return EXIT_FAILURE; }
        cmd_watch(pid, addr, len, interval_ms);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "snapshot_diff")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid       = (pid_t)strtoull(argv[2], NULL, 0);
        const char *dir = argv[3];
        cmd_snapshot_diff(pid, dir);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "breakpoint")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid     = (pid_t)strtoull(argv[2], NULL, 0);
        uint64_t addr = strtoull(argv[3], NULL, 16);
        cmd_breakpoint(pid, addr);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "inject_shellcode")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid       = (pid_t)strtoull(argv[2], NULL, 0);
        const char *hex = argv[3];
        cmd_inject_shellcode(pid, hex);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "trace")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_trace((pid_t)strtoull(argv[2], NULL, 0));
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "itrace")) {
        if (argc < 3) { usage(argv[0]); return EXIT_FAILURE; }
        bool disasm = false, syms = false;
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "-d") || !strcmp(argv[i], "--disas")) disasm = true;
            else if (!strcmp(argv[i], "-s") || !strcmp(argv[i], "--symbols")) syms = true;
            else { usage(argv[0]); return EXIT_FAILURE; }
        }
        cmd_itrace((pid_t)strtoull(argv[2], NULL, 0), disasm, syms);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "disas")) {
        if (argc < 5 || argc > 6) { usage(argv[0]); return EXIT_FAILURE; }
        bool syms = false;
        if (argc == 6) {
            if (strcmp(argv[5], "-s") && strcmp(argv[5], "--symbols")) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            syms = true;
        }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        uint64_t addr = strtoull(argv[3], NULL, 16);
        size_t len = (size_t)strtoul(argv[4], NULL, 10);
        if (len == 0) { fprintf(stderr, "disas: len must be > 0\n"); return EXIT_FAILURE; }
        cmd_disas(pid, addr, len, syms);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "calltrace")) {
        if (argc < 3 || argc > 4) { usage(argv[0]); return EXIT_FAILURE; }
        bool syms = false;
        if (argc == 4) {
            if (strcmp(argv[3], "-s") && strcmp(argv[3], "--symbols")) {
                usage(argv[0]);
                return EXIT_FAILURE;
            }
            syms = true;
        }
        cmd_calltrace((pid_t)strtoull(argv[2], NULL, 0), syms);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "ftrace")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        bool retval = false;
        int nnames = 0;
        for (int i = 3; i < argc; i++) {
            if (!strcmp(argv[i], "-r") || !strcmp(argv[i], "--retval")) retval = true;
            else nnames++;
        }
        if (nnames == 0) { usage(argv[0]); return EXIT_FAILURE; }
        char **names = malloc((size_t)nnames * sizeof(char*));
        if (!names) return EXIT_FAILURE;
        int j = 0;
        for (int i = 3; i < argc; i++) {
            if (strcmp(argv[i], "-r") && strcmp(argv[i], "--retval")) names[j++] = argv[i];
        }
        cmd_ftrace((pid_t)strtoull(argv[2], NULL, 0), nnames, names, retval);
        free(names);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "finish")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_finish((pid_t)strtoull(argv[2], NULL, 0));
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "backtrace")) {
        if (argc < 3) { usage(argv[0]); return EXIT_FAILURE; }
        bool pause = (argc >= 4 && !strcmp(argv[3], "-p"));
        cmd_backtrace((pid_t)strtoull(argv[2], NULL, 0), pause);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "mprotect")) {
        if (argc != 6) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_mprotect((pid_t)strtoull(argv[2], NULL, 0), strtoull(argv[3], NULL, 16), (size_t)strtoull(argv[4], NULL, 0), argv[5]);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "call")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_call((pid_t)strtoull(argv[2], NULL, 0), strtoull(argv[3], NULL, 16), argc - 4, &argv[4], true);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "signals")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_signals((pid_t)strtoull(argv[2], NULL, 0));
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "fds")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_fds((pid_t)strtoull(argv[2], NULL, 0));
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "load_so")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        cmd_load_so((pid_t)strtoull(argv[2], NULL, 0), argv[3]);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "upload")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        int prot = 0;

        if (!strcmp(argv[3], "--str")) {
            if (argc < 5) { usage(argv[0]); return EXIT_FAILURE; }
            const char *str = argv[4];
            size_t str_len = strlen(str);
            if (argc >= 6) {
                prot = parse_perms(argv[5]);
                if (prot < 0) { fprintf(stderr, "upload: invalid perms '%s'\n", argv[5]); return EXIT_FAILURE; }
            }
            uint64_t addr = cmd_upload(pid, str, str_len, prot);
            return addr != 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        } else {
            const char *hex = argv[3];
            if (argc >= 5) {
                prot = parse_perms(argv[4]);
                if (prot < 0) { fprintf(stderr, "upload: invalid perms '%s'\n", argv[4]); return EXIT_FAILURE; }
            }
            size_t blen = 0;
            unsigned char *bytes = parse_hex(hex, &blen);
            if (!bytes) { fprintf(stderr, "upload: invalid hex\n"); return EXIT_FAILURE; }
            uint64_t addr = cmd_upload(pid, bytes, blen, prot);
            free(bytes);
            return addr != 0 ? EXIT_SUCCESS : EXIT_FAILURE;
        }
    }

    if (!strcmp(argv[1], "resolve")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *symbol = argv[3];
        const char *source = "dlsym";
        uint64_t addr = cmd_resolve(pid, symbol, g_json);
        if (addr == 0 && elfsym_init(pid) == 0) {
            addr = elfsym_lookup(symbol);
            if (addr != 0) {
                source = "elfsym";
                if (!g_json) {
                    if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Resolved '%s' -> 0x%016llx (elfsym)\n" A_RESET,
                            symbol, (unsigned long long)addr);
                    else printf("Resolved '%s' -> 0x%016llx (elfsym)\n", symbol, (unsigned long long)addr);
                }
            }
            elfsym_free();
        }
        if (g_json) {
            if (addr != 0) {
                printf("{\"ok\":true,\"command\":\"resolve\",\"name\":");
                json_print_escaped((const unsigned char*)symbol, strlen(symbol));
                printf(",\"addr\":\"0x%016llx\",\"source\":\"%s\"}\n", (unsigned long long)addr, source);
            } else {
                json_err("resolve", "unresolved symbol");
            }
        }
        return addr != 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "elfresolve")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *symbol = argv[3];
        if (elfsym_init(pid) != 0) {
            if (g_json) { json_err("elfresolve", "no ELF symbols for pid"); return EXIT_FAILURE; }
            fprintf(stderr, "elfresolve: no ELF symbols for pid %d\n", pid);
            return EXIT_FAILURE;
        }
        uint64_t addr = elfsym_lookup(symbol);
        if (addr != 0) {
            if (g_json) {
                printf("{\"ok\":true,\"command\":\"elfresolve\",\"name\":");
                json_print_escaped((const unsigned char*)symbol, strlen(symbol));
                printf(",\"addr\":\"0x%016llx\",\"source\":\"elfsym\"}\n", (unsigned long long)addr);
            } else {
                if (g_is_tty) printf(A_BOLD A_GREEN "  ★ Resolved '%s' -> 0x%016llx\n" A_RESET,
                        symbol, (unsigned long long)addr);
                else printf("Resolved '%s' -> 0x%016llx\n", symbol, (unsigned long long)addr);
            }
        } else {
            if (g_json) json_err("elfresolve", "unresolved symbol");
            else fprintf(stderr, "elfresolve: unresolved symbol '%s'\n", symbol);
        }
        elfsym_free();
        return addr != 0 ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "save")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *outdir = argv[3];
        checkpoint(pid, outdir);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "incr_save")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *outdir = argv[3];
        const char *baseline = argv[4];
        incremental_checkpoint(pid, outdir, baseline);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "incr_restore")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *indir = argv[3];
        
        if (g_is_tty) printf(A_BOLD A_CYAN);
        printf("  %s Incremental restoring checkpoint %s into PID %d\n", S_INFO, indir, pid);
        if (g_is_tty) printf(A_RESET);
        incremental_restore(pid, indir);
        if (g_is_tty) printf(A_BOLD A_GREEN);
        printf("  %s Incremental restore complete. Use 'resume' to continue.\n", S_OK);
        if (g_is_tty) printf(A_RESET);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "parasite")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *indir = argv[3];
        
        if (g_is_tty) printf(A_BOLD A_CYAN);
        printf("  %s Parasite restore checkpoint %s into PID %d\n", S_INFO, indir, pid);
        if (g_is_tty) printf(A_RESET);
        inject_and_restore(pid, indir);
        if (g_is_tty) printf(A_BOLD A_GREEN);
        printf("  %s Parasite restore complete.\n", S_OK);
        if (g_is_tty) printf(A_RESET);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "save_t")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *outdir = argv[3];
        checkpoint_with_threads(pid, outdir);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "restore_t")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *indir = argv[3];
        
        if (g_is_tty) printf(A_BOLD A_CYAN);
        printf("  %s Restoring dump %s into PID %d (with threads)\n", S_INFO, indir, pid);
        if (g_is_tty) printf(A_RESET);
        if (tracee_attach(pid) == -1) DIE("PTRACE_ATTACH restore_t");
        waitpid(pid, NULL, __WALL);
        restore_with_threads(pid, indir);
        tracee_detach(pid, NULL);
        if (g_is_tty) printf(A_BOLD A_GREEN);
        printf("  %s Restore complete (with threads). Use 'resume' to continue.\n", S_OK);
        if (g_is_tty) printf(A_RESET);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "threads")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        show_threads((pid_t)strtoull(argv[2], NULL, 0));
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "threads_dump")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        show_threads_dump(argv[2]);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "restore")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *indir = argv[3];
        
        if (g_is_tty) printf(A_BOLD A_CYAN);
        printf("  %s Restoring dump %s into PID %d\n", S_INFO, indir, pid);
        if (g_is_tty) printf(A_RESET);
        if (tracee_attach(pid) == -1) DIE("PTRACE_ATTACH restore");
        waitpid(pid, NULL, __WALL);
        restore_into(pid, indir);
        tracee_detach(pid, NULL);
        if (g_is_tty) printf(A_BOLD A_GREEN);
        printf("  %s Restore complete. Use 'resume' to continue.\n", S_OK);
        if (g_is_tty) printf(A_RESET);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "relocate")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *indir = argv[3];
        
        if (g_is_tty) printf(A_BOLD A_CYAN);
        printf("  %s Relocating dump %s into PID %d\n", S_INFO, indir, pid);
        if (g_is_tty) printf(A_RESET);
        if (tracee_attach(pid) == -1) DIE("PTRACE_ATTACH relocate");
        waitpid(pid, NULL, 0);
        relocate_into(pid, indir);
        tracee_detach(pid, NULL);
        if (g_is_tty) printf(A_BOLD A_GREEN);
        printf("  %s Relocation complete. Use 'resume' to continue.\n", S_OK);
        if (g_is_tty) printf(A_RESET);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "replay")) {
        if (argc != 4) { usage(argv[0]); return EXIT_FAILURE; }
        const char *prog = argv[2];
        const char *indir = argv[3];
        
        fprintf(stderr, "[replay] Spawning %s paused...\n", prog);
        
        int pipefd[2];
        if (pipe(pipefd) < 0) DIE("pipe");
        
        pid_t child = fork();
        if (child < 0) DIE("fork");
        
        if (child == 0) {
            close(pipefd[0]);
            if (fcntl(pipefd[1], F_SETFD, FD_CLOEXEC) < 0)
                perror("fcntl(FD_CLOEXEC)");
            
            prctl(PR_SET_PDEATHSIG, 0);
            
            execvp(prog, (char*[]){prog, NULL});
            
            perror("execvp");
            write(pipefd[1], "X", 1);
            _exit(127);
        }
        
        close(pipefd[1]);
        
        char buf;
        read(pipefd[0], &buf, 1);
        close(pipefd[0]);
        
        if (tracee_attach(child) == -1) DIE("PTRACE_ATTACH");
        waitpid(child, NULL, 0);
        
        fprintf(stderr, "[replay] Attached to child %d, restoring memory...\n", child);
        
        restore_into(child, indir);
        
        fprintf(stderr, "[replay] Detaching to let child continue...\n");
        tracee_detach(child, NULL);
        
        fprintf(stderr, "[replay] Done. Child %d should continue with restored state.\n", child);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "spawn")) {
        if (argc < 3) { usage(argv[0]); return EXIT_FAILURE; }
        spawn_paused_and_print(&argv[2]);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "spawn_show")) {
        if (argc < 3) { usage(argv[0]); return EXIT_FAILURE; }
        useconds_t run_us = 500000;
        char *endp = NULL;
        if (argc >= 4) {
            long maybe_ms = strtol(argv[argc-1], &endp, 10);
            if (endp && *endp == '\0') {
                run_us = (maybe_ms < 0 ? 0 : (useconds_t)maybe_ms) * 1000u;
                argv[argc-1] = NULL;
            }
        }
        spawn_show_then_pause(&argv[2], run_us);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "resume")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        cont_pid((pid_t)strtoull(argv[2], NULL, 0));
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "step")) {
        if (argc < 3) { usage(argv[0]); return EXIT_FAILURE; }
        int steps = 1;
        if (argc == 4) steps = atoi(argv[3]);
        step_pid((pid_t)strtoull(argv[2], NULL, 0), steps);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "stop")) {
        if (argc != 3) { usage(argv[0]); return EXIT_FAILURE; }
        stop_pid((pid_t)strtoull(argv[2], NULL, 0));
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "write")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        uint64_t addr = strtoull(argv[3], NULL, 16);
        const char *hex = argv[4];
        size_t blen = 0;
        unsigned char *bytes = parse_hex(hex, &blen);
        if (!bytes) {
            if (g_json) { json_err("write", "invalid hex bytes"); return EXIT_FAILURE; }
            
            if (g_is_tty) printf(A_BOLD A_RED);
            printf("  %s Invalid hex bytes\n", S_ERR);
            if (g_is_tty) printf(A_RESET);
            return EXIT_FAILURE;
        }
        bool ok = mem_write_region(pid, addr, bytes, blen);
        if (ok) {
            if (g_json) {
                printf("{\"ok\":true,\"command\":\"write\",\"addr\":\"0x%016llx\",\"bytes\":%zu}\n",
                       (unsigned long long)addr, blen);
            } else {
            
            if (g_is_tty) printf(A_BOLD A_GREEN);
            printf("  %s Wrote %zu bytes to PID %d at 0x%016llx\n", S_OK, blen, pid, (unsigned long long)addr);
            if (g_is_tty) printf(A_RESET);
            }
        } else if (g_json) {
            json_err("write", "write failed");
        }
        free(bytes);
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "write_str")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        uint64_t addr = strtoull(argv[3], NULL, 16);
        const char *str = argv[4];
        size_t blen = strlen(str);
        bool ok = mem_write_region(pid, addr, str, blen);
        if (ok) {
            if (g_json) {
                printf("{\"ok\":true,\"command\":\"write_str\",\"addr\":\"0x%016llx\",\"bytes\":%zu}\n",
                       (unsigned long long)addr, blen);
            } else {
            
            if (g_is_tty) printf(A_BOLD A_GREEN);
            printf("  %s Wrote %zu bytes to PID %d at 0x%016llx\n", S_OK, blen, pid, (unsigned long long)addr);
            if (g_is_tty) printf(A_RESET);
            }
        } else if (g_json) {
            json_err("write_str", "write failed");
        }
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "read")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        uint64_t addr = strtoull(argv[3], NULL, 16);
        size_t len = (size_t)strtoul(argv[4], NULL, 10);
        unsigned char *buf = (unsigned char*)malloc(len);
        bool ok = read_bytes_from_pid(pid, addr, buf, len);
        if (ok) {
            if (g_json) {
                printf("{\"ok\":true,\"command\":\"read\",\"addr\":\"0x%016llx\",\"len\":%zu,\"hex\":\"",
                       (unsigned long long)addr, len);
                for (size_t i = 0; i < len; i++) printf("%02x", buf[i]);
                printf("\",\"ascii\":");
                json_print_escaped(buf, len);
                printf("}\n");
            } else {
            
            if (g_is_tty) printf(A_BOLD A_CYAN);
            printf("  %s Reading %zu bytes from PID %d at 0x%016llx\n", S_INFO, len, pid, (unsigned long long)addr);
            if (g_is_tty) printf(A_RESET);
            for (size_t off = 0; off < len; off += 16) {
                size_t row = len - off < 16 ? len - off : 16;
                hexdump_line(addr + off, buf + off, row);
            }
            }
        } else if (g_json) {
            json_err("read", "read failed");
        }
        free(buf);
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "search_str")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *text = argv[3];
        const char *seg = (argc >= 5 ? argv[4] : "any");
        search_ctx_t ctx = { .needle = (const unsigned char*)text, .nlen = strlen(text), .seg = seg, .found = 0, .out_all = NULL };
        (void)for_each_mapping(pid, search_bytes_in_map_cb, &ctx);
        if (ctx.found) {
            if (g_json) printf("{\"ok\":true,\"command\":\"search_str\",\"addr\":\"0x%016llx\"}\n", (unsigned long long)ctx.found);
            else printf("%016llx\n", (unsigned long long)ctx.found);
            return EXIT_SUCCESS;
        }
        if (g_json) json_err("search_str", "not found");
        return EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "search_bytes")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *hex = argv[3];
        size_t blen = 0;
        unsigned char *bytes = parse_hex(hex, &blen);
        if (!bytes) {
            if (g_json) { json_err("search_bytes", "invalid hex bytes"); return EXIT_FAILURE; }
            fprintf(stderr, "invalid hex_bytes\n"); return EXIT_FAILURE;
        }
        const char *seg = (argc >= 5 ? argv[4] : "any");
        search_ctx_t ctx = { .needle = bytes, .nlen = blen, .seg = seg, .found = 0, .out_all = NULL };
        (void)for_each_mapping(pid, search_bytes_in_map_cb, &ctx);
        if (ctx.found) {
            if (g_json) printf("{\"ok\":true,\"command\":\"search_bytes\",\"addr\":\"0x%016llx\"}\n", (unsigned long long)ctx.found);
            else printf("%016llx\n", (unsigned long long)ctx.found);
            free(bytes); return EXIT_SUCCESS;
        }
        if (g_json) json_err("search_bytes", "not found");
        free(bytes);
        return EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "search_dump_str")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        const char *text = argv[3];
        const char *seg = (argc >= 5 ? argv[4] : "any");
        
        if (g_is_tty) printf(A_BOLD A_CYAN);
        printf("  %s Searching for string '%s' in dump %s\n", S_INFO, text, indir);
        if (g_is_tty) printf(A_RESET);
        size_t found = search_all_in_dumped_maps(indir, (const unsigned char*)text, strlen(text), seg, 1);
        return (found > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "search_dump_bytes")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        const char *hex = argv[3];
        size_t blen = 0;
        unsigned char *bytes = parse_hex(hex, &blen);
        if (!bytes) {
            
            if (g_is_tty) printf(A_BOLD A_RED);
            printf("  %s Invalid hex bytes\n", S_ERR);
            if (g_is_tty) printf(A_RESET);
            return EXIT_FAILURE;
        }
        const char *seg = (argc >= 5 ? argv[4] : "any");
        
        if (g_is_tty) printf(A_BOLD A_CYAN);
        printf("  %s Searching for bytes %s in dump %s\n", S_INFO, hex, indir);
        if (g_is_tty) printf(A_RESET);
        size_t found = search_all_in_dumped_maps(indir, bytes, blen, seg, 1);
        free(bytes);
        return (found > 0) ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "search_all_str")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *text = argv[3];
        const char *seg = (argc >= 5 ? argv[4] : "any");
        search_ctx_t ctx = { .needle = (const unsigned char*)text, .nlen = strlen(text), .seg = seg, .found = 0, .out_all = stdout };
        (void)for_each_mapping(pid, search_bytes_in_map_cb, &ctx);
        if (g_json) {
            printf("{\"ok\":true,\"command\":\"search_all_str\",\"addrs\":[");
            for (size_t i = 0; i < ctx.naddrs; i++) {
                if (i) putchar(',');
                printf("\"0x%016llx\"", (unsigned long long)ctx.addrs[i]);
            }
            printf("]}\n");
            free(ctx.addrs);
        }
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "search_all_bytes")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        pid_t pid = (pid_t)strtoull(argv[2], NULL, 0);
        const char *hex = argv[3];
        size_t blen = 0;
        unsigned char *bytes = parse_hex(hex, &blen);
        if (!bytes) {
            if (g_json) { json_err("search_all_bytes", "invalid hex bytes"); return EXIT_FAILURE; }
            fprintf(stderr, "invalid hex_bytes\n"); return EXIT_FAILURE;
        }
        const char *seg = (argc >= 5 ? argv[4] : "any");
        search_ctx_t ctx = { .needle = bytes, .nlen = blen, .seg = seg, .found = 0, .out_all = stdout };
        (void)for_each_mapping(pid, search_bytes_in_map_cb, &ctx);
        free(bytes);
        if (g_json) {
            printf("{\"ok\":true,\"command\":\"search_all_bytes\",\"addrs\":[");
            for (size_t i = 0; i < ctx.naddrs; i++) {
                if (i) putchar(',');
                printf("\"0x%016llx\"", (unsigned long long)ctx.addrs[i]);
            }
            printf("]}\n");
            free(ctx.addrs);
        }
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "search_dump_all_str")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        const char *text = argv[3];
        const char *seg = (argc >= 5 ? argv[4] : "any");
        (void)search_all_in_dumped_maps(indir, (const unsigned char*)text, strlen(text), seg, -1);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "search_dump_all_bytes")) {
        if (argc < 4) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        const char *hex = argv[3];
        size_t blen = 0;
        unsigned char *bytes = parse_hex(hex, &blen);
        if (!bytes) { fprintf(stderr, "invalid hex_bytes\n"); return EXIT_FAILURE; }
        const char *seg = (argc >= 5 ? argv[4] : "any");
        (void)search_all_in_dumped_maps(indir, bytes, blen, seg, -1);
        free(bytes);
        return EXIT_SUCCESS;
    }

    if (!strcmp(argv[1], "write_dump")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        uint64_t addr = strtoull(argv[3], NULL, 16);
        const char *hex = argv[4];
        size_t blen = 0;
        unsigned char *bytes = parse_hex(hex, &blen);
        if (!bytes) {
            
            if (g_is_tty) printf(A_BOLD A_RED);
            printf("  %s Invalid hex bytes\n", S_ERR);
            if (g_is_tty) printf(A_RESET);
            return EXIT_FAILURE;
        }
        char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", indir);
        DIR *d = opendir(memdir); if (!d) { free(bytes); return EXIT_FAILURE; }
        struct dirent *de; bool ok=false; int found=0;
        
        if (g_is_tty) printf(A_BOLD A_GREEN);
        printf("  %s Writing %zu bytes to dump %s at 0x%016llx\n", S_OK, blen, indir, (unsigned long long)addr);
        if (g_is_tty) printf(A_RESET);
        while ((de = readdir(d))) {
            if (de->d_name[0]=='.') continue;
            unsigned long long s=0,e=0; if (sscanf(de->d_name, "%16llx-%16llx.bin", &s, &e) != 2) continue;
            if (s <= addr && addr+blen <= e) {
                if (g_is_tty) printf(A_BOLD A_CYAN);
                printf("  %s Matched chunk %016llx-%016llx\n", S_INFO, (unsigned long long)s, (unsigned long long)e);
                if (g_is_tty) printf(A_RESET);
                char path[1024]; snprintf(path, sizeof(path), "%s/%s", memdir, de->d_name);
                int fd = open(path, O_RDWR); if (fd<0) continue;
                off_t off = (off_t)(addr - s);
                if (pwrite(fd, bytes, blen, off) == (ssize_t)blen) {
                    if (g_is_tty) printf(A_GREEN);
                    printf("  %s Wrote: %s offset=0x%lx\n", S_OK, path, (unsigned long)off);
                    if (g_is_tty) printf(A_RESET);
                    ok=true; found++;
                }
                close(fd);
            }
        }
        closedir(d); free(bytes);
        if (!found) {
            
            if (g_is_tty) printf(A_BOLD A_RED);
            printf("  %s No chunk contained the address.\n", S_ERR);
            if (g_is_tty) printf(A_RESET);
        }
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "write_dump_str")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        uint64_t addr = strtoull(argv[3], NULL, 16);
        const char *str = argv[4];
        size_t blen = strlen(str);
        char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", indir);
        DIR *d = opendir(memdir); if (!d) return EXIT_FAILURE;
        struct dirent *de; bool ok=false; int found=0;
        
        if (g_is_tty) printf(A_BOLD A_GREEN);
        printf("  %s Writing %zu bytes to dump %s at 0x%016llx\n", S_OK, blen, indir, (unsigned long long)addr);
        if (g_is_tty) printf(A_RESET);
        while ((de = readdir(d))) {
            if (de->d_name[0]=='.') continue;
            unsigned long long s=0,e=0; if (sscanf(de->d_name, "%16llx-%16llx.bin", &s, &e) != 2) continue;
            if (s <= addr && addr+blen <= e) {
                if (g_is_tty) printf(A_BOLD A_CYAN);
                printf("  %s Matched chunk %016llx-%016llx\n", S_INFO, (unsigned long long)s, (unsigned long long)e);
                if (g_is_tty) printf(A_RESET);
                char path[1024]; snprintf(path, sizeof(path), "%s/%s", memdir, de->d_name);
                int fd = open(path, O_RDWR); if (fd<0) continue;
                off_t off = (off_t)(addr - s);
                if (pwrite(fd, str, blen, off) == (ssize_t)blen) {
                    if (g_is_tty) printf(A_GREEN);
                    printf("  %s Wrote: %s offset=0x%lx\n", S_OK, path, (unsigned long)off);
                    if (g_is_tty) printf(A_RESET);
                    ok=true; found++;
                }
                close(fd);
            }
        }
        closedir(d);
        if (!found) {
            
            if (g_is_tty) printf(A_BOLD A_RED);
            printf("  %s No chunk contained the address.\n", S_ERR);
            if (g_is_tty) printf(A_RESET);
        }
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (!strcmp(argv[1], "read_dump")) {
        if (argc != 5) { usage(argv[0]); return EXIT_FAILURE; }
        const char *indir = argv[2];
        uint64_t addr = strtoull(argv[3], NULL, 16);
        size_t len = (size_t)strtoul(argv[4], NULL, 10);
        char memdir[512]; snprintf(memdir, sizeof(memdir), "%s/mem", indir);
        DIR *d = opendir(memdir); if (!d) return EXIT_FAILURE;
        struct dirent *de; bool ok=false; int found=0; unsigned char *buf = (unsigned char*)malloc(len);
        while ((de = readdir(d))) {
            if (de->d_name[0]=='.') continue;
            unsigned long long s=0,e=0; if (sscanf(de->d_name, "%16llx-%16llx.bin", &s, &e) != 2) continue;
            if (s <= addr && addr+len <= e) {
                char path[1024]; snprintf(path, sizeof(path), "%s/%s", memdir, de->d_name);
                int fd = open(path, O_RDONLY); if (fd<0) continue;
                off_t off = (off_t)(addr - s);
                ssize_t rd = pread(fd, buf, len, off);
                close(fd);
                if (rd == (ssize_t)len) {
                    
                    if (g_is_tty) printf(A_BOLD A_CYAN);
                    printf("  %s Reading %zu bytes from dump %s at 0x%016llx\n", S_INFO, len, indir, (unsigned long long)addr);
                    if (g_is_tty) printf(A_RESET);
                    for (size_t o = 0; o < len; o += 16) {
                        size_t row = len - o < 16 ? len - o : 16;
                        hexdump_line(addr + o, buf + o, row);
                    }
                    ok=true; found++;
                }
            }
        }
        closedir(d);
        if (!found) {
            
            if (g_is_tty) printf(A_BOLD A_RED);
            printf("  %s No chunk contained the address.\n", S_ERR);
            if (g_is_tty) printf(A_RESET);
        }
        free(buf);
        return ok ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    usage(argv[0]);
    return EXIT_FAILURE;
}

int main(int argc, char **argv) {
    g_is_tty = is_tty();

    if (argc >= 2 && (!strcmp(argv[1], "-i") || !strcmp(argv[1], "--interactive"))) {
        return cmd_shell(argc, argv);
    }
    if (argc < 2) {
        if (g_is_tty) return cmd_shell(argc, argv);
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    return dispatch(argc, argv);
}
