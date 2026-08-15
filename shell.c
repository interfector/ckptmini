#include "ckptmini.h"

#include <readline/readline.h>
#include <readline/history.h>
#include <ctype.h>

#define SHELL_MAX_ARGS 64
#define SHELL_MAX_VARS 64

/* ---------------- shell variable table ---------------- */

typedef struct {
    char name[64];
    uint64_t value;
} shell_var_t;

static shell_var_t g_vars[SHELL_MAX_VARS];
static size_t g_nvars = 0;

/* Last pid named by `attach <pid>` / `set $pid <pid>`.  Unlike the hold
   (g_held_pid), this survives `continue`/`detach` so $pid and the default-pid
   substitution keep working after the target is released. */
static pid_t g_last_pid = -1;

static shell_var_t *shell_var_lookup(const char *name) {
    for (size_t i = 0; i < g_nvars; i++)
        if (!strcmp(g_vars[i].name, name)) return &g_vars[i];
    return NULL;
}

static void shell_var_set(const char *name, uint64_t value) {
    shell_var_t *v = shell_var_lookup(name);
    if (v) { v->value = value; return; }
    if (g_nvars >= SHELL_MAX_VARS) return;
    snprintf(g_vars[g_nvars].name, sizeof(g_vars[g_nvars].name), "%s", name);
    g_vars[g_nvars].value = value;
    g_nvars++;
}

/*
 * Resolve a $-name to a value:
 *   $pid              -> the held target pid
 *   $<register>       -> a register of the held target (via PTRACE_GETREGS)
 *   $<var>            -> a shell variable set with `set $<var> <expr>`
 */
static bool resolve_var_value(const char *name, uint64_t *out) {
    if (!strcmp(name, "pid")) {
        if (g_held_pid != -1) { *out = (uint64_t)g_held_pid; return true; }
        if (g_last_pid != -1) { *out = (uint64_t)g_last_pid; return true; }
        return false;
    }
    if (g_held_pid != -1) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, g_held_pid, 0, &regs) == 0) {
            if (get_reg_by_name(&regs, name, out) == 0) return true;
        }
    }
    const shell_var_t *v = shell_var_lookup(name);
    if (v) { *out = v->value; return true; }
    return false;
}

/* ---------------- expression evaluator ----------------
 *
 * uint64 arithmetic with C-like precedence (unary > * / % > + - > << >>),
 * parentheses, hex/octal/decimal literals, $-variables, registers, and
 * target memory reads `*(addr)` (8 bytes, little-endian) when a pid is held.
 */

typedef struct {
    const char *s;
    size_t pos;
    int err;
    char errmsg[256];
} expr_parser_t;

static size_t paren_match_end(const char *p);

static void expr_error(expr_parser_t *p, const char *msg) {
    if (!p->err) {
        p->err = 1;
        snprintf(p->errmsg, sizeof(p->errmsg), "expr error at offset %zu: %s", p->pos, msg);
    }
}

static void expr_skip_ws(expr_parser_t *p) {
    while (p->s[p->pos] == ' ' || p->s[p->pos] == '\t' || p->s[p->pos] == '\n')
        p->pos++;
}

static bool expr_parse_number(expr_parser_t *p, uint64_t *out) {
    const char *start = p->s + p->pos;
    size_t i = 0;
    while (isalnum((unsigned char)start[i]) || start[i] == 'x' || start[i] == 'X')
        i++;
    if (i == 0) { expr_error(p, "expected number"); return false; }
    if (i >= 64) { expr_error(p, "number too long"); return false; }
    char tmp[64];
    memcpy(tmp, start, i);
    tmp[i] = '\0';
    char *end = NULL;
    unsigned long long v = strtoull(tmp, &end, 0);
    if (!end || end == tmp || *end != '\0') { expr_error(p, "invalid number"); return false; }
    *out = (uint64_t)v;
    p->pos += i;
    return true;
}

static bool expr_add(expr_parser_t *p, uint64_t *out);
static bool expr_shift(expr_parser_t *p, uint64_t *out);

static bool expr_primary(expr_parser_t *p, uint64_t *out) {
    expr_skip_ws(p);
    if (p->s[p->pos] == '(') {
        p->pos++;
        if (!expr_shift(p, out)) return false;
        expr_skip_ws(p);
        if (p->s[p->pos] != ')') { expr_error(p, "missing ')'"); return false; }
        p->pos++;
        return true;
    }
    if (p->s[p->pos] == '$' && p->s[p->pos + 1] == '(') {
        /* Nested $(...) capture. */
        size_t end = paren_match_end(p->s + p->pos + 1);
        if (!end || end < 3) { expr_error(p, "unbalanced '$( ' expression"); return false; }
        size_t len = end - 2;
        if (len >= 512) { expr_error(p, "'$( )' expression too long"); return false; }
        char inner[512];
        memcpy(inner, p->s + p->pos + 2, len);
        inner[len] = '\0';
        expr_parser_t sub = { .s = inner, .pos = 0, .err = 0, .errmsg = "" };
        uint64_t v;
        if (!expr_shift(&sub, &v)) { expr_error(p, sub.errmsg); return false; }
        expr_skip_ws(&sub);
        if (sub.s[sub.pos] != '\0') { expr_error(p, "trailing garbage in '$( )'"); return false; }
        *out = v;
        p->pos += 1 + end;
        return true;
    }
    if (p->s[p->pos] == '$') {
        p->pos++;
        const char *name = p->s + p->pos;
        while (isalnum((unsigned char)*name) || *name == '_') name++;
        size_t len = (size_t)(name - (p->s + p->pos));
        if (len == 0) { expr_error(p, "empty variable name after '$'"); return false; }
        if (len >= 64) { expr_error(p, "variable name too long"); return false; }
        char vname[64];
        memcpy(vname, p->s + p->pos, len);
        vname[len] = '\0';
        p->pos += len;
        uint64_t v;
        if (!resolve_var_value(vname, &v)) {
            char msg[96];
            snprintf(msg, sizeof(msg), "unknown variable or register '$%s'", vname);
            expr_error(p, msg);
            return false;
        }
        *out = v;
        return true;
    }
    return expr_parse_number(p, out);
}

static bool expr_unary(expr_parser_t *p, uint64_t *out) {
    expr_skip_ws(p);
    if (p->s[p->pos] == '-') {
        p->pos++;
        uint64_t v;
        if (!expr_unary(p, &v)) return false;
        *out = 0ULL - v;
        return true;
    }
    if (p->s[p->pos] == '*') {
        p->pos++;
        expr_skip_ws(p);
        if (p->s[p->pos] != '(') { expr_error(p, "'*' memory read requires *(addr)"); return false; }
        p->pos++;
        uint64_t addr;
        if (!expr_add(p, &addr)) return false;
        expr_skip_ws(p);
        if (p->s[p->pos] != ')') { expr_error(p, "missing ')' in memory read"); return false; }
        p->pos++;
        if (g_held_pid == -1) { expr_error(p, "no pid set; use 'attach <pid>' first"); return false; }
        uint64_t val = 0;
        if (!read_bytes_from_pid(g_held_pid, (uintptr_t)addr, &val, sizeof(val))) {
            expr_error(p, "memory read failed");
            return false;
        }
        *out = val;
        return true;
    }
    return expr_primary(p, out);
}

static bool expr_mul(expr_parser_t *p, uint64_t *out) {
    uint64_t a;
    if (!expr_unary(p, &a)) return false;
    for (;;) {
        expr_skip_ws(p);
        char op = p->s[p->pos];
        if (op != '*' && op != '/' && op != '%') break;
        p->pos++;
        uint64_t b;
        if (!expr_unary(p, &b)) return false;
        if (op == '*') { a = a * b; }
        else if (op == '/') { if (b == 0) { expr_error(p, "division by zero"); return false; } a = a / b; }
        else { if (b == 0) { expr_error(p, "modulo by zero"); return false; } a = a % b; }
    }
    *out = a;
    return true;
}

static bool expr_shift(expr_parser_t *p, uint64_t *out) {
    uint64_t a;
    if (!expr_add(p, &a)) return false;
    for (;;) {
        expr_skip_ws(p);
        if (p->s[p->pos] != '<' && p->s[p->pos] != '>') break;
        if (p->s[p->pos + 1] != p->s[p->pos]) { expr_error(p, "single '<' or '>' not supported (use << or >>)"); return false; }
        int left = (p->s[p->pos] == '<');
        p->pos += 2;
        uint64_t b;
        if (!expr_add(p, &b)) return false;
        if (left) a = a << b; else a = a >> b;
    }
    *out = a;
    return true;
}

static bool expr_add(expr_parser_t *p, uint64_t *out) {
    uint64_t a;
    if (!expr_mul(p, &a)) return false;
    for (;;) {
        expr_skip_ws(p);
        char op = p->s[p->pos];
        if (op != '+' && op != '-') break;
        p->pos++;
        uint64_t b;
        if (!expr_mul(p, &b)) return false;
        if (op == '+') a = a + b; else a = a - b;
    }
    *out = a;
    return true;
}

/** @brief Evaluate a shell expression (0 on success, error printed on failure) */
bool shell_eval_expr(const char *s, uint64_t *out) {
    expr_parser_t p = { .s = s, .pos = 0, .err = 0, .errmsg = "" };
    uint64_t v;
    if (!expr_shift(&p, &v)) {
        fprintf(stderr, "%s\n", p.errmsg);
        return false;
    }
    expr_skip_ws(&p);
    if (p.s[p.pos] != '\0') {
        fprintf(stderr, "expr error: trailing garbage at offset %zu\n", p.pos);
        return false;
    }
    *out = v;
    return true;
}

/* ---------------- $(...) capture and token substitution ---------------- */

/* Returns the index one past the ')' that closes the '(' at p[0], or 0 if unbalanced. */
static size_t paren_match_end(const char *p) {
    int depth = 0;
    for (size_t i = 0; p[i]; i++) {
        if (p[i] == '(') depth++;
        else if (p[i] == ')') {
            depth--;
            if (depth == 0) return i + 1;
        }
    }
    return 0;
}

/* Evaluate the expression inside "$( ... )" (expr_start points at the '('). */
static bool shell_capture_expr(const char *expr_start, uint64_t *out) {
    size_t end = paren_match_end(expr_start);
    if (!end) return false;
    size_t len = end - 2;
    if (len == 0 || len >= 512) return false;
    char inner[512];
    memcpy(inner, expr_start + 1, len);
    inner[len] = '\0';
    return shell_eval_expr(inner, out);
}

/*
 * Expand a command token:
 *   $(expr) or "$name" as the whole token -> the value,
 *   embedded $(...) inside a token -> replaced in place.
 * $pid expands to decimal (pid args use atoi); everything else is hex with a
 * 0x prefix (address args use strtoull base 16/0).  Returns NULL on error
 * after printing a message.
 */
static char *shell_expand_token(const char *tok) {
    size_t n = strlen(tok);
    char *out = malloc(n + 32);
    if (!out) return NULL;

    if (tok[0] == '$' && tok[1] != '\0' && tok[1] != '(') {
        uint64_t v;
        if (!resolve_var_value(tok + 1, &v)) {
            fprintf(stderr, "shell: unknown variable or register '%s'\n", tok);
            free(out);
            return NULL;
        }
        if (!strcmp(tok + 1, "pid"))
            snprintf(out, n + 32, "%d", (int)v);
        else
            snprintf(out, n + 32, "0x%llx", (unsigned long long)v);
        return out;
    }

    if (tok[0] == '$' && tok[1] == '(') {
        uint64_t v;
        if (!shell_capture_expr(tok + 1, &v)) {
            fprintf(stderr, "shell: bad $( ) expression: %s\n", tok);
            free(out);
            return NULL;
        }
        snprintf(out, n + 32, "0x%llx", (unsigned long long)v);
        return out;
    }

    /* Embedded $(...) substitution. */
    const char *p = tok;
    char *d = out;
    while (*p) {
        if (p[0] == '$' && p[1] == '(') {
            uint64_t v;
            size_t end = paren_match_end(p + 1);
            if (!end || !shell_capture_expr(p + 1, &v)) {
                fprintf(stderr, "shell: bad $( ) expression: %s\n", tok);
                free(out);
                return NULL;
            }
            int nw = snprintf(d, (size_t)(n + 32 - (d - out)), "0x%llx", (unsigned long long)v);
            if (nw < 0) { free(out); return NULL; }
            d += nw;
            p += 1 + end;
        } else {
            *d++ = *p++;
        }
    }
    *d = '\0';
    return out;
}

static char **shell_tokenize(const char *line, int *nargs_out) {
    char **args = calloc(SHELL_MAX_ARGS, sizeof(char *));
    if (!args) return NULL;
    int n = 0;
    const char *p = line;
    while (*p && n < SHELL_MAX_ARGS) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        const char *start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        size_t len = (size_t)(p - start);
        char *tok = malloc(len + 1);
        if (!tok) { free(args); return NULL; }
        memcpy(tok, start, len);
        tok[len] = '\0';
        /* The variable name in `set $name <expr>` must stay literal. */
        if (n == 1 && args[0] && !strcmp(args[0], "set")) {
            args[n] = tok;
        } else {
            args[n] = shell_expand_token(tok);
            free(tok);
        }
        if (!args[n]) {
            for (int i = 0; i < n; i++) free(args[i]);
            free(args);
            return NULL;
        }
        n++;
    }
    *nargs_out = n;
    return args;
}

/* ---------------- shell builtins and dispatch ---------------- */

static bool cmd_resumes_target(const char *cmd) {
    static const char *const run[] = {
        "trace", "itrace", "calltrace", "ftrace", "finish", "watch",
        "breakpoint", "inject_shellcode", "mprotect", "step", "call",
        "load_so", "upload", "parasite", "restore", "restore_t",
        "relocate", "incr_restore", "replay", NULL
    };
    for (int i = 0; run[i]; i++)
        if (!strcmp(cmd, run[i])) return true;
    return false;
}

/* Commands where argv[2] is NOT a target pid (program name, dump dir, ...).
   All other commands default to $pid when the pid argument is omitted. */
static bool cmd_uses_pid_arg(const char *cmd) {
    static const char *const nopid[] = {
        "setreg_dump", "show_dump", "read_dump",
        "write_dump", "write_dump_str",
        "search_dump_str", "search_dump_bytes",
        "search_dump_all_str", "search_dump_all_bytes",
        "spawn", "spawn_show", NULL
    };
    for (int i = 0; nopid[i]; i++)
        if (!strcmp(cmd, nopid[i])) return false;
    return true;
}

static bool str_is_numeric(const char *s) {
    if (!s || !*s) return false;
    if (!strncmp(s, "0x", 2) || !strncmp(s, "0X", 2)) s += 2;
    if (!*s) return false;
    for (; *s; s++)
        if (!isdigit((unsigned char)*s)) return false;
    return true;
}

/*
 * If the command takes a target pid and the pid argument was omitted (or is a
 * symbol name like `ftrace printf`), substitute $pid so commands can be typed
 * without repeating the pid.  On success args[1..] shift right by one and
 * *nargs grows by one; the caller frees the injected token with the rest.
 */
static void shell_inject_pid(char **args, int *nargs) {
    const char *cmd = args[0];
    int n = *nargs;
    if (n < 1 || n >= SHELL_MAX_ARGS - 1) return;
    if (!cmd_uses_pid_arg(cmd)) return;
    if (n >= 2 && str_is_numeric(args[1])) return;

    uint64_t v;
    if (!resolve_var_value("pid", &v)) return;

    char *pidtok = malloc(32);
    if (!pidtok) return;
    snprintf(pidtok, 32, "%d", (int)v);
    for (int i = n; i >= 2; i--) args[i] = args[i - 1];
    args[1] = pidtok;
    args[n + 1] = NULL;
    *nargs = n + 1;
}

static void shell_print_help(void) {
    usage("ckptmini");
    fprintf(stderr, "\n  %s\n", "Shell Commands:");
    fprintf(stderr, "  %-24s %s\n", "attach <pid>", "Attach and hold the target stopped");
    fprintf(stderr, "  %-24s %s\n", "detach", "Release the held target (it resumes; $pid is kept)");
    fprintf(stderr, "  %-24s %s\n", "continue / cont", "Same as detach (release the hold)");
    fprintf(stderr, "  %-24s %s\n", "set $name <expr>", "Set a shell variable ($pid attaches; $reg writes the register)");
    fprintf(stderr, "  %-24s %s\n", "set", "List shell variables");
    fprintf(stderr, "  %-24s %s\n", "expr <expr>", "Evaluate an expression ($vars, registers, *(mem) reads)");
    fprintf(stderr, "  %-24s %s\n", "quit / exit", "Leave the shell");
    fprintf(stderr, "\n  %s\n", "Target commands (trace, ftrace, dump, ...) default to $pid when the pid is omitted.");
}

static void shell_set(char **args, int nargs) {
    if (nargs == 1) {
        if (g_held_pid != -1)
            printf("$pid = %d (held stopped)\n", (int)g_held_pid);
        else if (g_last_pid != -1)
            printf("$pid = %d (not held)\n", (int)g_last_pid);
        else
            printf("$pid = <not set>\n");
        for (size_t i = 0; i < g_nvars; i++)
            printf("$%s = 0x%llx\n", g_vars[i].name, (unsigned long long)g_vars[i].value);
        return;
    }
    if (nargs < 3) { fprintf(stderr, "usage: set $name <expr>\n"); return; }
    const char *name = args[1];
    if (name[0] != '$' || name[1] == '\0') {
        fprintf(stderr, "set: variable name must start with '$'\n");
        return;
    }
    const char *vname = name + 1;
    int start = 2;
    if (!strcmp(args[2], "=")) start = 3;  /* accept an optional '=' */
    if (start >= nargs) { fprintf(stderr, "set: missing expression\n"); return; }

    char expr[512] = "";
    for (int i = start; i < nargs; i++) {
        if (strlen(expr) + strlen(args[i]) + 2 >= sizeof(expr)) break;
        strcat(expr, args[i]);
        strcat(expr, " ");
    }
    uint64_t v;
    if (!shell_eval_expr(expr, &v)) return;

    if (!strcmp(vname, "pid")) {
        g_last_pid = (pid_t)v;
        hold_pid((pid_t)v);
        if (g_held_pid == (pid_t)v)
            printf("$pid = %d (held stopped)\n", (int)g_held_pid);
        else
            printf("$pid = %d (not held)\n", (int)g_last_pid);
        return;
    }

    /* Writing a known register of the held target. */
    if (g_held_pid != -1) {
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, g_held_pid, 0, &regs) == 0) {
            if (set_reg_by_name(&regs, vname, v) == 0) {
                if (ptrace(PTRACE_SETREGS, g_held_pid, 0, &regs) == -1) {
                    perror("PTRACE_SETREGS");
                } else {
                    printf("$%s = 0x%llx\n", vname, (unsigned long long)v);
                }
                return;
            }
        }
    }

    shell_var_set(vname, v);
    printf("$%s = 0x%llx\n", vname, (unsigned long long)v);
}

/*
 * Execute one shell line.  Returns 1 when the shell should exit (quit/exit).
 * *nargs is updated in place so the caller frees injected pid tokens too.
 */
static int shell_exec(char **args, int *nargs_p) {
    int nargs = *nargs_p;
    if (nargs == 0) return 0;
    const char *cmd = args[0];

    if (!strcmp(cmd, "help") || !strcmp(cmd, "?")) { shell_print_help(); return 0; }
    if (!strcmp(cmd, "quit") || !strcmp(cmd, "exit")) return 1;

    if (!strcmp(cmd, "attach")) {
        if (nargs != 2) { fprintf(stderr, "usage: attach <pid>\n"); return 0; }
        g_last_pid = (pid_t)atoi(args[1]);
        hold_pid((pid_t)atoi(args[1]));
        if (g_held_pid != -1)
            printf("attached to %d (held stopped)\n", (int)g_held_pid);
        else
            printf("attach failed; $pid = %d\n", (int)g_last_pid);
        return 0;
    }

    if (!strcmp(cmd, "detach") || !strcmp(cmd, "continue") || !strcmp(cmd, "cont")) {
        if (g_held_pid != -1) {
            release_hold();
            printf("released held pid\n");
        } else {
            fprintf(stderr, "no pid held\n");
        }
        return 0;
    }

    if (!strcmp(cmd, "resume")) {
        /* With a held pid (explicitly or by $pid default), resume = release.
           Otherwise fall through so `resume <pid>` reaches the CLI. */
        if (g_held_pid != -1 && (nargs == 1 || (nargs == 2 && (pid_t)atoi(args[1]) == g_held_pid))) {
            release_hold();
            printf("continued\n");
            return 0;
        }
    }

    if (!strcmp(cmd, "set")) { shell_set(args, nargs); return 0; }

    if (!strcmp(cmd, "expr")) {
        if (nargs < 2) { fprintf(stderr, "usage: expr <expression>\n"); return 0; }
        char expr[512] = "";
        for (int i = 1; i < nargs; i++) {
            if (strlen(expr) + strlen(args[i]) + 2 >= sizeof(expr)) break;
            strcat(expr, args[i]);
            strcat(expr, " ");
        }
        uint64_t v;
        if (shell_eval_expr(expr, &v))
            printf("0x%llx\n", (unsigned long long)v);
        return 0;
    }

    /* Commands that run the target implicitly end the hold. */
    if (cmd_resumes_target(cmd) && g_held_pid != -1) {
        printf("releasing held pid %d\n", (int)g_held_pid);
        release_hold();
    }

    /* Substitute $pid for a missing/non-numeric pid argument. */
    shell_inject_pid(args, &nargs);
    *nargs_p = nargs;

    char *dargv[SHELL_MAX_ARGS + 1];
    int dc = 0;
    dargv[dc++] = (char *)"ckptmini";
    for (int i = 0; i < nargs && dc < SHELL_MAX_ARGS; i++)
        dargv[dc++] = args[i];
    dispatch(dc, dargv);
    return 0;
}

/** @brief Interactive shell / REPL entry point */
int cmd_shell(int argc, char **argv) {
    (void)argc;
    (void)argv;
    g_is_tty = is_tty();
    rl_catch_signals = 0;
    install_sigint_stop();

    printf("ckptmini interactive shell  (type 'help' for commands, 'quit' to exit)\n");

    for (;;) {
        g_interrupt = 0;
        char *line = readline("ckptmini> ");
        if (!line) {
            if (g_interrupt) {
                /* Ctrl+C at the prompt: clear the interrupted line and re-prompt. */
                g_interrupt = 0;
                rl_cleanup_after_signal();
                rl_free_line_state();
                rl_replace_line("", 0);
                printf("\n");
                continue;
            }
            printf("\n");
            break;  /* EOF / Ctrl+D */
        }

        char *t = line;
        while (*t == ' ' || *t == '\t') t++;
        if (!*t || *t == '#') { free(line); continue; }

        add_history(line);

        int nargs = 0;
        char **args = shell_tokenize(t, &nargs);
        if (args) {
            int rc = shell_exec(args, &nargs);
            for (int i = 0; i < nargs; i++) free(args[i]);
            free(args);
            if (rc) { free(line); break; }
        }
        free(line);
    }

    if (g_held_pid != -1) release_hold();
    printf("bye\n");
    return EXIT_SUCCESS;
}
