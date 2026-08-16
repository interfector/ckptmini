#!/bin/bash

# ckptmini interactive shell test suite
# Run with: ./test_shell.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

CKPTMINI="$(cd "$(dirname "$0")/.." && pwd)/ckptmini"
TESTLOOP="$(cd "$(dirname "$0")" && pwd)/test_loop"
TESTBP="$(cd "$(dirname "$0")" && pwd)/test_bp"
TPID=""

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }

PASS=0
FAIL=0

cleanup() {
    if [ -n "$TPID" ] && kill -0 "$TPID" 2>/dev/null; then
        kill -9 "$TPID" 2>/dev/null || true
    fi
    wait "$TPID" 2>/dev/null || true
}
trap cleanup EXIT

# Run a script in the shell; feeds the lines in $1 and returns captured stdout.
run_shell() {
    printf '%b' "$1" | "$CKPTMINI" -i 2>&1
}

info "Shell: expression evaluation"
OUT=$(run_shell 'set $x = 0x1000 + 0x20\nexpr $x\nexpr $(0x1000+0x20)\nexpr $x + 0x10\nset\nquit\n')
if echo "$OUT" | grep -q '\$x = 0x1020' && \
   echo "$OUT" | grep -q '^0x1020$' && \
   echo "$OUT" | grep -q '^0x1030$' && \
   echo "$OUT" | grep -q '\$pid = <not set>'; then
    pass "set variable, expr eval, and \$( ) capture work"
else
    fail "variable/expr/\$( ) evaluation (output: $(echo "$OUT" | tr '\n' '|'))"
fi

info "Shell: C-like precedence and nesting"
OUT=$(run_shell 'expr 0x10 << 2 + 1\nexpr 0x1000 + 0x20 * 3\nexpr (0x1000 + 0x20) * 3\nexpr $(0x10+$(0x20+2))\nquit\n')
if echo "$OUT" | grep -q '^0x80$' && \
   echo "$OUT" | grep -q '^0x1060$' && \
   echo "$OUT" | grep -q '^0x3060$' && \
   echo "$OUT" | grep -q '^0x32$'; then
    pass "precedence (shifts below +/-) and nested \$() work"
else
    fail "precedence/nesting (output: $(echo "$OUT" | tr '\n' '|'))"
fi

info "Shell: error reporting"
OUT=$(run_shell 'expr $nonexistent\nexpr 1 +\nexpr 2 3\nquit\n')
if echo "$OUT" | grep -q "unknown variable or register" && \
   echo "$OUT" | grep -q "expected number" && \
   echo "$OUT" | grep -q "trailing garbage"; then
    pass "error messages report the offending offset"
else
    fail "error reporting (output: $(echo "$OUT" | tr '\n' '|'))"
fi

info "Shell: quoting and hex pids"
if [ -x "$TESTLOOP" ]; then
    "$TESTLOOP" >/dev/null 2>&1 &
    TPID=$!
    sleep 0.2
    HEX=$(printf '0x%x' "$TPID")
    OUT=$(printf 'attach %s\nexpr $pid\ndetach\nquit\n' "$HEX" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q "attached to $TPID (held stopped)" && \
       echo "$OUT" | grep -q "^0x$(printf '%x' "$TPID")$"; then
        pass "attach accepts a hex pid (expr \$pid output is reusable)"
    else
        fail "hex pid attach (output: $(echo "$OUT" | tr '\n' '|'))"
    fi
    kill -9 "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=""

    "$TESTLOOP" >/dev/null 2>&1 &
    TPID=$!
    sleep 0.2
    OUT=$(printf "attach %d\nupload --str 'Hello World'\nquit\n" "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q "Uploaded 11 bytes"; then
        pass "quoted strings keep spaces ('Hello World' uploads 11 bytes)"
    else
        fail "quoted string upload (output: $(echo "$OUT" | tr '\n' '|'))"
    fi
    kill -9 "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=""
fi

info "Shell: attach / registers / memory / hold release"
if [ -x "$TESTLOOP" ]; then
    "$TESTLOOP" >/dev/null 2>&1 &
    TPID=$!
    sleep 0.2

    OUT=$(printf 'attach %d\nexpr $rip\nexpr *($rsp)\nset $rax = 0x1234\nexpr $rax\ndetach\nquit\n' "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q "attached to $TPID (held stopped)" && \
       echo "$OUT" | grep -q '^0x[0-9a-f]*$' && \
       echo "$OUT" | grep -q '\$rax = 0x1234' && \
       echo "$OUT" | grep -q '^0x1234$' && \
       echo "$OUT" | grep -q "released held pid"; then
        pass "attach holds target, registers/memory readable, register write works"
    else
        fail "attach/register/memory flow (output: $(echo "$OUT" | tr '\n' '|'))"
    fi

    OUT=$(printf 'set $pid = %d\nexpr $rip\ncontinue\nexpr $pid\nset\nquit\n' "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q '\$pid = '"$TPID"' (held stopped)' && \
       echo "$OUT" | grep -q '^0x[0-9a-f]*$' && \
       echo "$OUT" | grep -q "released held pid" && \
       echo "$OUT" | grep -q '\$pid = '"$TPID"' (not held)'; then
        pass "set \$pid attaches, continue releases, \$pid survives the release"
    else
        fail "set \$pid/continue/\$pid persistence (output: $(echo "$OUT" | tr '\n' '|'))"
    fi

    OUT=$(printf 'attach %d\ndump\nexpr $rip\ndetach\nquit\n' "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q 'PID '"$TPID"' ' && \
       echo "$OUT" | grep -q '^0x[0-9a-f]*$'; then
        pass "commands default to \$pid when the pid is omitted (dump while held)"
    else
        fail "default-pid injection (output: $(echo "$OUT" | tr '\n' '|'))"
    fi

    OUT=$(printf 'attach %d\nstep %d 2\nexpr $rip\ndetach\nquit\n' "$TPID" "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q "releasing held pid" && \
       echo "$OUT" | grep -q "no pid held"; then
        pass "resume commands release the hold (step)"
    else
        fail "hold release on step (output: $(echo "$OUT" | tr '\n' '|'))"
    fi

    if kill -0 "$TPID" 2>/dev/null; then
        pass "target survives shell attach/detach cycles"
    else
        fail "target died during shell attach/detach cycles"
    fi

    kill -9 "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=""
else
    warn "test_loop not built; skipping live-target tests"
fi

info "Shell: persistent breakpoints"
if [ -x "$TESTBP" ]; then
    "$TESTBP" >/dev/null 2>&1 &
    TPID=$!
    sleep 0.5

    OUT=$(printf 'attach %d\nbreak tick\ncontinue\nexpr $rip\nexpr $rdi\ncontinue\nexpr $rdi\ninfo break\nquit\n' "$TPID" | "$CKPTMINI" -i 2>&1)
    BPADDR=$(echo "$OUT" | grep '^breakpoint 1 at ' | sed -n 's/.*at 0x0*\([0-9a-f]*\).*/\1/p')
    if echo "$OUT" | grep -q "Breakpoint 1 hit" && \
       echo "$OUT" | grep -q "breakpoint 1: .*  idle  2 hits" && \
       [ -n "$BPADDR" ] && echo "$OUT" | grep -q "^0x$BPADDR$" && \
       echo "$OUT" | grep -q "^0x[0-9a-f][0-9a-f]*$"; then
        pass "breakpoint hits, \$rip at bp address, repeated continue works"
    else
        fail "unconditional breakpoint (bp=$BPADDR output: $(echo "$OUT" | tr '\n' '|'))"
    fi
    kill -9 "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=""

    "$TESTBP" >/dev/null 2>&1 &
    TPID=$!
    sleep 0.5
    OUT=$(printf 'attach %d\nbreak tick if $rdi >= 0x30\ncontinue\nexpr $rdi\ncontinue\nexpr $rdi\ninfo break\nquit\n' "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q "Breakpoint 1 hit" && \
       echo "$OUT" | grep -q "if \$rdi >= 0x30" && \
       echo "$OUT" | grep -q "breakpoint 1: .*  idle  2 hits.*if \$rdi >= 0x30" && \
       ! echo "$OUT" | grep -q "condition false, continuing"; then
        pass "conditional breakpoint steps over false hits, stops on true, no flood"
    else
        fail "conditional breakpoint (output: $(echo "$OUT" | tr '\n' '|'))"
    fi
    kill -9 "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=""

    "$TESTBP" >/dev/null 2>&1 &
    TPID=$!
    sleep 0.5
    OUT=$(printf 'attach %d\nbreak tick\ncontinue\ndel 1\ninfo break\ncontinue\nquit\n' "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q "breakpoint 1 removed" && \
       echo "$OUT" | grep -q "no breakpoints" && \
       echo "$OUT" | grep -q "released held pid"; then
        pass "del removes a breakpoint, continue releases the hold cleanly"
    else
        fail "del/continue (output: $(echo "$OUT" | tr '\n' '|'))"
    fi
    kill -9 "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=""

    "$TESTBP" >/dev/null 2>&1 &
    TPID=$!
    sleep 0.5
    OUT=$(printf 'attach %d\nbreak tick\ncontinue\ndetach\nattach %d\ninfo break\ncontinue\ninfo break\nquit\n' "$TPID" "$TPID" | "$CKPTMINI" -i 2>&1)
    if echo "$OUT" | grep -q "breakpoint 1: .*  1 hit" && \
       echo "$OUT" | grep -q "Breakpoint 1 hit" && \
       echo "$OUT" | grep -q "breakpoint 1: .*  2 hits"; then
        pass "breakpoint persists and re-arms across detach/re-attach"
    else
        fail "detach/re-attach persistence (output: $(echo "$OUT" | tr '\n' '|'))"
    fi

    if kill -0 "$TPID" 2>/dev/null; then
        pass "target survives breakpoint attach/continue/detach cycles"
    else
        fail "target died during breakpoint cycles"
    fi

    kill -9 "$TPID" 2>/dev/null || true
    wait "$TPID" 2>/dev/null || true
    TPID=""
else
    echo -e "${YELLOW}[INFO]${NC} test_bp not built; skipping breakpoint tests"
fi

info "Shell: help and quit"
OUT=$(run_shell 'help\nquit\n')
if echo "$OUT" | grep -q "Shell Commands:" && echo "$OUT" | grep -q "attach <pid>"; then
    pass "help lists shell commands"
else
    fail "help output"
fi

#######################################
# SUMMARY
#######################################
echo ""
echo -e "${BLUE}=== Shell Test Summary ===${NC}"
echo -e "${GREEN}Passed: $PASS${NC}"
if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Failed: $FAIL${NC}"
else
    echo -e "${GREEN}Failed: $FAIL${NC}"
fi
echo ""

[ $FAIL -eq 0 ]
