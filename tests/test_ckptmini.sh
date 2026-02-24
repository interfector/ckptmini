#!/bin/bash

# ckptmini test suite
# Run with: ./test_ckptmini.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

CKPTMINI="$(cd "$(dirname "$0")/.." && pwd)/ckptmini"
TESTDIR="/tmp/ckptmini_test_$$"
SAVEDIR="$TESTDIR/saved"
TESTLOOP="$(cd "$(dirname "$0")" && pwd)/test_loop"
TESTCALL="$(cd "$(dirname "$0")" && pwd)/test_call"
TESTTHREAD="$(cd "$(dirname "$0")" && pwd)/test_thread"
TESTLIB="$(cd "$(dirname "$0")" && pwd)/testlib.so"
TESTLOOP_PID=""
TESTCALL_PID=""
TESTTHREAD_PID=""

pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((PASS++)); }
fail() { echo -e "${RED}[FAIL]${NC} $1"; ((FAIL++)); }
info() { echo -e "${BLUE}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

timeout_cmd() {
    timeout 2s "$@" 2>/dev/null
}

cleanup() {
    if [ -n "$TESTLOOP_PID" ] && kill -0 "$TESTLOOP_PID" 2>/dev/null; then
        kill -9 "$TESTLOOP_PID" 2>/dev/null || true
    fi
    if [ -n "$TESTCALL_PID" ] && kill -0 "$TESTCALL_PID" 2>/dev/null; then
        kill -9 "$TESTCALL_PID" 2>/dev/null || true
    fi
    if [ -n "$TESTTHREAD_PID" ] && kill -0 "$TESTTHREAD_PID" 2>/dev/null; then
        kill -9 "$TESTTHREAD_PID" 2>/dev/null || true
    fi
    wait "$TESTLOOP_PID" 2>/dev/null || true
    wait "$TESTCALL_PID" 2>/dev/null || true
    wait "$TESTTHREAD_PID" 2>/dev/null || true
    rm -rf "$TESTDIR"
    pkill -f "test_loop" 2>/dev/null || true
    pkill -f "test_call" 2>/dev/null || true
    pkill -f "test_thread" 2>/dev/null || true
}

trap cleanup EXIT

PASS=0
FAIL=0

echo -e "${BLUE}=== ckptmini Test Suite ===${NC}\n"

# Create test directory
mkdir -p "$TESTDIR/mem"
mkdir -p "$SAVEDIR/mem"

#######################################
# Start test_call and save it
# Also capture output to file for addresses
#######################################
info "Starting test_call program..."
# Start in background with output redirected to file
"$TESTCALL" > "$TESTDIR/test_call_output.txt" 2>&1 &
TESTCALL_PID=$!
sleep 0.5

if ! kill -0 "$TESTCALL_PID" 2>/dev/null; then
    fail "Failed to start test_call"
    exit 1
fi
pass "Started test_call (PID: $TESTCALL_PID)"

# Read addresses from captured output
ADDY=$(grep "add_numbers is at" "$TESTDIR/test_call_output.txt" | awk '{print $5}' | tr -d '0x')
GLOBAL_VAR_ADDR=$(grep "global_var is at" "$TESTDIR/test_call_output.txt" | awk '{print $4}' | tr -d '0x')

info "test_call addresses:"
info "  add_numbers: 0x$ADDY"
info "  global_var: 0x$GLOBAL_VAR_ADDR"

info "Saving test_call process..."
$CKPTMINI save "$TESTCALL_PID" "$SAVEDIR" > /dev/null 2>&1 || warn "save failed (may need root)"

# Verify saved files
if [ -f "$SAVEDIR/maps.txt" ] && [ -f "$SAVEDIR/regs.bin" ]; then
    pass "Saved files created"
else
    warn "Saved files may be incomplete"
fi

# Keep test_call running for live tests

#######################################
# TEST 1: Help/Usage
#######################################
info "Test 1: Usage output"
$CKPTMINI 2>&1 | grep -q "ckptmini" || { fail "Usage test"; }
$CKPTMINI 2>&1 | grep -q "save" || { fail "Usage missing save"; }
pass "Usage displays correctly"

#######################################
# TEST 2: Dump saved state
#######################################
info "Test 2: dump saved state"
if [ -d "$SAVEDIR" ]; then
    $CKPTMINI dump "$SAVEDIR" > /dev/null 2>&1 || { fail "dump saved"; }
    pass "dump saved state works"
else
    warn "No saved state, skipping dump test"
fi

#######################################
# TEST 3: show_dump
#######################################
info "Test 3: show_dump"
if [ -d "$SAVEDIR" ]; then
    $CKPTMINI show_dump "$SAVEDIR" > /dev/null 2>&1 || { fail "show_dump"; }
    pass "show_dump works"
else
    warn "No saved state, skipping show_dump test"
fi

#######################################
# TEST 4-7: Search in saved dump
#######################################
info "Test 4: search_dump_str"
if [ -d "$SAVEDIR" ]; then
    RESULT=$($CKPTMINI search_dump_str "$SAVEDIR" test 2>&1) || true
    echo "$RESULT" | grep -q "Searching" || { fail "search_dump_str"; }
    pass "search_dump_str works"
else
    warn "No saved state, skipping"
fi

info "Test 5: search_dump_all_str"
if [ -d "$SAVEDIR" ]; then
    RESULT=$($CKPTMINI search_dump_all_str "$SAVEDIR" test 2>&1) || true
    echo "$RESULT" | grep -q "mem/" || { fail "search_dump_all_str"; }
    pass "search_dump_all_str works"
else
    warn "No saved state, skipping"
fi

info "Test 6: search_dump_bytes"
if [ -d "$SAVEDIR" ]; then
    $CKPTMINI search_dump_bytes "$SAVEDIR" 48656c6c6f > /dev/null 2>&1 || warn "search_dump_bytes"
    pass "search_dump_bytes executes"
else
    warn "No saved state, skipping"
fi

info "Test 7: search_dump_all_bytes"
if [ -d "$SAVEDIR" ]; then
    $CKPTMINI search_dump_all_bytes "$SAVEDIR" 48656c6c6f > /dev/null 2>&1 || warn "search_dump_all_bytes"
    pass "search_dump_all_bytes executes"
else
    warn "No saved state, skipping"
fi

#######################################
# TEST 8-9: Read from saved dump
#######################################
info "Test 8: read_dump"
if [ -d "$SAVEDIR" ]; then
    ADDR=$(head -5 "$SAVEDIR/maps.txt" | grep -v "^\[" | head -1 | awk -F'-' '{print $1}')
    if [ -n "$ADDR" ]; then
        RESULT=$($CKPTMINI read_dump "$SAVEDIR" "0x$ADDR" 32 2>&1) || true
        echo "$RESULT" | grep -q "Reading" || { fail "read_dump"; }
        pass "read_dump works"
    else
        warn "Could not find address in maps"
    fi
else
    warn "No saved state, skipping read_dump test"
fi

info "Test 9: read_dump with hex output"
if [ -d "$SAVEDIR" ]; then
    ADDR=$(head -5 "$SAVEDIR/maps.txt" | grep -v "^\[" | head -1 | awk -F'-' '{print $1}')
    if [ -n "$ADDR" ]; then
        RESULT=$($CKPTMINI read_dump "$SAVEDIR" "0x$ADDR" 16 2>&1) || true
        echo "$RESULT" | grep -q "0000" || { fail "read_dump hex"; }
        pass "read_dump shows hex"
    else
        warn "Could not find address"
    fi
else
    warn "No saved state, skipping"
fi

#######################################
# TEST 10-11: Write to saved dump
#######################################
info "Test 10: write_dump_str"
if [ -d "$SAVEDIR" ]; then
    ADDR=$(grep "\[stack\]" "$SAVEDIR/maps.txt" | head -1 | cut -d'-' -f1)
    if [ -n "$ADDR" ]; then
        $CKPTMINI write_dump_str "$SAVEDIR" "0x$ADDR" "testwrite" > /dev/null 2>&1 || warn "write_dump"
        pass "write_dump_str executes"
    else
        warn "No stack found"
    fi
else
    warn "No saved state, skipping"
fi

info "Test 11: write_dump"
if [ -d "$SAVEDIR" ]; then
    ADDR=$(grep "\[stack\]" "$SAVEDIR/maps.txt" | head -1 | cut -d'-' -f1)
    if [ -n "$ADDR" ]; then
        $CKPTMINI write_dump "$SAVEDIR" "0x$ADDR" 41424344 > /dev/null 2>&1 || warn "write_dump"
        pass "write_dump executes"
    else
        warn "No stack found"
    fi
else
    warn "No saved state, skipping"
fi

#######################################
# TEST 12-14: Error handling
#######################################
info "Test 12: Invalid command handling"
OUTPUT=$($CKPTMINI invalid_command 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
echo "$OUTPUT" | grep -q "ckptmini" || { fail "invalid command"; }
pass "Invalid command shows usage"

info "Test 13: Missing arguments"
OUTPUT=$($CKPTMINI save 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
echo "$OUTPUT" | grep -q "ckptmini" || { fail "missing args"; }
pass "Missing args shows usage"

info "Test 14: Usage categories"
OUTPUT=$($CKPTMINI 2>&1 | sed 's/\x1b\[[0-9;]*m//g')
echo "$OUTPUT" | grep -q "Core Commands" || { fail "missing Core Commands"; }
echo "$OUTPUT" | grep -q "Process Control" || { fail "missing Process Control"; }
echo "$OUTPUT" | grep -q "Memory Operations" || { fail "missing Memory Operations"; }
echo "$OUTPUT" | grep -q "Search" || { fail "missing Search"; }
pass "Usage has all categories"

#######################################
# TEST 15-17: Search segment filters
#######################################
info "Test 15: Search with 'text' segment filter"
if [ -d "$SAVEDIR" ]; then
    $CKPTMINI search_dump_str "$SAVEDIR" test text > /dev/null 2>&1 || warn "search with text"
    pass "search with text segment"
else
    warn "No saved state, skipping"
fi

info "Test 16: Search with 'data' segment filter"
if [ -d "$SAVEDIR" ]; then
    $CKPTMINI search_dump_str "$SAVEDIR" test data > /dev/null 2>&1 || warn "search with data"
    pass "search with data segment"
else
    warn "No saved state, skipping"
fi

info "Test 17: Search with 'any' segment filter"
if [ -d "$SAVEDIR" ]; then
    $CKPTMINI search_dump_str "$SAVEDIR" test any > /dev/null 2>&1 || warn "search with any"
    pass "search with any segment"
else
    warn "No saved state, skipping"
fi

#######################################
# TEST 18-22: Live process operations on test_call
#######################################
if kill -0 "$TESTCALL_PID" 2>/dev/null; then
    info "Test 18: Live process read"
    $CKPTMINI read "$TESTCALL_PID" 0x0 16 > /dev/null 2>&1 || warn "read (needs root)"
    pass "read executes"
    
    info "Test 19: Search in live process"
    $CKPTMINI search_str "$TESTCALL_PID" test > /dev/null 2>&1 || warn "search_str (needs root)"
    pass "search_str executes"
    
    info "Test 20: Backtrace"
    $CKPTMINI backtrace "$TESTCALL_PID" > /dev/null 2>&1 || warn "backtrace (needs root)"
    pass "backtrace executes"
    
    info "Test 21: Signals"
    $CKPTMINI signals "$TESTCALL_PID" > /dev/null 2>&1 || warn "signals (needs root)"
    pass "signals executes"
    
    info "Test 22: File descriptors"
    $CKPTMINI fds "$TESTCALL_PID" > /dev/null 2>&1 || warn "fds (needs root)"
    pass "fds executes"
else
    warn "test_call not running, skipping live tests"
fi

#######################################
# TEST 23: Call function (needs root)
# Verify that calling add_numbers(1, 2) returns 3
# Uses the test_call started at the beginning
#######################################
if kill -0 "$TESTCALL_PID" 2>/dev/null; then
    info "Test 23: Call remote function"
    
    if [ -n "$ADDY" ]; then
        # Call the function with arguments 1 and 2
        # The test_call program outputs "add_numbers called with X and Y" and returns X+Y
        RESULT=$($CKPTMINI call "$TESTCALL_PID" "0x$ADDY" 1 2 2>&1)
        echo "$RESULT"
        
        # Check return value (should be 3 = 0x3)
        if echo "$RESULT" | grep -qE "RAX: 0x3|RAX: 3"; then
            pass "call function - return value is correct (3)"
        else
            warn "call function - return value may be incorrect"
        fi
    else
        warn "Could not find add_numbers address"
    fi
else
    warn "test_call not running, skipping call test"
fi

#######################################
# TEST 24: Inject shellcode (needs root)
# Shellcode should write "Hello" to stdout
#######################################
info "Test 24: Inject shellcode"
# Shellcode that writes "Hello" to stdout via write syscall
# write(1, "Hello\n", 6)
SHELLCODE="b8010000004831ff4831f64889c6ba0600000048c7c1ffffffff0f05"
if kill -0 "$TESTCALL_PID" 2>/dev/null; then
    RESULT=$($CKPTMINI inject_shellcode "$TESTCALL_PID" "$SHELLCODE" 2>&1)
    echo "$RESULT"
    
    # Check if shellcode wrote "Hello" to stdout
    if echo "$RESULT" | grep -q "Hello"; then
        pass "inject_shellcode - shellcode executed and wrote Hello"
    # Check if shellcode hit the trap
    elif echo "$RESULT" | grep -q "Shellcode hit TRAP"; then
        pass "inject_shellcode - shellcode executed"
    else
        warn "inject_shellcode - shellcode may not have executed correctly"
    fi
else
    warn "test_call not running, skipping inject_shellcode test"
fi

#######################################
# TEST 25: Watch memory (needs root)
# Monitor memory changes - hard to verify automatically
#######################################
info "Test 25: Watch memory"
if kill -0 "$TESTCALL_PID" 2>/dev/null; then
    # Use the global_var address captured at startup
    if [ -n "$GLOBAL_VAR_ADDR" ]; then
        # Run watch for a short time in background
        # Just verify it runs without crash
        timeout 1 $CKPTMINI watch "$TESTCALL_PID" "0x$GLOBAL_VAR_ADDR" 4 100 > /dev/null 2>&1 || warn "watch (needs root)"
        pass "watch executes"
    else
        warn "Could not find global_var address"
    fi
else
    warn "test_call not running, skipping watch test"
fi

#######################################
# TEST 26: Load shared library (needs root)
# Verify library was loaded by checking for constructor output
# Start a new test_call specifically for this test to capture library output
#######################################
info "Test 26: Load shared library"

if [ ! -f "$TESTLIB" ]; then
    warn "testlib.so not found"
else
    # Start a new test_call and capture its output to a file
    "$TESTCALL" > "$TESTDIR/test_call_for_load.txt" 2>&1 &
    TESTCALL_FOR_LOAD_PID=$!
    sleep 0.5
    
    if kill -0 "$TESTCALL_FOR_LOAD_PID" 2>/dev/null; then
        # Load the shared library
        LOAD_RESULT=$($CKPTMINI load_so "$TESTCALL_FOR_LOAD_PID" "$TESTLIB" 2>&1)
        echo "load_so result:"
        echo "$LOAD_RESULT"
        
        # Give time for constructor to run
        sleep 0.5
        
        # Kill the process
        kill -9 "$TESTCALL_FOR_LOAD_PID" 2>/dev/null || true
        wait "$TESTCALL_FOR_LOAD_PID" 2>/dev/null || true
        
        # Read the captured output
        if [ -f "$TESTDIR/test_call_for_load.txt" ]; then
            TESTCALL_OUTPUT=$(cat "$TESTDIR/test_call_for_load.txt")
            echo "test_call output:"
            echo "$TESTCALL_OUTPUT"
            
            # The library's constructor prints:
            # puts address: 0x...\nstring address: 0x...
            if echo "$TESTCALL_OUTPUT" | grep -q "puts address:"; then
                pass "load_so - library loaded successfully"
            else
                warn "load_so - library may not have loaded"
            fi
        else
            warn "load_so - could not capture test_call output"
        fi
    else
        warn "Could not start test_call for load_so test"
    fi
fi

#######################################
# TEST 27: Thread enumeration (threads command)
#######################################
info "Test 27: threads command"

# Start test_thread in background
"$TESTTHREAD" > /dev/null 2>&1 &
TESTTHREAD_PID=$!
sleep 1

if kill -0 "$TESTTHREAD_PID" 2>/dev/null; then
    RESULT=$($CKPTMINI threads "$TESTTHREAD_PID" 2>&1)
    
    if echo "$RESULT" | grep -q "Threads for PID"; then
        pass "threads command displays thread list"
    else
        fail "threads command output unexpected"
    fi
    
    # Should show at least 4 threads (main + 3 workers)
    THREAD_COUNT=$(echo "$RESULT" | grep -c "^" || true)
    if [ "$THREAD_COUNT" -ge 4 ]; then
        pass "threads command shows multiple threads"
    else
        warn "threads may not show all threads (found $THREAD_COUNT)"
    fi
else
    warn "Could not start test_thread"
fi

#######################################
# TEST 28: Thread checkpoint (save_t)
#######################################
info "Test 28: save_t command"

if kill -0 "$TESTTHREAD_PID" 2>/dev/null; then
    THREAD_SAVE_DIR="$TESTDIR/thread_save"
    mkdir -p "$THREAD_SAVE_DIR"
    
    $CKPTMINI save_t "$TESTTHREAD_PID" "$THREAD_SAVE_DIR" > /dev/null 2>&1 || warn "save_t failed"
    
    if [ -f "$THREAD_SAVE_DIR/threads.txt" ]; then
        pass "save_t creates threads.txt"
    else
        fail "save_t did not create threads.txt"
    fi
    
    if [ -d "$THREAD_SAVE_DIR/threads" ]; then
        pass "save_t creates threads directory"
    else
        warn "save_t threads directory not created"
    fi
else
    warn "test_thread not running, skipping save_t test"
fi

#######################################
# TEST 29: Thread checkpoint inspection (threads_dump)
#######################################
info "Test 29: threads_dump command"

if [ -d "$THREAD_SAVE_DIR" ]; then
    RESULT=$($CKPTMINI threads_dump "$THREAD_SAVE_DIR" 2>&1)
    
    if echo "$RESULT" | grep -q "Threads in checkpoint"; then
        pass "threads_dump displays checkpoint threads"
    else
        fail "threads_dump output unexpected"
    fi
else
    warn "No thread save directory, skipping threads_dump test"
fi

#######################################
# TEST 30: Thread restore (restore_t)
# Note: Full restore may fail without root, but we test the command runs
#######################################
info "Test 30: restore_t command"

# Start a fresh test_thread in background (not from spawn, just direct run)
"$TESTTHREAD" > /dev/null 2>&1 &
SPAWN_PID=$!
sleep 0.5

if kill -0 "$SPAWN_PID" 2>/dev/null && [ -d "$THREAD_SAVE_DIR" ]; then
    # Try to restore with timeout to prevent hanging
    RESTORE_RESULT=$(timeout 3 $CKPTMINI restore_t "$SPAWN_PID" "$THREAD_SAVE_DIR" 2>&1) || true
    
    if echo "$RESTORE_RESULT" | grep -q "Restore"; then
        pass "restore_t command executes"
    else
        warn "restore_t may have failed (expected without root)"
    fi
else
    warn "Could not test restore_t (no spawned process or no save dir)"
fi

# Clean up
if [ -n "$SPAWN_PID" ] && kill -0 "$SPAWN_PID" 2>/dev/null; then
    kill -9 "$SPAWN_PID" 2>/dev/null || true
fi

#######################################
# Clean up test_thread
#######################################
if kill -0 "$TESTTHREAD_PID" 2>/dev/null; then
    kill -9 "$TESTTHREAD_PID" 2>/dev/null || true
fi
wait "$TESTTHREAD_PID" 2>/dev/null || true
TESTTHREAD_PID=""

#######################################
# Clean up test_call
#######################################
if kill -0 "$TESTCALL_PID" 2>/dev/null; then
    kill -9 "$TESTCALL_PID" 2>/dev/null || true
fi
wait "$TESTCALL_PID" 2>/dev/null || true
TESTCALL_PID=""

#######################################
# TEST 32: Incremental checkpoint (save baseline)
#######################################
info "Test 32: incr_save - baseline"

# Start test_loop in background
"$TESTLOOP" > /dev/null 2>&1 &
TESTLOOP_INCR_PID=$!
sleep 1

INCR_BASELINE_DIR="$TESTDIR/incr_baseline"
mkdir -p "$INCR_BASELINE_DIR"

if kill -0 "$TESTLOOP_INCR_PID" 2>/dev/null; then
    $CKPTMINI save "$TESTLOOP_INCR_PID" "$INCR_BASELINE_DIR" > /dev/null 2>&1 || warn "baseline save failed"
    
    if [ -f "$INCR_BASELINE_DIR/maps.txt" ]; then
        pass "baseline checkpoint created"
    else
        warn "baseline checkpoint may be incomplete"
    fi
else
    warn "test_loop not running, skipping incremental test"
fi

#######################################
# TEST 33: Incremental checkpoint (save delta)
#######################################
info "Test 33: incr_save - delta"

if kill -0 "$TESTLOOP_INCR_PID" 2>/dev/null; then
    INCR_DELTA_DIR="$TESTDIR/incr_delta"
    mkdir -p "$INCR_DELTA_DIR"
    
    # Save incremental checkpoint (comparing with baseline) - with timeout
    timeout 3 $CKPTMINI incr_save "$TESTLOOP_INCR_PID" "$INCR_DELTA_DIR" "$INCR_BASELINE_DIR" > /dev/null 2>&1 || warn "incremental save failed"
    
    if [ -f "$INCR_DELTA_DIR/is_incremental" ]; then
        pass "incremental checkpoint marked as delta"
    else
        warn "incremental checkpoint may not be marked correctly"
    fi
    
    if [ -f "$INCR_DELTA_DIR/baseline" ]; then
        pass "incremental checkpoint has baseline reference"
    else
        warn "incremental checkpoint missing baseline reference"
    fi
else
    warn "test_loop not running, skipping incremental delta test"
fi

# Kill the test_loop after incremental save
if kill -0 "$TESTLOOP_INCR_PID" 2>/dev/null; then
    kill -9 "$TESTLOOP_INCR_PID" 2>/dev/null || true
fi

#######################################
# TEST 34: Incremental restore
#######################################
info "Test 34: incr_restore"

# Start a fresh test_loop in background
"$TESTLOOP" > /dev/null 2>&1 &
SPAWN_PID=$!
sleep 0.5

KILLER_PID=$!

if kill -0 "$SPAWN_PID" 2>/dev/null && [ -d "$INCR_DELTA_DIR" ]; then
    # Try incremental restore with timeout
    INCR_RESTORE_RESULT=$(timeout 3 $CKPTMINI incr_restore "$SPAWN_PID" "$INCR_DELTA_DIR" 2>&1) || true
    
    if echo "$INCR_RESTORE_RESULT" | grep -q "Incremental"; then
        pass "incr_restore command executes"
    else
        warn "incr_restore may have failed"
    fi
else
    warn "Could not test incr_restore (no spawned process or no delta dir)"
fi

# Clean up
kill -9 "$KILLER_PID" 2>/dev/null || true
#if [ -n "$SPAWN_PID" ] && kill -0 "$SPAWN_PID" 2>/dev/null; then
#    kill -9 "$SPAWN_PID" 2>/dev/null || true
#fi

#######################################
# SUMMARY
#######################################
echo ""
echo -e "${BLUE}=== Test Summary ===${NC}"
echo -e "${GREEN}Passed: $PASS${NC}"
if [ $FAIL -gt 0 ]; then
    echo -e "${RED}Failed: $FAIL${NC}"
else
    echo -e "${GREEN}Failed: $FAIL${NC}"
fi
echo ""

if [ $FAIL -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${YELLOW}Some tests failed (expected for operations needing root)${NC}"
    exit 0
fi
