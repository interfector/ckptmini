# ckptmini

A lightweight Linux checkpoint/restart utility using ptrace. Save a running process's state to disk and restore it later, or inject code into live processes.

## Primary Feature: Checkpoint & Restore

The core functionality allows you to freeze a running process and resume it later:

```bash
# Save process state to disk
./ckptmini save <pid> /tmp/checkpoint

# Restore into a new process
./ckptmini restore <pid> /tmp/checkpoint

# Or replay from scratch
./ckptmini replay /path/to/binary /tmp/checkpoint
```

An interactive shell (`./ckptmini -i`) layers attach/detach, register and memory inspection, expression evaluation, and persistent conditional breakpoints on top of these commands (see [Interactive Shell](#interactive-shell)).

This saves:
- All CPU registers
- Complete memory contents (stack, heap, code, libraries)
- Process command line and environment

**Limitations:**
- Does not preserve open file descriptors
- Does not preserve signal handlers or pending signals
- ASLR may cause issues on restore if addresses differ

## Command Reference

### Checkpoint & Restore

| Command | Description |
|---------|-------------|
| `save <pid> <dir>` | Save complete process state (registers, memory, metadata) to directory |
| `save_t <pid> <dir>` | Save process with thread support |
| `restore <pid> <dir>` | Restore saved checkpoint into a running process |
| `restore_t <pid> <dir>` | Restore with thread support |
| `replay <prog> <dir>` | Fork and exec program, then restore checkpoint into it |
| `relocate <pid> <dir>` | Restore memory layout from dump into a different process |

### Incremental Checkpoints

| Command | Description |
|---------|-------------|
| `incr_save <pid> <dir> <baseline>` | Save incremental checkpoint (only changed pages) |
| `incr_restore <pid> <dir>` | Restore incremental checkpoint |

Example:
```bash
# Save baseline checkpoint
./ckptmini save 12345 /tmp/baseline
# Save incremental (only changed pages compared to baseline)
./ckptmini incr_save 12345 /tmp/delta /tmp/baseline
# Restore incremental
./ckptmini incr_restore 12345 /tmp/delta
```

### Thread Support

| Command | Description |
|---------|-------------|
| `threads <pid>` | Show threads of a live process |
| `threads_dump <dir>` | Show threads in a checkpoint |

**Note:** Thread support is experimental. Full restoration requires elevated ptrace permissions.

### Process Control

| Command | Description |
|---------|-------------|
| `spawn <prog> [args]` | Spawn a process in paused state |
| `spawn_show <prog> [args] [us]` | Spawn, run for specified microseconds, then pause |
| `resume <pid>` | Continue a stopped process |
| `stop <pid>` | Stop a process via SIGSTOP |
| `step <pid> [n]` | Single-step the process n times (default 1) |

**Limitations:** `spawn*` require program path; no handling of complex argv parsing.

### Memory Operations

| Command | Description |
|---------|-------------|
| `read <pid> <addr> <len>` | Read and hexdump memory from live process |
| `write <pid> <addr> <hex>` | Write hex bytes to process memory |
| `write_str <pid> <addr> <str>` | Write null-terminated string to memory |
| `watch <pid> <addr> <len> [ms]` | Poll memory region and detect changes |

**Limitations:**
- `write` overwrites without safety checks; can corrupt process
- `watch` is polling-based (not event-driven), may miss fast changes

### Memory Protection

| Command | Description |
|---------|-------------|
| `mprotect <pid> <addr> <len> <perms>` | Change memory protection (r/w/x combinations) |

**Limitations:** Changing protection on shared libraries or executable pages may crash the process.

### Dump Inspection & Modification

| Command | Description |
|---------|-------------|
| `show <pid>` | Display memory maps and registers of live process |
| `show_dump <dir>` | Display memory maps of a saved checkpoint |
| `dump <pid\|dir>` | Display memory regions with colors (accepts a live pid or a checkpoint dir) |
| `read_dump <dir> <addr> <len>` | Read memory from a checkpoint dump |
| `write_dump <dir> <addr> <hex>` | Modify memory in a checkpoint file |
| `write_dump_str <dir> <addr> <str>` | Write string to checkpoint dump |

**Limitations:** Cannot add new memory regions; only modify existing ones.

### Search

| Command | Description |
|---------|-------------|
| `search_str <pid> <str> [seg]` | Search for string in process memory |
| `search_all_str <pid> <str> [seg]` | Find all occurrences in process |
| `search_bytes <pid> <hex> [seg]` | Search for byte pattern in live process |
| `search_all_bytes <pid> <hex> [seg]` | Find all byte-pattern occurrences in process |
| `search_dump_str <dir> <str> [seg]` | Search for string in checkpoint |
| `search_dump_all_str <dir> <str> [seg]` | Find all matches in checkpoint |
| `search_dump_bytes <dir> <hex> [seg]` | Search for bytes in checkpoint |
| `search_dump_all_bytes <dir> <hex> [seg]` | Find all byte matches in checkpoint |

The optional `seg` filter can be: `stack`, `heap`, `lib`, `any`.

**Limitations:** Searches are linear and slow on large memory regions.

### JSON Output

Append `--json` to a command to get machine-readable output on stdout, with
failures signalled by a non-zero exit code. This lets commands be chained
through pipes, e.g.:

```bash
# Find every occurrence of bytes 90 90 and write 00 at each address
./ckptmini search_all_bytes 12345 9090 --json | jq -r '.addrs[]' | while read -r a; do
    ./ckptmini write 12345 "$a" 00
done

# Read bytes at a resolved symbol's address
./ckptmini read 12345 "$(./ckptmini elfresolve 12345 main --json | jq -r '.addr')" 16 --json
```

Commands that currently support `--json`:

| Command | Output |
|---------|--------|
| `search_bytes` / `search_str` | `{"ok":true,"addr":"0x..."}` |
| `search_all_bytes` / `search_all_str` | `{"ok":true,"addrs":["0x...",...]}` |
| `search_dump_bytes` / `search_dump_str` | `{"ok":true,"addr":"0x..."}` |
| `search_dump_all_bytes` / `search_dump_all_str` | `{"ok":true,"addrs":["0x...",...]}` |
| `read` | `{"ok":true,"addr":"0x...","len":N,"hex":"...","ascii":"..."}` |
| `write` / `write_str` | `{"ok":true,"addr":"0x...","bytes":N}` |
| `resolve` / `elfresolve` | `{"ok":true,"name":"...","addr":"0x...","source":"dlsym\|elfsym"}` |
| `call` | `{"ok":true,"addr":"0x...","retval":"0x..."}` |
| `backtrace` | `{"ok":true,"frames":[{"n":N,"rip":"0x...","module":"..."},...]}` |
| `disas` | `{"ok":true,"addr":"0x...","len":N,"insns":[{"addr","bytes","mnemonic","op_str"},...]}` |
| `finish` | `{"ok":true,"symbol":"...","addr":"0x...","retval":"0x..."}` |
| `show` / `show_dump` | `{"ok":true,"maps":[{"start","end","perms","offset","dev","inode","path"},...],"regs":{...}}` |
| `step` | one object per step (JSON Lines): `{"ok":true,"step":N,"rip":"0x...","rsp","rbp","rax","rbx","rcx","rdx"}` |

`step` emits one object per step (JSON Lines) so scripts can follow execution.
All other `--json` commands emit a single JSON object.

On failure the object is `{"ok":false,"command":"...","error":"..."}` and the
exit code is non-zero.

### Example One-liners

The JSON output is meant to be composed through pipes with `jq` — no wrapper
library needed. A few handy pipelines:

```bash
PID=1234

# Read bytes at a resolved symbol's address
./ckptmini read "$PID" "$(./ckptmini elfresolve "$PID" main --json | jq -r '.addr')" 16 --json | jq -r '.hex'

# Resolve several symbols in one go
for s in main add_numbers global_var; do
    ./ckptmini elfresolve "$PID" "$s" --json | jq -r '"\(.name)  \(.addr)"'
done

# Remote function call: retval is the call's return value
./ckptmini call "$PID" "$(./ckptmini elfresolve "$PID" add_numbers --json | jq -r '.addr')" 40 2 --json | jq -r '.retval'

# Step 5 instructions and collect the RIP trail
./ckptmini step "$PID" 5 --json | jq -r '.rip'

# Poor-man's watchpoint: poll an address until the value changes
while :; do v=$(./ckptmini read "$PID" "$ADDR" 8 --json | jq -r '.hex'); [ "$v" != "$prev" ] && { echo "changed: $v"; break; }; prev=$v; sleep 0.2; done

# List executable mappings (filter the maps array)
./ckptmini show "$PID" --json | jq -r '.maps[] | select(.perms | contains("x")) | .path' | sort -u

# Find every `call` instruction in a disassembled region
./ckptmini disas "$PID" "$FUNC_ADDR" 64 --json | jq -r '.insns[] | select(.mnemonic == "call") | .op_str'

# Find every occurrence of bytes 90 90 and write 00 at each address
./ckptmini search_all_bytes "$PID" 9090 --json | jq -r '.addrs[]' | while read -r a; do
    ./ckptmini write "$PID" "$a" 00
done
```

Notes:
- `search_all_*` always exits 0 even with zero matches, so check the returned
  `.addrs` array length before looping.
- `write` can modify any mapped page: writable pages are written directly via
  `/proc/<pid>/mem`, and read-only pages (e.g. `.text`) get a brief
  attach → temp `mprotect` RW → write → restore-prot → detach cycle, so the
  target is only paused for the duration of the write.

### Process Inspection

| Command | Description |
|---------|-------------|
| `backtrace <pid> [-p]` | Print stack backtrace; `-p` pauses process first |
| `fds <pid>` | List all open file descriptors and their targets |
| `signals <pid>` | Display signal handler configuration |
| `trace <pid>` | Trace syscalls (strace-like output) |
| `itrace <pid> [-d] [-s]` | Single-step and print each executed instruction (`-d` disassemble with Capstone, `-s` resolve symbols) |
| `calltrace <pid> [-s]` | Log call/jmp/ret flow (call graph); `-s` annotates symbols |
| `ftrace <pid> <sym> [sym...] [-r]` | Trace calls to the named functions; `-r` captures return values |
| `finish <pid>` | Run until the current function returns (step-out) |
| `disas <pid> <addr> <len> [-s]` | Disassemble memory with Capstone; `-s` annotates symbols |

**Limitations:**
- `backtrace` may be inaccurate with optimized binaries or missing debug symbols
- `trace` is basic; doesn't capture syscall arguments in full
- `ftrace` relies on symbols being present in the target

### Debugging

| Command | Description |
|---------|-------------|
| `breakpoint <pid> <addr>` | Set an int3 breakpoint at address |
| `setreg <pid> <name> <val>` | Modify a CPU register by name |
| `setreg_dump <dir> <name> <val>` | Modify registers in a checkpoint |

Register names: rip, rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15.

**Limitations:** The CLI `breakpoint` command is single-shot; it is removed after triggering. For persistent conditional breakpoints, use the [interactive shell](#interactive-shell).

### Code Injection

| Command | Description |
|---------|-------------|
| `inject_shellcode <pid> <hex>` | Write and execute machine code in process |
| `upload <pid> <hex> [perms]` | Upload bytes to remote process (length derived from the hex; prints the allocated address) |
| `upload <pid> --str <string> [perms]` | Upload a string to remote process |

Example - spawn a shell:
```bash
./ckptmini inject_shellcode 12345 b801000000bf01000000488d3508000000ba050000000f05cc48656c6c6f
# write(1, "Hello", 5);
```

**Limitations:**
- No automatic recovery; process may crash if code is malformed
- Must know correct address space layout (ASLR)
- Code runs once and leaves modified memory

### Remote Function Calls

| Command | Description |
|---------|-------------|
| `call <pid> <addr> [args]` | Call function at address with arguments |
| `load_so <pid> <path>` | Load shared library into process |
| `resolve <pid> <symbol>` | Resolve symbol address using dlsym (falls back to the ELF table if dlsym can't see it) |
| `elfresolve <pid> <symbol>` | Resolve symbol address from the target's ELF symbol table (covers static `.symtab` functions and data objects dlsym can't see) |
| `upload <pid> <hex> [perms]` | Upload bytes to remote process memory |
| `upload <pid> --str <string> [perms]` | Upload string to remote process memory |

`load_so` and `resolve` use `dlopen`/`dlsym` internally to inject libraries or resolve symbols. `elfresolve` instead reads the target's `/proc/<pid>/maps` and ELF symbol tables on disk, so it needs no injection and can resolve static symbols like `main`.

**Usage examples:**
```bash
# Resolve a symbol address
./ckptmini resolve 12345 system

# Resolve a static symbol address via the ELF symbol table
./ckptmini elfresolve 12345 main

# Upload a string to remote process
./ckptmini upload 12345 --str "/bin/sh"

# Upload binary data (5 bytes: "Hello")
./ckptmini upload 12345 48656c6c6f
```

**Limitations:**
- Function addresses must be known (static binaries harder)
- Arguments limited to basic types
- No automatic cleanup of function results

## Advanced Features

### Parasite-Based Restore

| Command | Description |
|---------|-------------|
| `parasite <pid> <dir>` | Restore checkpoint using position-independent parasite code injection |

The `parasite` command implements an ASLR-safe restore mechanism that injects position-independent code into the target process. This allows restoring checkpoints into processes at arbitrary memory addresses without requiring fixed address layouts.

**How it works:**
1. Allocates memory space in target process for parasite code, stack, and region descriptors
2. Injects position-independent parasite binary that can run anywhere in memory
3. Uses int3 breakpoints + SIGTRAP signals for communication
4. Restores each memory region using `/proc/<pid>/mem` for data transfer
5. Restores saved CPU registers and jumps to original entry point
6. Automatically unmaps parasite code before returning control to restored process

**Advantages over `restore` command:**
- Works with ASLR-enabled systems (processes at different base addresses)
- No hardcoded address assumptions
- Cleaner restoration (parasite self-unmaps)

**Usage example:**
```bash
# Save a checkpoint
./ckptmini save 12345 /tmp/checkpoint

# Stop the process and restore using parasite
kill -STOP 12345
./ckptmini parasite 12345 /tmp/checkpoint

# Process continues from checkpoint state
```

**Limitations:**
- Requires ptrace attach permissions
- May fail with certain memory protection schemes
- Not suitable for processes with custom signal handlers

### Modifying Checkpoint Dumps

| Command | Description |
|---------|-------------|
| `snapshot_diff <pid> <dir>` | Compare live process memory to saved checkpoint |

**Limitations:** Diff only shows changes; doesn't auto-merge.

### Register Access

| Command | Description |
|---------|-------------|
| `setreg_dump <dir> <name> <val>` | Modify saved register values in checkpoint |

### Hex Parsing

The tool uses standard hex string format: `4831c0` = bytes [0x48, 0x31, 0xc0].

## Interactive Shell

Launch the shell with `./ckptmini -i` (or just `./ckptmini` on a TTY). It can attach to a process and hold it stopped, inspect registers and memory, evaluate expressions, and run persistent conditional breakpoints without leaving the tool.

| Command | Description |
|---------|-------------|
| `attach <pid>` | Attach and hold the target stopped |
| `detach` | Release the held target (it resumes; `$pid` is kept) |
| `continue` / `cont` | Run until a breakpoint hits (otherwise release the hold) |
| `break <addr\|sym> [if <expr>]` | Persistent breakpoint; condition evaluated at hit time |
| `info break` | List breakpoints (address, state, hit count, condition) |
| `del <n>` | Remove breakpoint by number |
| `clear <addr>` | Remove breakpoint by address |
| `set $name <expr>` | Set a shell variable (`set $pid <pid>` attaches; `set $reg <val>` writes the register) |
| `set` | List shell variables |
| `expr <expr>` | Evaluate an expression (`$vars`, registers, `*(mem)` reads) |
| `quit` / `exit` | Leave the shell |

- Break conditions keep `$registers`/`$vars` literal and are evaluated at hit time, e.g. `break tick if $rdi >= 0x10 && $rdi <= 0x20`.
- On a hit the target stays held stopped with `$rip` at the breakpoint address for inspection; `continue` single-steps the real instruction and re-arms the int3 before resuming.
- Breakpoints survive `detach` and are re-armed automatically on the next `attach`/`continue`.
- Target commands (`trace`, `ftrace`, `dump`, ...) default to `$pid` when the pid argument is omitted.
- Expressions support C-style precedence, including comparisons, logical and bitwise operators (`== != < <= > >= & ^ | && || ~ !`).

## Cool Features

### Inject Shellcode

Execute arbitrary machine code in a live process. This bypasses normal function calls and can be used for:
- Exploit development
- Runtime code injection
- Quick payload execution

### Load Shared Libraries

Dynamically load a .so into a running process. This is powerful for:
- Runtime instrumentation
- Debugging without restart
- Extending functionality dynamically

### Resolve Symbols

Resolve function addresses in a remote process using dlsym. Useful when you need to:
- Find addresses of functions without hardcoding them
- Call functions in dynamically loaded libraries
- Build payloads that work across different ASLR layouts

### Memory Watching

Monitor memory regions for changes. Useful for:
- Detecting memory corruption
- Finding writes to sensitive areas
- Reverse engineering

## Building

```bash
make
```

## Possible New Features

- **File descriptor restoration** - Save and restore open FDs
- **Signal state preservation** - Pending signals, handlers, masks
- **Child process trees** - Checkpoint entire process groups
- **Memory compression** - Compress saved regions
- **CRIU compatibility** - Import/export CRIU format
- **Live migration** - Checkpoint, transfer, restore over network

## License

ckptmini inherits the license from [pmparser](https://github.com/ouadev/proc_maps_parser) (used for memory map parsing):

```
@Author  : ouadev
@date    : December 2015

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.  No representations are made about the suitability of this
software for any purpose.  It is provided "as is" without express or
implied warranty.
```
