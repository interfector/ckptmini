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

This saves:
- All CPU registers
- Complete memory contents (stack, heap, code, libraries)
- Process command line and environment

**Limitations:**
- Single-threaded processes only
- Does not preserve open file descriptors
- Does not preserve signal handlers or pending signals
- ASLR may cause issues on restore if addresses differ

## Command Reference

### Checkpoint & Restore

| Command | Description |
|---------|-------------|
| `save <pid> <dir>` | Save complete process state (registers, memory, metadata) to directory |
| `restore <pid> <dir>` | Restore saved checkpoint into a running process |
| `replay <prog> <dir>` | Fork and exec program, then restore checkpoint into it |
| `relocate <pid> <dir>` | Restore memory layout from dump into a different process |

**Limitations:** All save/restore commands above are single-threaded only.

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
| `read_dump <dir> <addr> <len>` | Read memory from a checkpoint dump |
| `write_dump <dir> <addr> <hex>` | Modify memory in a checkpoint file |
| `write_dump_str <dir> <addr> <str>` | Write string to checkpoint dump |

**Limitations:** Cannot add new memory regions; only modify existing ones.

### Search

| Command | Description |
|---------|-------------|
| `search_str <pid> <str> [seg]` | Search for string in process memory |
| `search_all_str <pid> <str> [seg]` | Find all occurrences in process |
| `search_dump_str <dir> <str> [seg]` | Search for string in checkpoint |
| `search_dump_all_str <dir> <str>` | Find all matches in checkpoint |
| `search_bytes <pid> <hex> [seg]` | Search for byte pattern in live process |
| `search_dump_bytes <dir> <hex> [seg]` | Search for bytes in checkpoint |

The optional `seg` filter can be: `stack`, `heap`, `lib`, `any`.

**Limitations:** Searches are linear and slow on large memory regions.

### Process Inspection

| Command | Description |
|---------|-------------|
| `backtrace <pid> [-p]` | Print stack backtrace; `-p` pauses process first |
| `fds <pid>` | List all open file descriptors and their targets |
| `signals <pid>` | Display signal handler configuration |
| `trace <pid>` | Trace syscalls (strace-like output) |

**Limitations:**
- `backtrace` may be inaccurate with optimized binaries or missing debug symbols
- `trace` is basic; doesn't capture syscall arguments in full

### Debugging

| Command | Description |
|---------|-------------|
| `breakpoint <pid> <addr>` | Set an int3 breakpoint at address |
| `setreg <pid> <name> <val>` | Modify a CPU register by name |
| `setreg_dump <dir> <name> <val>` | Modify registers in a checkpoint |

Register names: rip, rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp, r8-r15.

**Limitations:** Breakpoints are single-shot; they are removed after triggering.

### Code Injection

| Command | Description |
|---------|-------------|
| `inject_shellcode <pid> <hex>` | Write and execute machine code in process |

Example - spawn a shell:
```bash
./ckptmini inject_shellcode 12345 4831c0b89a01000000000000
# execve("/bin/sh", 0, 0)
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

`load_so` uses `dlopen` internally to inject the library.

**Limitations:**
- Function addresses must be known (static binaries harder)
- Arguments limited to basic types
- No automatic cleanup of function results

### Modifying Checkpoint Dumps

| Command | Description |
|---------|-------------|
| `dump <dir>` | Legacy alias for creating checkpoint |
| `snapshot_diff <pid> <dir>` | Compare live process memory to saved checkpoint |

**Limitations:** Diff only shows changes; doesn't auto-merge.

### Register Access

| Command | Description |
|---------|-------------|
| `setreg_dump <dir> <name> <val>` | Modify saved register values in checkpoint |

### Hex Parsing

The tool uses standard hex string format: `4831c0` = bytes [0x48, 0x31, 0xc0].

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

- **Thread support** - Handle multi-threaded processes
- **File descriptor restoration** - Save and restore open FDs
- **Signal state preservation** - Pending signals, handlers, masks
- **Child process trees** - Checkpoint entire process groups
- **Memory compression** - Compress saved regions
- **Incremental checkpoints** - Diff-based snapshots
- **CRIU compatibility** - Import/export CRIU format
- **Live migration** - Checkpoint, transfer, restore over network

## License

ckptmini inherits the license from pmparser (used for memory map parsing):

```
@Author  : nex
@date    : February 2026

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
