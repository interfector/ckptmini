#ifndef CKPTMINI_H
#define CKPTMINI_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <signal.h>
#include <dirent.h>
#include <time.h>

#include <pmparser.h>

#if defined(__x86_64__)
  #include <sys/user.h>
  typedef struct user_regs_struct regs_t;
#else
  #error "This demo currently targets x86_64 only."
#endif

/**
 * @brief Exit on error with message
 * @param msg The error message to print
 */
#define DIE(msg) do { perror(msg); exit(EXIT_FAILURE); } while(0)

/**
 * @brief Exit if condition is false
 * @param cond The condition to check
 * @param msg The error message to print if condition fails
 */
#define ENSURE(cond, msg) do { if(!(cond)) { fprintf(stderr, "%s\n", msg); exit(EXIT_FAILURE);} } while(0)

/* Terminal color codes for colored output */
#define A_RESET  "\033[0m"
#define A_BOLD   "\033[1m"
#define A_DIM    "\033[2m"
#define A_RED    "\033[31m"
#define A_GREEN  "\033[32m"
#define A_YELLOW "\033[33m"
#define A_CYAN   "\033[36m"
#define A_WHITE  "\033[97m"
#define A_BGBLUE "\033[44m"

/* Unicode symbols for status messages */
#define S_OK "★"
#define S_INFO "◆"
#define S_ERR "⚠"

/**
 * @brief Register entry for x86_64 CPU registers
 * Used to map register names to their offsets in struct user_regs_struct
 */
typedef struct { const char *name; size_t offset; } reg_entry_t;

typedef enum { SETREG_LIVE, SETREG_DUMP } setreg_mode_t;
typedef enum { SHOW_LIVE, SHOW_DUMP } show_mode_t;

/**
 * @brief Memory region descriptor
 * Represents a single memory mapping with its address range and properties
 */
typedef struct {
    uint64_t start, end;  /**< Start and end addresses of the region */
    int prot;             /**< Protection flags (PROT_READ, PROT_WRITE, PROT_EXEC) */
    char name[256];       /**< Pathname or name of the mapping (e.g., "/lib/libc.so") */
    bool dump;            /**< Whether this region should be included in checkpoint */
} region_t;

/**
 * @brief Saved map descriptor for restored checkpoints
 * Simplified version of region_t used when loading saved checkpoints
 */
typedef struct {
    uint64_t start, end;
    int prot;
} saved_map_t;

/**
 * @brief Context for iterating over memory maps
 * Used as argument to callback functions in for_each_map_* functions
 */
typedef struct {
    bool (*callback)(uint64_t start, uint64_t end, int prot, const char *pathname, void *arg);
    void *arg;
} pm_iter_ctx_t;

/**
 * @brief Context for memory search operations
 * Holds search pattern and results for byte/string searching in memory
 */
typedef struct { 
    const unsigned char *needle;  /**< Pattern to search for */
    size_t nlen;                  /**< Length of the pattern */
    const char *seg;              /**< Segment filter (e.g., "heap", "stack", "any") */
    uint64_t found;               /**< First match address (for single search) */
    FILE *out_all;                /**< Output file for "find all" searches */
} search_ctx_t;

/**
 * @brief Set a CPU register by name
 * @param regs Pointer to register structure
 * @param name Register name (e.g., "rax", "rip", "rsp")
 * @param value Value to set
 * @return 0 on success, -1 if register not found
 */
int set_reg_by_name(struct user_regs_struct *regs, const char *name, uint64_t value);

/**
 * @brief Get a CPU register value by name
 * @param regs Pointer to register structure
 * @param name Register name
 * @param out Pointer to store the retrieved value
 * @return 0 on success, -1 if register not found
 */
int get_reg_by_name(const struct user_regs_struct *regs, const char *name, uint64_t *out);

/**
 * @brief Set register in either live process or checkpoint dump
 * @param mode Either SETREG_LIVE or SETREG_DUMP
 * @param target PID for live mode, directory path for dump mode
 * @param regname Register name to modify
 * @param value New value
 * @return 0 on success
 */
int setreg(setreg_mode_t mode, void *target, const char *regname, uint64_t value);

/**
 * @brief Parse hexadecimal string to bytes
 * @param hex Hex string (e.g., "4831c0")
 * @param out_len Output: length of resulting byte array
 * @return Newly allocated byte array, or NULL on error
 */
unsigned char* parse_hex(const char *hex, size_t *out_len);

/**
 * @brief Parse permission string to mprotect flags
 * @param s Permission string (e.g., "rwx", "rw")
 * @return Protection flags (PROT_READ|PROT_WRITE|PROT_EXEC)
 */
int parse_perms(const char *s);

/**
 * @brief Create directory path, exit on failure
 * @param p Directory path to create
 */
void mkpath_or_die(const char *p);

/**
 * @brief Write all bytes or exit on error
 * @param fd File descriptor
 * @param buf Buffer to write
 * @param sz Number of bytes to write
 */
void write_all_or_die(int fd, const void *buf, size_t sz);

/**
 * @brief Read all bytes or exit on error
 * @param fd File descriptor
 * @param buf Buffer to read into
 * @param sz Number of bytes to read
 */
void read_all_or_die(int fd, void *buf, size_t sz);

/**
 * @brief Check if stdout is a TTY
 * @return true if stdout is a terminal
 */
bool is_tty(void);

/**
 * @brief Global flag: true if stdout is a TTY (set once at startup)
 */
extern bool g_is_tty;

/**
 * @brief Format bytes as human-readable size
 * @param bytes Number of bytes
 * @param buf Output buffer
 * @param bufsz Buffer size
 * @return Pointer to formatted string
 */
const char *hr_size(uint64_t bytes, char *buf, size_t bufsz);

/**
 * @brief Print hexdump line (16 bytes per line)
 * @param base Starting address
 * @param buf Data to dump
 * @param len Number of bytes
 */
void hexdump_line(uint64_t base, const unsigned char *buf, size_t len);

/**
 * @brief Print timestamp with milliseconds
 */
void print_timestamp(void);

/**
 * @brief Parse memory maps from live process
 * @param pid Process ID
 * @return Iterator over memory regions, or NULL on error
 */
procmaps_iterator* parse_maps_live(pid_t pid);

/**
 * @brief Parse memory maps from saved checkpoint
 * @param indir Checkpoint directory path
 * @return Iterator over memory regions, or NULL on error
 */
procmaps_iterator* parse_maps_dump(const char *indir);

/**
 * @brief Get protection flags for address range in live process
 * @param pid Process ID
 * @param start Start address
 * @param end End address
 * @return Protection flags, or 0 if range not found
 */
int prot_for_range_live(pid_t pid, uint64_t start, uint64_t end);

/**
 * @brief Iterate over all memory maps in live process
 * @param pid Process ID
 * @param cb Callback function for each region
 * @param arg User argument passed to callback
 */
void for_each_map_live(pid_t pid, bool (*cb)(uint64_t, uint64_t, int, const char*, void*), void *arg);

/**
 * @brief Iterate over all memory maps in checkpoint dump
 * @param indir Checkpoint directory
 * @param cb Callback function for each region
 * @param arg User argument passed to callback
 */
void for_each_map_dump(const char *indir, bool (*cb)(uint64_t, uint64_t, int, const char*, void*), void *arg);

/**
 * @brief Iterate with additional perms/path info
 * @param pid Process ID
 * @param cb Callback with permissions string and pathname
 * @param ud User data
 * @return true on success
 */
bool for_each_mapping(pid_t pid, bool (*cb)(pid_t, uint64_t, uint64_t, const char*, const char*, void*), void *ud);

/**
 * @brief Save CPU registers to checkpoint
 * @param pid Process ID
 * @param dir Checkpoint directory
 */
void save_regs(pid_t pid, const char *dir);

/**
 * @brief Save process metadata (cmdline, environ)
 * @param pid Process ID
 * @param dir Checkpoint directory
 */
void save_meta(pid_t pid, const char *dir);

/**
 * @brief Save all memory maps and contents
 * @param pid Process ID
 * @param dir Checkpoint directory
 */
void save_maps_and_memory(pid_t pid, const char *dir);

/**
 * @brief Dump memory region to binary file
 * @param dir Output directory
 * @param rg Region descriptor
 * @param data Memory data
 * @param len Length
 * @return Number of bytes written
 */
size_t dump_region_bin(const char *dir, const region_t *rg, const void *data, size_t len);

/**
 * @brief Read bytes from process memory
 * @param pid Process ID
 * @param memfd Open /proc/pid/mem file descriptor
 * @param start Start address
 * @param buf Output buffer
 * @param len Bytes to read
 * @return Bytes actually read
 */
size_t dump_bytes_from_mem(pid_t pid, int memfd, uint64_t start, void *buf, size_t len);

/**
 * @brief Full checkpoint: save process state to disk
 * @param pid Process ID to checkpoint
 * @param outdir Output directory for checkpoint
 */
void checkpoint(pid_t pid, const char *outdir);

/**
 * @brief Execute syscall in remote process
 * Uses ptrace to inject and execute a syscall
 * @param pid Target process ID
 * @param nr Syscall number
 * @param a1-a6 Syscall arguments
 * @return Syscall return value
 */
long remote_syscall_x64(pid_t pid, long nr, unsigned long a1, unsigned long a2, unsigned long a3,
                        unsigned long a4, unsigned long a5, unsigned long a6);

/**
 * @brief Allocate memory at fixed address in remote process
 * @param pid Target process
 * @param addr Desired address
 * @param len Size to allocate
 * @param prot Protection flags
 * @param flags mmap flags
 * @return 0 on success, -1 on failure
 */
int remote_mmap_fixed(pid_t pid, uint64_t addr, size_t len, int prot, int flags);

/**
 * @brief Change memory protection in remote process
 * @param pid Target process
 * @param addr Start address
 * @param len Size
 * @param prot New protection flags
 * @return 0 on success, -1 on failure
 */
int remote_mprotect(pid_t pid, uint64_t addr, size_t len, int prot);

/**
 * @brief Load saved map information from checkpoint
 * @param dir Checkpoint directory
 * @param out Output: array of saved_map_t
 * @return Number of maps loaded
 */
size_t load_saved_maps(const char *dir, saved_map_t **out);

/**
 * @brief Get protection flags for address in saved maps
 * @param maps Array of saved maps
 * @param nmaps Number of maps
 * @param start Start address
 * @param end End address
 * @param defprot Default if not found
 * @return Protection flags
 */
int prot_for_range(saved_map_t *maps, size_t nmaps, uint64_t start, uint64_t end, int defprot);

/**
 * @brief Read bytes from live process memory
 * Uses process_vm_readv first, falls back to /proc/PID/mem
 * @param pid Process ID
 * @param addr Source address
 * @param data Destination buffer
 * @param len Number of bytes
 * @return true on success
 */
bool read_bytes_from_pid(pid_t pid, uintptr_t addr, void *data, size_t len);

/**
 * @brief Write bytes to live process memory
 * Uses process_vm_writev first, falls back to /proc/PID/mem
 * @param pid Process ID
 * @param addr Destination address
 * @param buf Source buffer
 * @param len Number of bytes
 * @return true on success
 */
bool write_bytes_to_pid(pid_t pid, uint64_t addr, const void *buf, size_t len);

/**
 * @brief Open /proc/PID/mem file
 * @param pid Process ID
 * @param flags Open flags (O_RDONLY, O_RDWR, etc.)
 * @return File descriptor, or -1 on error
 */
int get_memfd(pid_t pid, int flags);

/**
 * @brief Write data to memory region
 * @param pid Process ID
 * @param addr Target address
 * @param data Source data
 * @param len Length
 * @return true on success
 */
bool mem_write_region(pid_t pid, uint64_t addr, const void *data, size_t len);

/**
 * @brief Load registers from checkpoint
 * @param pid Target process
 * @param dir Checkpoint directory
 */
void load_regs(pid_t pid, const char *dir);

/**
 * @brief Map and fill memory region from file
 * @param pid Process ID
 * @param memfd Open /proc/PID/mem file descriptor
 * @param start Target start address
 * @param end Target end address
 * @param prot Protection flags
 * @param binfile Source file with memory data
 * @return true on success
 */
bool map_and_fill_region(pid_t pid, int memfd, uint64_t start, uint64_t end, int prot, const char *binfile);

/**
 * @brief Restore all memory regions from checkpoint
 * @param pid Target process
 * @param dir Checkpoint directory
 * @return true on success
 */
bool restore_regions(pid_t pid, const char *dir);

/**
 * @brief Restore process from checkpoint (full restore)
 * @param pid Target process (already attached)
 * @param dir Checkpoint directory
 */
void restore_into(pid_t pid, const char *dir);

/**
 * @brief Restore with address relocation (for different ASLR)
 * @param pid Target process
 * @param indir Checkpoint directory
 */
void relocate_into(pid_t pid, const char *indir);

/**
 * @brief Display memory maps and registers
 * @param mode SHOW_LIVE or SHOW_DUMP
 * @param arg PID or directory path
 */
void show_maps_and_regs(show_mode_t mode, const char *arg);

/**
 * @brief Dump command: show memory regions
 * @param arg PID (live) or directory (dump)
 */
void cmd_dump(const char *arg);

/**
 * @brief Watch memory region for changes
 * Polls memory and shows hexdump when changes detected
 * @param pid Process ID
 * @param addr Start address
 * @param len Length to watch
 * @param interval_ms Polling interval in milliseconds
 */
void cmd_watch(pid_t pid, uint64_t addr, size_t len, unsigned int interval_ms);

/**
 * @brief Compare live process memory to saved checkpoint
 * @param pid Process ID
 * @param indir Checkpoint directory
 */
void cmd_snapshot_diff(pid_t pid, const char *indir);

/**
 * @brief Set breakpoint at address
 * @param pid Process ID
 * @param addr Breakpoint address
 */
void cmd_breakpoint(pid_t pid, uint64_t addr);

/**
 * @brief Inject and execute shellcode
 * Writes hex machine code to process and executes it
 * @param pid Process ID
 * @param hex Hex-encoded shellcode
 */
void cmd_inject_shellcode(pid_t pid, const char *hex);

/**
 * @brief Trace syscalls (strace-like)
 * @param pid Process ID
 */
void cmd_trace(pid_t pid);

/**
 * @brief Change memory protection
 * @param pid Process ID
 * @param addr Start address
 * @param len Length
 * @param perms_str Permission string ("rwx", "rw", etc.)
 */
void cmd_mprotect(pid_t pid, uint64_t addr, size_t len, const char *perms_str);

/**
 * @brief Show stack backtrace
 * @param pid Process ID
 * @param pause Whether to pause process first
 */
void cmd_backtrace(pid_t pid, bool pause);

/**
 * @brief Show signal handler configuration
 * @param pid Process ID
 */
void cmd_signals(pid_t pid);

/**
 * @brief List open file descriptors
 * @param pid Process ID
 */
void cmd_fds(pid_t pid);

/**
 * @brief Call function in remote process
 * @param pid Process ID
 * @param addr Function address
 * @param argc Argument count
 * @param argv Arguments
 * @param detach Detach after call
 * @return Function return value
 */
uintptr_t cmd_call(pid_t pid, uint64_t addr, int argc, char **argv, bool detach);

/**
 * @brief Call function with return value
 * @param pid Process ID
 * @param addr Function address
 * @param argc Argument count
 * @param argv Arguments
 * @param detach Detach after call
 * @param ret_val Output: return value
 * @return Function return value
 */
uintptr_t cmd_call_ret(pid_t pid, uint64_t addr, int argc, char **argv, bool detach, uintptr_t *ret_val);

/**
 * @brief Load shared library into process
 * Uses dlopen to inject .so file
 * @param pid Process ID
 * @param so_path Path to .so file
 */
void cmd_load_so(pid_t pid, const char *so_path);

/**
 * @brief Spawn process in paused state
 * @param argv Program and arguments
 */
void spawn_paused_and_print(char **argv);

/**
 * @brief Spawn, run briefly, then pause
 * @param argv Program and arguments
 * @param run_us Microseconds to run before pausing
 */
void spawn_show_then_pause(char **argv, useconds_t run_us);

/**
 * @brief Stop process with SIGSTOP
 * @param pid Process ID
 */
void stop_pid(pid_t pid);

/**
 * @brief Continue process with SIGCONT
 * @param pid Process ID
 */
void cont_pid(pid_t pid);

/**
 * @brief Single-step process
 * @param pid Process ID
 * @param max_steps Number of steps
 */
void step_pid(pid_t pid, int max_steps);

/**
 * @brief Search for pattern in all checkpoint memory regions
 * @param indir Checkpoint directory
 * @param needle Pattern bytes
 * @param nlen Pattern length
 * @param seg Segment filter
 * @param count Max results (-1 for all)
 * @return Number of matches found
 */
size_t search_all_in_dumped_maps(const char *indir, const unsigned char *needle, size_t nlen, const char *seg, size_t count);

/**
 * @brief Check if permissions match segment filter
 * @param perms Permissions string (e.g., "rwx")
 * @param seg Segment filter ("text", "data", "any")
 * @return true if matches
 */
bool mapping_matches_seg_perms(const char *perms, const char *seg);

/**
 * @brief Build permissions string from map
 * @param map Memory map structure
 * @param perms Output buffer (5 bytes)
 */
void get_perms_string(const procmaps_struct *map, char *perms);

/**
 * @brief Find checkpoint chunk file containing address
 * @param memdir Memory dump directory
 * @param addr Address to find
 * @param len Length of region
 * @param path Output: full path to chunk file
 * @param path_sz Path buffer size
 * @param out_offset Output: offset within chunk
 * @return 0 on success, -1 if not found
 */
int find_chunk_for_addr(const char *memdir, uint64_t addr, size_t len, char *path, size_t path_sz, off_t *out_offset);

/**
 * @brief Search callback for mapping iteration
 * @param pid Process ID
 * @param start Region start
 * @param end Region end
 * @param perms Permissions string
 * @param path Mapping path
 * @param ud User data (search_ctx_t)
 * @return true to continue, false to stop
 */
bool search_bytes_in_map_cb(pid_t pid, uint64_t start, uint64_t end, const char *perms, const char *path, void *ud);

typedef struct {
    pid_t tid;             /**< Thread ID */
    uint64_t stack_start;  /**< Stack start address */
    uint64_t stack_end;   /**< Stack end address */
} thread_info_t;

/**
 * @brief Get list of all threads in a process
 * @param pid Process ID
 * @param count Output: number of threads found
 * @return Dynamically allocated array of thread_info_t, must be freed
 */
thread_info_t* get_thread_list(pid_t pid, size_t *count);

/**
 * @brief Save thread registers to checkpoint
 * @param tid Thread ID
 * @param dir Checkpoint directory
 */
void save_thread_regs(pid_t tid, const char *dir);

/**
 * @brief Save all threads (including main) to checkpoint
 * @param pid Main process ID
 * @param dir Checkpoint directory
 */
void save_all_threads(pid_t pid, const char *dir);

/**
 * @brief Load thread list from checkpoint
 * @param dir Checkpoint directory
 * @param count Output: number of threads
 * @return Dynamically allocated array of thread IDs
 */
pid_t* load_thread_list(const char *dir, size_t *count);

/**
 * @brief Load thread registers from checkpoint
 * @param tid Thread ID (used for directory naming)
 * @param dir Checkpoint directory
 * @return regs_t structure with saved registers
 */
regs_t load_thread_regs(pid_t tid, const char *dir);

/**
 * @brief Restore all threads from checkpoint (except main)
 * @param pid Main process ID (already restored)
 * @param dir Checkpoint directory
 */
void restore_threads(pid_t pid, const char *dir);

/**
 * @brief Full checkpoint with thread support
 * @param pid Process ID
 * @param outdir Output directory
 */
void checkpoint_with_threads(pid_t pid, const char *outdir);

/**
 * @brief Restore with thread support
 * @param pid Target process
 * @param dir Checkpoint directory
 */
void restore_with_threads(pid_t pid, const char *dir);

/**
 * @brief Show threads of a live process
 * @param pid Process ID
 */
void show_threads(pid_t pid);

/**
 * @brief Show saved threads from checkpoint
 * @param dir Checkpoint directory
 */
void show_threads_dump(const char *dir);

/**
 * @brief Check if region should be included in checkpoint
 * @param map Memory map structure
 * @return true if region should be dumped
 */
bool region_is_minimal_target_pm(const procmaps_struct *map);

/**
 * @brief Print usage information
 * @param prog Program name
 */
void usage(const char *prog);

/**
 * @brief Check if checkpoint is incremental
 * @param dir Checkpoint directory
 * @return true if incremental checkpoint
 */
bool is_incremental_checkpoint(const char *dir);

/**
 * @brief Get baseline checkpoint directory for incremental checkpoint
 * @param dir Incremental checkpoint directory
 * @param out Baseline directory path buffer
 * @param out_sz Buffer size
 * @return 0 on success, -1 if not found
 */
int get_baseline_dir(const char *dir, char *out, size_t out_sz);

/**
 * @brief Save incremental checkpoint (only changed regions)
 * @param pid Process ID
 * @param outdir Output directory for incremental checkpoint
 * @param baseline_dir Previous checkpoint directory (can be NULL for full)
 */
void incremental_checkpoint(pid_t pid, const char *outdir, const char *baseline_dir);

/**
 * @brief Restore from incremental checkpoint
 * @param pid Target process
 * @param indir Checkpoint directory (incremental or baseline)
 */
void incremental_restore(pid_t pid, const char *indir);

#endif
