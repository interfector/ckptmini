#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

#define SAVE_SIZE 16
#define MSG_SIZE 256

static unsigned char saved_bytes[SAVE_SIZE];
static void *libc_printf_addr = NULL;
static unsigned char patch_bytes[5];

int hijack_printf(const char *fmt, ...) {
    char msg[MSG_SIZE];
    snprintf(msg, sizeof(msg), "[hijack] printf called\n%s", fmt);
    
    // Restore original bytes
    memcpy(libc_printf_addr, saved_bytes, SAVE_SIZE);
    
    // Call original printf
    va_list args;
    va_start(args, fmt);
    int result = vprintf(msg, args);
    va_end(args);
    
    // Re-patch to jump back to hijack_printf
    memcpy(libc_printf_addr, patch_bytes, 5);
    
    return result;
}

__attribute__((constructor))
static void init(void) {
    libc_printf_addr = &printf;
    
    printf("[hijacklib] constructor: loading...\n");
    printf("[hijacklib] libc printf at: %p\n", libc_printf_addr);
    printf("[hijacklib] hijack_printf at: %p\n", (void *)&hijack_printf);
    
    long page_size = sysconf(_SC_PAGESIZE);
    uintptr_t page_start = (uintptr_t)libc_printf_addr & ~(page_size - 1);
    
    printf("[hijacklib] mprotect page at: %p\n", (void *)page_start);
    
    if (mprotect((void *)page_start, page_size, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        printf("[hijacklib] ERROR: mprotect failed: %s\n", strerror(errno));
        return;
    }
    
    memcpy(saved_bytes, libc_printf_addr, SAVE_SIZE);
    
    long offset = (uintptr_t)&hijack_printf - ((uintptr_t)libc_printf_addr + 5);
    
    patch_bytes[0] = 0xE9;  // jmp rel32
    patch_bytes[1] = (offset >> 0) & 0xFF;
    patch_bytes[2] = (offset >> 8) & 0xFF;
    patch_bytes[3] = (offset >> 16) & 0xFF;
    patch_bytes[4] = (offset >> 24) & 0xFF;
    
    memcpy(libc_printf_addr, patch_bytes, 5);
    
    printf("[hijacklib] patched printf with jmp to hijack_printf!\n");
}

__attribute__((destructor))
static void cleanup(void) {
    if (libc_printf_addr && saved_bytes[0] != 0) {
        memcpy(libc_printf_addr, saved_bytes, SAVE_SIZE);
        printf("[hijacklib] restored original printf bytes\n");
    }
}

void *get_unhook_addr(void) { return &cleanup; }
