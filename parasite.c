#include "parasite.h"

#define NULL ((void*)0)

#define SYS_mmap     9
#define SYS_mprotect 10
#define SYS_munmap   11

#define PROT_READ    0x1
#define PROT_WRITE   0x2
#define PROT_EXEC    0x4

#define MAP_PRIVATE   0x2
#define MAP_ANONYMOUS 0x20
#define MAP_FIXED     0x10

#define STACK_SIZE 65536

void parasite_entry(void) __attribute__((naked));
void parasite_main(ParasiteArgs *args);
void self_unmap_and_jump(uint64_t parasite_start, uint64_t parasite_size, uint64_t target_rip, uint64_t target_rsp);

// Entry point - MUST BE FIRST
void parasite_entry(void) {
    asm volatile (
        "mov %r12, %rdi\n\t"      // Pass args in RDI
        "mov 0x28(%rdi), %rax\n\t" // Load args->scratch_offset (offset 40=0x28) into RAX
        "mov 0x08(%rdi), %rdx\n\t" // Load args->parasite_start (offset 8) into RDX  
        "add %rdx, %rax\n\t"       // Add parasite_start to scratch_offset
        // Actually, use stack_offset for RSP setup
        "mov 0x20(%rdi), %rax\n\t" // Load args->stack_offset (offset 32=0x20) into RAX
        "mov 0x08(%rdi), %rdx\n\t" // Load args->parasite_start (offset 8) into RDX  
        "add %rdx, %rax\n\t"       // Add parasite_start to stack_offset
        "add $0xfff8, %rax\n\t"    // Add STACK_SIZE - 8 (0xfff8)
        "mov %rax, %rsp\n\t"       // Set RSP to stack_top
        "jmp parasite_main\n\t"
    );
}

static void *do_mmap(void *addr, uint64_t len, int prot, int flags, int fd, uint64_t offset) {
    void *ret;
    asm volatile (
        "mov %[addr], %%rdi\n\t"
        "mov %[len], %%rsi\n\t"
        "mov %[prot], %%rdx\n\t"
        "mov %[flags], %%r10\n\t"
        "mov %[fd], %%r8\n\t"
        "mov %[offset], %%r9\n\t"
        "mov $9, %%rax\n\t"
        "syscall\n\t"
        "mov %%rax, %[ret]\n\t"
        : [ret] "=r"(ret)
        : [addr] "r"((uint64_t)addr), [len] "r"(len), [prot] "r"((uint64_t)prot),
          [flags] "r"((uint64_t)flags), [fd] "r"((uint64_t)fd), [offset] "r"(offset)
        : "rax", "rcx", "r11", "memory"
    );
    return ret;
}

static int do_munmap(void *addr, uint64_t len) {
    int64_t ret;
    asm volatile (
        "mov %[addr], %%rdi\n\t"
        "mov %[len], %%rsi\n\t"
        "mov $11, %%rax\n\t"
        "syscall\n\t"
        "mov %%rax, %[ret]\n\t"
        : [ret] "=r"(ret)
        : [addr] "r"((uint64_t)addr), [len] "r"(len)
        : "rax", "rdi", "rsi", "rcx", "r11", "memory"
    );
    return (int)ret;
}

static int do_mprotect(void *addr, uint64_t len, int prot) {
    int64_t ret;
    asm volatile (
        "mov %[addr], %%rdi\n\t"
        "mov %[len], %%rsi\n\t"
        "mov %[prot], %%rdx\n\t"
        "mov $10, %%rax\n\t"
        "syscall\n\t"
        "mov %%rax, %[ret]\n\t"
        : [ret] "=r"(ret)
        : [addr] "r"((uint64_t)addr), [len] "r"(len), [prot] "r"((uint64_t)prot)
        : "rax", "rdi", "rsi", "rdx", "rcx", "r11", "memory"
    );
    return (int)ret;
}

static void do_memcpy(void *dst, const void *src, uint64_t len) {
    asm volatile (
        "mov %[dst], %%rdi\n\t"
        "mov %[src], %%rsi\n\t"
        "mov %[len], %%rcx\n\t"
        "rep movsb\n\t"
        : 
        : [dst] "r"(dst), [src] "r"(src), [len] "r"(len)
        : "rdi", "rsi", "rcx", "memory"
    );
}

void parasite_main(ParasiteArgs *args) {
    RegionDesc *regions = (RegionDesc*)(args + 1);
    ControlBlock *ctrl = (ControlBlock*)(args->parasite_start + args->ctrl_offset);
    uint8_t *scratch_base = (uint8_t*)(args->parasite_start + args->scratch_offset);
    
    // Mark entry to parasite_main
    ctrl->status = 1;
    ctrl->debug_info = (uint64_t)args;
    
    // Stack already set in parasite_entry
    // Mark stack switched
    ctrl->status = 2;

    asm volatile ("int3" : : : "memory");

    for (uint64_t i = 0; i < args->num_regions; i++) {
        RegionDesc *r = &regions[i];

        if (r->flags & IS_VDSO) {
            continue;
        }
        if (r->flags & IS_VSYSCALL) {
            continue;
        }
        if (r->flags & IS_SKIP) {
            continue;
        }
        if (r->start == args->parasite_start) {
            continue;
        }

        // Spin-wait for cmd to change from CMD_WAIT
        // ckptmini has written checkpoint data to scratch area and updated ctrl->cmd to CMD_NEXT
        while (ctrl->cmd == CMD_WAIT) {
            asm volatile ("pause" : : : "memory");
        }

        ctrl->status = 10 + i;  // Mark we received signal

        if (ctrl->cmd == CMD_GO) {
            break;
        }

        // Data is now in scratch area, copied there by ckptmini
        // r->start now contains the NEW address (pre-allocated by ckptmini)
        ctrl->status = 20 + i;
        
        // Make the pre-allocated region writable
        do_mprotect((void*)r->start, r->size, PROT_READ | PROT_WRITE);
        
        ctrl->status = 45 + i;
        ctrl->actual_addr = (uint64_t)r->start;
        ctrl->debug_info = (uint64_t)r->start;
        
        // Copy data from scratch to NEW address (r->start was updated by ckptmini)
        do_memcpy((void*)r->start, scratch_base, ctrl->write_size);
        
        ctrl->status = 60 + i;
        
        // Restore correct permissions
        do_mprotect((void*)r->start, r->size, r->prot);

        ctrl->cmd = CMD_WAIT;
        asm volatile ("int3" : : : "memory");
    }

    // Final int3: "All regions done, waiting for register restore and GO signal"
    asm volatile ("int3" : : : "memory");
    
    // Spin-wait for CMD_GO after register restoration
    while (ctrl->cmd != CMD_GO) {
        asm volatile ("pause" : : : "memory");
    }

    self_unmap_and_jump(args->parasite_start, args->parasite_size, args->restore_rip, args->restore_rsp);
}
