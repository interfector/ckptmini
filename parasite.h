#ifndef PARASITE_H
#define PARASITE_H

#include <stdint.h>
#include <stdbool.h>

#define CMD_WAIT  0
#define CMD_NEXT  1
#define CMD_GO    2

#define IS_VDSO     0x0001
#define IS_VSYSCALL 0x0002
#define IS_SKIP     0x0004

typedef struct {
    volatile uint32_t cmd;
    volatile uint32_t status;
    volatile uint64_t debug_info;
    uint32_t region_index;
    uint64_t write_addr;
    uint64_t write_size;
    uint64_t actual_addr;  // Actual address where region was mapped
} ControlBlock;

typedef struct {
    uint64_t num_regions;
    uint64_t parasite_start;
    uint64_t parasite_size;
    uint64_t ctrl_offset;
    uint64_t stack_offset;
    uint64_t scratch_offset;  // Offset to scratch area within parasite mapping
    uint64_t scratch_size;    // Size of scratch area
    uint64_t restore_rip;
    uint64_t restore_rsp;
} ParasiteArgs;

typedef struct {
    uint64_t start;
    uint64_t size;
    uint32_t prot;
    uint32_t flags;
} RegionDesc;

#endif
