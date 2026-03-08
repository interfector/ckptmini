/*
 * test_collider.c - Test program to demonstrate address collision scenarios
 * 
 * This program reserves specific addresses (0x600000, 0x700000, 0x800000) that
 * will be included in the checkpoint. The intent is to test what happens when
 * we try to restore this checkpoint into a process that already has these addresses
 * mapped.
 *
 * NOTE: In practice, both "restore" and "parasite" commands work because:
 *   1. Linux's virtual address space is vast (128TB on x86_64)
 *   2. MAP_FIXED allows replacing existing mappings
 *   3. Address collisions are rare in typical scenarios
 *
 * The theoretical difference:
 *   - restore: writes directly to checkpoint addresses (may fail if addresses collide)
 *   - parasite: pre-allocates fresh memory at original addresses first (more robust)
 *
 * To truly force a collision, you'd need a program that consumes most of the
 * virtual address space before attempting restore.
 */

#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

int main() {
    /* Reserve 3 specific addresses - these will be in the checkpoint */
    void *addrs[] = {
        (void*)0x600000,
        (void*)0x700000, 
        (void*)0x800000,
    };
    
    printf("Reserving addresses for collision test...\n");
    for (int i = 0; i < 3; i++) {
        void *p = mmap(addrs[i], 0x1000, 
                       PROT_READ|PROT_WRITE, 
                       MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
        if (p == MAP_FAILED) {
            printf("Failed to reserve %p\n", addrs[i]);
        } else {
            printf("Reserved: %p\n", p);
            /* Write recognizable data so we can verify restore worked */
            memset(p, 0xAA + i, 0x1000);
        }
    }
    
    printf("Holding addresses (PID %d)...\n", getpid());
    sleep(30);
    
    return 0;
}
