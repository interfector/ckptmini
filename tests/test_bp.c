#include <stdio.h>
#include <unistd.h>

/* Called every iteration with the current counter, so a conditional
   breakpoint on tick can test the argument in $rdi. */
__attribute__((noinline)) static unsigned long tick(unsigned long v) {
    return v + 1;
}

int main(void) {
    unsigned long i = 0;
    for (;;) {
        i++;
        tick(i);
        fflush(stdout);
        usleep(20000);   /* keep the counter small enough for deterministic tests */
    }
}
