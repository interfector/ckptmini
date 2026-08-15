#include <stdio.h>

/* Busy-spin in a frameless leaf (compiled at -O2, so no "push rbp" frame
   pointer) whose caller main keeps a frame pointer.  The tracer attaches while
   hotloop is mid-loop and finish must step out of THIS frame, not the caller's.
   Returns sum(0..n-1), deterministic per call. */
static volatile unsigned long g_iters = 1000000000UL;

__attribute__((noinline)) static unsigned long hotloop(unsigned long n) {
    volatile unsigned long acc = 0;
    for (unsigned long i = 0; i < n; i++) acc += i;
    return acc;
}

__attribute__((optimize("no-omit-frame-pointer"))) int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[target] leaf spin started\n");
    unsigned long acc = 0;
    for (;;) acc += hotloop(g_iters);
    return (int)acc;
}
