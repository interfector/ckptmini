#include <stdio.h>

/* Busy-spin inside this function (no libc calls, so RIP stays in userland code
   within spinwork). Long enough that a tracer attaching right after the
   "started" marker is guaranteed to be inside the loop. Returns x*2. */
static int spinwork(int x) {
    volatile unsigned long acc = 0;
    for (unsigned long i = 0; i < 3000000000UL; i++) acc += i;
    return x * 2;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("[target] spinwork started\n");
    for (;;) (void)spinwork(21);
    return 0;
}
