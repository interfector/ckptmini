#include <stdio.h>
#include <unistd.h>

/* Busy-spin inside this function (no libc calls, so RIP stays in userland code
   within spinwork). Long enough that a tracer attaching right after the
   "started" marker is guaranteed to be inside the loop. Returns x*2. */
static int spinwork(int x) {
    printf("[target] spinwork started\n");
    volatile unsigned long acc = 0;
    for (unsigned long i = 0; i < 3000000000UL; i++) acc += i;
    return x * 2;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    for (;;) {
        int r = spinwork(21);
        printf("[target] spinwork=%d\n", r);
        sleep(2);
    }
    return 0;
}
