#include <stdio.h>
#include <unistd.h>

/* A static function: only visible in .symtab, not .dynsym, so it is
   unresolvable via dlsym and exercises ftrace's static-symbol fallback. */
static int static_add(int a, int b) {
    return a + b;
}

int main(void) {
    /* Disable buffering for immediate feedback in logs */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[target] Starting test_static. PID: %d\n", getpid());

    for (;;) {
        printf("[target] static_add=%d\n", static_add(2, 3));
        sleep(1);
    }

    return 0;
}
