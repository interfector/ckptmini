#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>

int global_var = 42;

/* A simple function to test remote calls with arguments */
int add_numbers(int a, int b) {
    printf("[target] add_numbers called with %d and %d\n", a, b);
    return a + b;
}

/* A nested function to test backtracing */
void deep_function(int depth) {
    if (depth > 0) {
        deep_function(depth - 1);
    } else {
        printf("[target] Deep function reached. PID: %d. Waiting...\n", getpid());
        while (1) {
            sleep(1);
            printf("[target] loop... global_var=%d\n", global_var);
        }
    }
}

int main() {
    /* Disable buffering for immediate feedback in logs */
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("[target] Starting test_features. PID: %d\n", getpid());
    printf("[target] add_numbers is at %p\n", (void*)add_numbers);
    printf("[target] global_var is at %p\n", (void*)&global_var);
    
    deep_function(5);
    
    return 0;
}
