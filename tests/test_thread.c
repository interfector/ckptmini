#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>

void* thread_func(void* arg) {
    int id = *(int*)arg;
    int i = 0;
    printf("Thread %d running\n", id);
    fflush(stdout);
    while (1) {
        printf("T#%d: %d\n", id, i++);
	   sleep(1);
    }
    return NULL;
}

int main() {
    pthread_t t1, t2, t3;
    int id1 = 1, id2 = 2, id3 = 3;
    
    printf("Main thread starting (PID: %d, TID: %lu)\n", getpid(), (unsigned long)pthread_self());
    printf("Creating 3 worker threads...\n");
    fflush(stdout);
    
    pthread_create(&t1, NULL, thread_func, &id1);
    pthread_create(&t2, NULL, thread_func, &id2);
    pthread_create(&t3, NULL, thread_func, &id3);
    
    printf("All threads created, entering main loop\n");
    fflush(stdout);
    
    while (1) {
        sleep(1);
    }
    
    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
    
    return 0;
}
