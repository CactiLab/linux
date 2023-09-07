#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

pthread_t thread1;

/**
 * What will happen to the child process if it calls `pthread_join`?
 * A joinable thread don't need to join the creator thread, it can join any other thread in the process. But they can't join other processes.
*/

void *t1(void *message){
    char *str;
    str = (char *) message;
    int n = 0;
    printf("USER Thread %s PID=%d\n", str, getpid());
    while (1) {
        n++;
	    syscall(459, message, message);
        sleep(1);
        if (n == 10)
            break;
    }
    printf("Thread %s, ends\n", str);
    return NULL;
}

void *t2(void *message) {
    printf("a PID=%d\n", getpid());
    int ret = pthread_join(thread1, NULL);
    printf("b %d\n", ret);
    printf("In thread2, after join\n");
    sleep(2);
    printf("c\n");
}

int main() {
    pthread_t thread2;
    char *message1 = "1Thread 1";
    char *message2 = "2Thread 2";
    int ret1, ret2;

    printf("Start of the user program.\n");

    // Create threads
    ret1 = pthread_create(&thread1, NULL, t1, (void*) message1);
    ret2 = pthread_create(&thread2, NULL, t2, (void*) message2);

    // pthread_detach(thread2);

    // Check if threads were successfully create
    if(ret1 != 0) {
        printf("Failed to create thread.\n");
        exit(1);
    }

    while(1) {
        printf("Hello\n");
        sleep(1);

    }

    // printf("After fork\n");

    // Wait for threads to finish
    // int join_res = pthread_join(thread2, NULL);

    // printf("after join PID=%d, join returns %d\n", getpid(), join_res);

    return 0;
}