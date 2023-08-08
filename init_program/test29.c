#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

/**
 * What will happen to the child process if it calls `pthread_join`?
 * Nothing, the thread cannot join to the child process.
*/

void *print_message(void *message){
    char *str;
    str = (char *) message;
    int n = 0;
    printf("USER Thread %s \n", str);
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

int main() {
    pthread_t thread1, thread2;
    char *message1 = "1Thread 1";
    char *message2 = "2Thread 2";
    int ret1, ret2;

    printf("Start of the user program.\n");

    // Create threads
    ret1 = pthread_create(&thread1, NULL, print_message, (void*) message1);

    // Check if threads were successfully create
    if(ret1 != 0) {
        printf("Failed to create thread.\n");
        exit(1);
    }

    sleep(2);
    pid_t pid = fork();
    if (pid < 0) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		// child
		printf("Continuing of user program (child), pid=%d\n", getpid());
        syscall(459, "child", "child");
	} else {
		// parent
		printf("Continuing of user program (parent), pid=%d\n", getpid());
        syscall(459, "parent", "parent");
	}

    printf("After fork\n");

    // Wait for threads to finish
    int join_res = pthread_join(thread1, NULL);

    printf("after join PID=%d, join returns %d\n", getpid(), join_res);

    return 0;
}