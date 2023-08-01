#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

void *print_message(void *message){
    char *str;
    str = (char *) message;
    int n = 0;
    printf("USER Thread %s \n", str);
    while (1) {
        n++;
	    syscall(459, message, message);
        if (n == 5 && *str  == '2') {
            pid_t pid = fork();
            if (pid < 0) {
                perror("fork");
                return NULL;
            } else if (pid == 0) {
                // child
                printf("Continuing of user program (child), pid=%d\n", getpid());
                while (1) {
                    syscall(459, "child", "child");
                    sleep(2);
                }
            } else {
                // parent
                printf("Continuing of user program (parent), pid=%d\n", getpid());
                while (1) {
                    syscall(459, "parent", "parent");
                    sleep(2);
                }
            }
        }
        sleep(1);
    }

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
    ret2 = pthread_create(&thread2, NULL, print_message, (void*) message2);

    // Check if threads were successfully create
    if(ret1 != 0 || ret2 != 0) {
        printf("Failed to create thread.\n");
        exit(1);
    }

    while (1) {
        /* code */
    }
    

    // Wait for threads to finish
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    return 0;
}