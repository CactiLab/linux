#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

/**
 * What if one thread intends to change cred
 * how other threads will be affected
*/

void *print_message(void *message){
    char *str;
    str = (char *) message;
    while (1) {
        printf("USER %s \n", str);
        syscall(459, str, str);
        sleep(1);
    }
    return NULL;
}

void *print_message1(void *message){
    sleep(2);
    char *str;
    str = (char *) message;
    int n = 0;
    // setreuid(-4, -4);
    syscall(145, -4, -4);
    // syscall(461);
    return NULL;
}

int main(){
    pthread_t thread1, thread2, thread3, thread4;
    char *message1 = "1Thread 1";
    char *message2 = "2Thread 2";
    char *message3 = "3Thread 3";
    char *message4 = "4Thread 4";
    int ret1, ret2, ret3, ret4;

    // Create threads
    ret1 = pthread_create(&thread1, NULL, print_message, (void*) message1);
    ret2 = pthread_create(&thread2, NULL, print_message1, (void*) message2);
    ret3 = pthread_create(&thread3, NULL, print_message, (void*) message3);
    ret4 = pthread_create(&thread4, NULL, print_message, (void*) message4);

    // Check if threads were successfully created
    if(ret1 != 0 || ret2 != 0 || ret3 != 0 || ret4 != 0) {
        printf("Failed to create thread.\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        sleep(2);
        printf("USER main thread\n");
        syscall(459, "main", "main");
    }

    // Wait for threads to finish
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);
    pthread_join(thread3, NULL);
    pthread_join(thread4, NULL);

    while (1);
    exit(EXIT_SUCCESS);
}

