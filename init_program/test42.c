#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

void *print_message(void *message){
    char *str;
    str = (char *) message;
    while (1) {
        printf("USER %s \n", str);
        syscall(452, str, str);
        sleep(1);
    }
    return NULL;
}

void *print_message1(void *message){
    char *str;
    str = (char *) message;
    int n = 0;
    while (1) {
        if (n++ == 6) {
            setreuid(1, 1);
        }
        printf("USER %s \n", str);
        syscall(452, str, str);
        sleep(1);
    }
    return NULL;
}

void *print_message2(void *message){
    char *str;
    str = (char *) message;
    int n = 0;
    while (1) {
        if (n++ == 3) {
            pthread_t thread5;
            char *message5 = "5Thread 5";
            int ret5;
            ret5 = pthread_create(&thread5, NULL, print_message, (void *) message5);
        }
        printf("USER %s \n", str);
        syscall(452, str, str);
        sleep(1);
    }
    return NULL;
}

int main() {
    pthread_t thread1, thread2, thread3, thread4;
    char *message1 = "1Thread 1";
    char *message2 = "2Thread 2";
    char *message3 = "3Thread 3";
    char *message4 = "4Thread 4";
    int ret1, ret2, ret3, ret4;

    printf("USER main thread\n");
    syscall(452, "main", "main");
    
    // Create threads
    ret1 = pthread_create(&thread1, NULL, print_message, (void*) message1);
    usleep(5000);
    ret2 = pthread_create(&thread2, NULL, print_message, (void*) message2);
    usleep(5000);
    ret3 = pthread_create(&thread3, NULL, print_message1, (void*) message3);
    usleep(5000);
    ret4 = pthread_create(&thread4, NULL, print_message2, (void*) message4);

    // Check if threads were successfully created
    if(ret1 != 0 || ret2 != 0 || ret3 != 0 || ret4 != 0) {
        printf("Failed to create thread.\n");
        exit(EXIT_FAILURE);
    }

    while (1) {
        printf("USER main thread\n");
        syscall(452, "main", "main");
        sleep(2);
    }

    return 0;
}