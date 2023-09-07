#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>

void *print_message(void *message){
    char *str;
    str = (char *) message;
    printf("%s \n", str);
//    setreuid('0' - *str, '0' - *str);
    return NULL;
}

int main(){
    pthread_t thread1, thread2;
    char *message1 = "1Thread 1";
    char *message2 = "2Thread 2";
    int ret1, ret2;

    // Create threads
    ret1 = pthread_create(&thread1, NULL, print_message, (void*) message1);
    ret2 = pthread_create(&thread2, NULL, print_message, (void*) message2);

    // Check if threads were successfully created
    if(ret1 != 0 || ret2 != 0) {
        printf("Failed to create thread.\n");
        exit(EXIT_FAILURE);
    }

    // Wait for threads to finish
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    while (1);
    exit(EXIT_SUCCESS);
}

