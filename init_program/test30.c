#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

// This is the function that will be executed in the new thread.
void* myThreadFunc(void *arg)
{
    printf("Inside the thread\n");
    return NULL;
}

int main()
{
    pthread_t threadId;

    // Create a new thread. The new thread will run the myThreadFunc.
    if (pthread_create(&threadId, NULL, myThreadFunc, NULL)) {
        printf("Error creating thread\n");
        return 1;
    }

    // Wait for the thread to finish.
    if (pthread_join(threadId, NULL)) {
        printf("Error joining thread\n");
        return 2;
    }

    printf("After the thread\n");
    return 0;
}
