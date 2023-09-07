#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>


void *pm1(void *message) {
    sleep(5);
    setreuid(-2, -2);
    while (1) {
        sleep(1);
        getuid();
    }
}

void *pm2(void *message) {
    while(1) {
        syscall(459, message);
        sleep(1);
    }
}


int main() {
    getuid();
    setreuid(1, 1);
    getgid();

    pthread_t thread1, thread2;
    char *message1 = "1Thread 1";
    char *message2 = "2Thread 2";
    int ret1, ret2;

    // Create threads
    ret1 = pthread_create(&thread1, NULL, pm1, (void*) message1);
    ret2 = pthread_create(&thread2, NULL, pm2, (void*) message2);

    // Check if threads were successfully create
    if(ret1 != 0 || ret2 != 0) {
        printf("Failed to create thread.\n");
        exit(1);
    }

    sleep(10);
    pid_t pid = fork();
    if (pid < 0) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		// child
		printf("Continuing of user program (child), pid=%d\n", getpid());
        seteuid(-8);
        int n = 0;
        while (1) {
            n++;
            if (n == 5) {
                break;
            }
            getuid();
	        syscall(459, "child", "child");
            sleep(2);
        }
        char *av[] = {"./demo", NULL};
		execve(av[0], av, NULL);
	} else {
		// parent
		printf("Continuing of user program (parent), pid=%d\n", getpid());
        seteuid(-6);
		while (1) {
            getgid();
	        syscall(459, "parent", "parent");
            sleep(2);
		}
	}

    // Wait for threads to finish
    pthread_join(thread1, NULL);
    pthread_join(thread2, NULL);

    while(1) {
        sleep(2);
        printf("Hello\n");
    }
}