#include <stdio.h>
#include <unistd.h>

#define _GNU_SOURCE

int vulfoo(void) {
	printf("I pity the fool.\n");
}

int main(int argc, char *argv[]) {
	printf("Start of user program, pid=%d\n", getpid());
/*
	uid_t ruid, euid, suid;
	uid_t uid;
	uid = getuid();
	printf("User program: ruid: %d, euid: %d, suid: %d\n", ruid, euid, suid);
	printf("User program: uid: %d\n", uid);
	*/
	int r = setreuid(0, 0);
	printf("setreuid = %d\n", r);
	printf("getuid() = %d\n", getuid());
	pid_t pid = fork();
	if (pid < 0) {
		perror("fork");
		return 1;
	} else if (pid == 0) {
		// child
		printf("Continuing of user program (child), pid=%d\n", getpid());
		setreuid(-2, -2);
		char *av[] = {"./demo", NULL};
		execve(av[0], av, NULL);
	} else {
		// parent
		printf("Continuing of user program (parent), pid=%d\n", getpid());
		setreuid(-3, -3);
		while (1) {
			vulfoo();
			sleep(1);
		}
	}
	return 0;
}
