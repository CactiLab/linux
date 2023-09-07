#include <stdio.h>
#include <unistd.h>

#define _GNU_SOURCE

int vulfoo(void) {
	printf("I pity the fool.\n");
}

int main(int argc, char *argv[]) {
	printf("Start of user program, pid=%d\n", getpid());
	setreuid(0, 0);
	uid_t ruid, euid, suid;
	getresuid(&ruid, &euid, &suid);
	printf("User program: ruid: %d, euid: %d, suid: %d\n", ruid, euid, suid);
	while (1) {
		vulfoo();
		sleep(1);
	}
	return 0;
}
