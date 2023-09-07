#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
	syscall(460, "awfjewiofjowoifj");
	while(1) {
		printf("hello");
		sleep(1);
	}
	return 0;
}
