#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
	printf("Starting of the user program.\n");
	syscall(452);
	printf("User program is entering into infinte loop...\n");
	while (1) {
	}
	return 0;
}
