#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
	printf("Starting of user program\n");
	setreuid(7, 7);
	printf("Entering infinite loop...\n");
	while(1);
	return 0;
}
