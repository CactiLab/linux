#include <stdio.h>
#include <unistd.h>

int main() {
	printf("Start of the user program\n");
	setuid(1);
	printf("Entering loop\n");
	while (1) {
	}
	return 0;
}
