#include <stdio.h>
#include <unistd.h>

int main() {
	printf("Starting of user program");
	setreuid(0, 0);
	int a = 0;
	printf("user &a = %lx\n", &a);
	printf("User program is entering infinite loop...");
	while (1) {
		printf("Hello!\n");
		sleep(1);
	}
	return 0;
}
