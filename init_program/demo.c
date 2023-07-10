#include <stdio.h>
#include <unistd.h>

int main() {
	printf("This is demo program.");
	printf("Demo program pid=%d\n", getpid());
	setreuid(-1, 0);
	return 0;
}
