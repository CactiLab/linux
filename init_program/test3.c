#include <stdio.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
	while (1) {
		setreuid(0, 0);
		printf("UID: %d\n", getuid());
		sleep(1);
	}
	return 0;
}
