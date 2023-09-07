#include <stdio.h>
#include <unistd.h>

void vulfoo(void) {
	printf("volfoo\n");
}

void f1() {
	printf("f1\n");
}

int main() {
	printf("1\n");
	vulfoo();
	void (*p) (void) = f1;
	(*p)();
	int a = 1;
	if (a == 2) {
		printf("2\n");
	} else {
		f1();
	}
	return 0;
}
