#include <stdio.h>
#include <unistd.h>

void __my_test(void) {
	printf("===Start of __my_test (user)===\n");
	unsigned long __xd, __xn, __xm;
	__xn = 0x12345689;
	__xm = 0xffffaaaa;
	printf("sizeof unsigned long = %lu\n", sizeof(__xd));
	printf("Before, xd=%lu, xn=%lu, xm=%lu\n", __xd, __xn, __xm);
	asm volatile(
//		"PACIASP\n\t"
		"PACGA %[out], %[val], %[context]\n\t"
		: [out] "=r" (__xd)
		: [val] "r" (__xn), [context] "r" (__xm)
		:
	);
	printf("After, xd=%lu, xn=%lu, xm=%lu\n", __xd, __xn, __xm);
	printf("===End of __my_test (user)===\n");
}

int main(int argc, char *argv[]) {
	__my_test();
	while (1) {
//		setreuid(0, 0);
		// printf("UID: %d\n", getuid());
	//	__my_test();
		pid_t pid;
		pid = fork();
		if (pid == 0) {
			__my_test();
			break;	
		}
		sleep(1);
	}
	return 0;
}
