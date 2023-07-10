#include <stdio.h>
#include <unistd.h>

static void my_print_keys(char *symbol) {
	// GL
	__uint64_t register_value;
	printf("=================keys=================%s\n", symbol);
	asm volatile ("mrs %0, APGAKeyHi_EL1" : "=r" (register_value));
	printf("APGAKEYHI_EL1 = %lx\n", register_value);
	asm volatile ("mrs %0, APGAKeyLo_EL1" : "=r" (register_value));
	printf("APGAKEYLO_EL1 = %lx\n", register_value);

	asm volatile ("mrs %0, APIAKeyHi_EL1" : "=r" (register_value));
	printf("APIAKEYHI_EL1 = %lx\n", register_value);
	asm volatile ("mrs %0, APIAKeyLo_EL1" : "=r" (register_value));
	printf("APIAKEYLO_EL1 = %lx\n", register_value);
	asm volatile ("mrs %0, APIBKeyHi_EL1" : "=r" (register_value));
	printf("APIBKEYHI_EL1 = %lx\n", register_value);
	asm volatile ("mrs %0, APIBKeyLo_EL1" : "=r" (register_value));
	printf("APIBKEYLO_EL1 = %lx\n", register_value);

	asm volatile ("mrs %0, APDAKeyHi_EL1" : "=r" (register_value));
	printf("APDAKEYHI_EL1 = %lx\n", register_value);
	asm volatile ("mrs %0, APDAKeyLo_EL1" : "=r" (register_value));
	printf("APDAKEYLO_EL1 = %lx\n", register_value);
	asm volatile ("mrs %0, APDBKeyHi_EL1" : "=r" (register_value));
	printf("APDBKEYHI_EL1 = %lx\n", register_value);
	asm volatile ("mrs %0, APDBKeyLo_EL1" : "=r" (register_value));
	printf("APDBKEYLO_EL1 = %lx\n", register_value);
	printf("=================----=================\n");
	//-----
}

void __my_test(void) {
	printf("Start of __my_test\n");
	unsigned long __xd, __xn, __xm;
	__xn = 0x12345689;
	__xm = 0xffffaaaa;
	printf("sizeof unsigned long = %lx\n", sizeof(__xd));
	printf("Before, xd=%lx, xn=%lx, xm=%lx\n", __xd, __xn, __xm);
	asm volatile(
		// "PACIASP\n\t"
		"PACGA %[out], %[val], %[context]\n\t"
		: [out] "=r" (__xd)
		: [val] "r" (__xn), [context] "r" (__xm)
		:
	);
	printf("After, xd=%lx, xn=%lx, xm=%lx\n", __xd, __xn, __xm);
	printf("End of __my_test\n");
}

int main() {
    // my_print_keys("User");
    __my_test();
    setreuid(0, 0);
    // my_print_keys("User2");
    __my_test();
    while (1);
    return 0;
}