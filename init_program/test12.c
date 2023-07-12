#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>

#define PR_PAC_RESET_KEYS		54
# define PR_PAC_APIAKEY			(1UL << 0)
# define PR_PAC_APIBKEY			(1UL << 1)
# define PR_PAC_APDAKEY			(1UL << 2)
# define PR_PAC_APDBKEY			(1UL << 3)
# define PR_PAC_APGAKEY			(1UL << 4)

int main(int argc, char *argv[]) {
	setreuid (0, 0);
	int i = 0;
	while (1) {
		i++;
		printf("============Round %d===========\n", i);
		unsigned long aa, bb, cc;
		aa = 0x1234567;
		bb = 0x7654321;
		asm  volatile(
			"mov X28, %[xn]\n\t"
			"PACIA X28, %[xm]\n\t"
			"mov %[cc], X28\n\t"
			: [cc] "=r" (cc)
			: [xn] "r" (aa), [xm] "r" (bb)
		);
		printf("user acgi4epgosiv, %lx\n", cc);
		setreuid(0,0);
		prctl(PR_PAC_RESET_KEYS, PR_PAC_APIAKEY, 0, 0, 0);
		sleep(1);
	}
	return 0;
}
