#include <stdio.h>
#include <unistd.h>
#include <sys/prctl.h>

#define PR_PAC_RESET_KEYS 54
# define PR_PAC_APGAKEY (1UL << 4)

int main() {
	printf("Starting of user program\n");
	setreuid(0, 0);
	prctl(PR_PAC_SET_ENABLED_KEYS, PR_PAC_APGAKEY, 0, 0, 0);
	prctl(PR_PAC_RESET_KEYS, PR_PAC_APGAKEY, 0, 0, 0);
	prctl(PR_PAC_RESET_KEYS, PR_PAC_APIAKEY, 0, 0, 0);
	setreuid(0, 0);
	printf("User program entering infinite loop...\n");
	while (1) {
		;
	}
	return 0;
}
