#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    printf("Start of the user program.\n");
	syscall(459, "Barney is a dinosaur", "barney");
    printf("User program is entering infinite loop...");
    while(1) {

    }
    return 0;
}