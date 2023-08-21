#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    printf("===============USER PROGRAM\n");
    syscall(459, "Barney is a dinosaur", "Barney is a dinosaur");
    syscall(462, -100);
    syscall(459, "from our imimagination", "from our imimagination");
    printf("===============USER PROGRAM\n");
    // getuid();
    while (1);
}