#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    printf("Start of the user program.\n");
    printf("USER PID = %d\n", getpid());
    int uid = getuid();
    printf("USER before artifical bug, uid=%d\n", uid);
	syscall(454, -1);
    char buf[] = {'\1', '\0', '\0', '\0'};
    syscall(457, 0xffff00000455ac04, buf, 4);
    uid = getuid();
    printf("USER after artifical bug, uid=%d\n", uid);
    printf("User program is entering infinite loop...");
    while(1) {

    }
    return 0;
}