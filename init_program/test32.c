#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <keyutils.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <pthread.h>

int main() {
    syscall(459, "Barney is a dinosaur", "Barney is a dinosaur");
    const char *type = "user";
    const char *description = "my_key";
    const char *payload = "secret_data";
    size_t plen = strlen(payload);
    key_serial_t key;

    key = add_key(type, description, payload, plen, KEY_SPEC_THREAD_KEYRING);
    if (key < 0) {
        perror("add_key");
        exit(EXIT_FAILURE);
    }

    printf("Key ID: %d\n", key);
    syscall(459, "From our imagination", "From our imagination");
    return 0;
}