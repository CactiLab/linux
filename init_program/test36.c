#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    int fd;
    char buffer[4096];  // buffer to hold file data
    ssize_t bytes_read;

    // Open the file for reading
    printf("before open syscall\n");
    fd = open("example.txt", O_RDONLY);
    printf("after open syscall\n");
    if (fd == -1) {
        perror("Failed to open file");
        return 1;
    }

    // Read the file contents and print them
    while ((bytes_read = read(fd, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytes_read] = '\0';  // Null-terminate the buffer
        printf("%s", buffer);
    }

    if (bytes_read == -1) {
        perror("Error reading file");
    }

    // Close the file
    close(fd);

    while (1);
    return 0;
}
