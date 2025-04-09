#include <stdio.h>  
#include <fcntl.h>  
#include <unistd.h>  

int main() {
    // 创建一个文件并获取文件描述符
    int fd = open("/tmp/testfile.txt", O_CREAT | O_RDWR, 0666);
    if (fd == -1) {
        perror("Failed to open file");
        return 1;
    }

    // 使用 dup 复制文件描述符
    int new_fd = dup(fd);
    if (new_fd == -1) {
        perror("Failed to duplicate file descriptor");
        close(fd);
        return 1;
    }

    printf("Original fd: %d, New fd: %d\n", fd, new_fd);

    // 关闭文件描述符
    close(fd);
    close(new_fd);

    return 0;
}