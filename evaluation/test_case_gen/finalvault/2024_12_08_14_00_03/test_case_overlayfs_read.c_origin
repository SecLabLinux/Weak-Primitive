#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

int main() {
    // 确保文件在 OverlayFS 文件系统上
    const char *file_path = "/mnt/overlayfs/test_file.txt";
    
    // 打开文件
    int fd = open(file_path, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open file");
        return 1;
    }

    // 读取文件
    char buffer[256];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer));
    if (bytes_read == -1) {
        perror("Failed to read file");
        close(fd);
        return 1;
    }

    // 打印读取内容
    printf("Read %ld bytes from file: %.*s\n", bytes_read, (int)bytes_read, buffer);

    // 关闭文件
    close(fd);
    
    return 0;
}