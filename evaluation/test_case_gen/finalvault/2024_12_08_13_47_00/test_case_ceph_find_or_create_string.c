#include <stdio.h>  
#include <stdlib.h>  
#include <fcntl.h>  
#include <dirent.h>  
#include <unistd.h>  
#include <string.h>  

#define TEST_DIR "/tmp/test_ceph_dir"
#define TEST_FILE "/tmp/test_ceph_dir/test_file"

void create_test_dir_and_file() {
    // 创建目录
    if (mkdir(TEST_DIR, 0755) == -1) {
        perror("mkdir failed");
        exit(EXIT_FAILURE);
    }

    // 创建文件
    int fd = open(TEST_FILE, O_CREAT | O_RDWR, 0644);
    if (fd == -1) {
        perror("open failed");
        exit(EXIT_FAILURE);
    }
    close(fd);
}

void read_directory() {
    DIR *dir = opendir(TEST_DIR);
    if (dir == NULL) {
        perror("opendir failed");
        exit(EXIT_FAILURE);
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        // 输出目录项
        printf("Found file: %s\n", entry->d_name);
    }

    closedir(dir);
}

void open_file_atomic() {
    int fd = open(TEST_FILE, O_RDONLY);
    if (fd == -1) {
        perror("open failed");
        exit(EXIT_FAILURE);
    }
    close(fd);
}

int main() {
    // 创建测试目录和文件
    create_test_dir_and_file();
    
    // 执行读取目录操作，触发相关内核函数
    read_directory();

    // 执行文件原子打开操作
    open_file_atomic();

    printf("Test completed successfully.\n");
    return 0;
}