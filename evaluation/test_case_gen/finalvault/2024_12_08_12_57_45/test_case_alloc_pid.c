#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>  // 添加 wait 的头文件

int main() {
    pid_t pid;

    // 创建子进程
    pid = fork();

    if (pid == -1) {
        // fork 失败
        perror("fork failed");
        exit(1);
    } else if (pid == 0) {
        // 子进程
        printf("This is the child process.\n");
        exit(0);  // 子进程结束
    } else {
        // 父进程
        printf("This is the parent process, child PID: %d\n", pid);
        wait(NULL);  // 等待子进程结束
    }

    return 0;
}