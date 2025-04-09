#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    pid_t pid = fork();  // 创建子进程
    if (pid < 0) {
        // 错误处理
        perror("fork failed");
        return 1;
    }

    if (pid == 0) {
        // 子进程
        printf("Child process: %d\n", getpid());
    } else {
        // 父进程
        printf("Parent process: %d, Child PID: %d\n", getpid(), pid);
        wait(NULL);  // 等待子进程结束
    }

    return 0;
}