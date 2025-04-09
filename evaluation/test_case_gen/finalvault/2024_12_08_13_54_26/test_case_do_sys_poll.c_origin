#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/poll.h>

int main() {
    int pipefds[2];
    struct pollfd pfds[1];
    char buf[1];

    // 创建管道
    if (pipe(pipefds) == -1) {
        perror("pipe");
        return 1;
    }

    // 设置 pollfd 结构
    pfds[0].fd = pipefds[0];  // 监听管道的读端
    pfds[0].events = POLLIN;   // 等待可读事件

    // 创建子进程来模拟管道写入
    if (fork() == 0) {
        // 子进程，往管道写入数据
        close(pipefds[0]);  // 关闭读端
        write(pipefds[1], "a", 1);
        close(pipefds[1]);  // 关闭写端
        return 0;
    } else {
        // 父进程，使用 poll 来监听事件
        close(pipefds[1]);  // 关闭写端
        int ret = poll(pfds, 1, -1);  // 阻塞等待事件发生

        if (ret > 0) {
            if (pfds[0].revents & POLLIN) {
                // 数据可读
                read(pipefds[0], buf, 1);
                printf("Received data: %c\n", buf[0]);
            }
        } else {
            perror("poll");
        }
        close(pipefds[0]);  // 关闭读端
    }

    return 0;
}