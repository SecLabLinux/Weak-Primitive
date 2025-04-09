#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKET_PATH "\0test_socket"  // 使用抽象地址，前面加 '\0'

int main() {
    int sockfd;
    struct sockaddr_un addr;

    // 创建 UNIX 域套接字
    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    // 配置套接字地址
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) - 1);  // 使用抽象地址

    // 绑定套接字
    if (bind(sockfd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    printf("Socket bound to %s\n", SOCKET_PATH);

    // 关闭套接字
    close(sockfd);
    return 0;
}