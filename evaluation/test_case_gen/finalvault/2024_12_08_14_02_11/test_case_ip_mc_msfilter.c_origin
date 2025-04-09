#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <unistd.h>

int main() {
    int sock;
    struct ip_mreq mreq;
    struct sockaddr_in addr;

    // 创建一个 UDP 套接字
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    // 设置套接字地址结构
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(12345);

    // 将套接字绑定到指定端口
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        exit(1);
    }

    // 配置多播组，加入多播地址
    mreq.imr_multiaddr.s_addr = inet_addr("224.0.0.1"); // 多播地址
    mreq.imr_interface.s_addr = htonl(INADDR_ANY); // 使用默认网络接口

    // 使用 setsockopt 加入多播组
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt");
        close(sock);
        exit(1);
    }

    printf("Successfully added to multicast group 224.0.0.1\n");

    // 模拟一个长期运行的程序，以便让内核处理多播
    while (1) {
        sleep(10);
    }

    close(sock);
    return 0;
}