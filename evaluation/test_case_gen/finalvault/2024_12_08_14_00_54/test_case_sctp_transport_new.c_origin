#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/sctp.h>

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct sctp_initmsg initmsg;

    // 创建 SCTP 套接字
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    // 配置 server 地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(36412);  // 示例端口
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // 设置 SCTP 初始化参数
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = 5;
    initmsg.sinit_max_instreams = 5;
    initmsg.sinit_max_attempts = 4;

    // 将 SCTP 初始化信息传递给套接字
    if (setsockopt(sockfd, IPPROTO_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0) {
        perror("setsockopt SCTP_INITMSG");
        close(sockfd);
        return -1;
    }

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(sockfd);
        return -1;
    }

    printf("SCTP connection established, triggering sctp_transport_new.\n");

    // 在此可以发送/接收数据来进一步触发相关的内核路径

    // 关闭套接字
    close(sockfd);

    return 0;
}