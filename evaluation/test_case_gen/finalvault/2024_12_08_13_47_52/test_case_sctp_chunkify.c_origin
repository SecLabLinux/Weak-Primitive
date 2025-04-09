#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/sctp.h>
#include <arpa/inet.h>
#include <unistd.h>

#define SERVER_ADDR "127.0.0.1"
#define SERVER_PORT 9899

int main() {
    int sockfd;
    struct sockaddr_in server_addr;
    struct sctp_sndrcvinfo sndrcv_info;
    struct sctp_initmsg initmsg;
    char buffer[1024] = "Hello, SCTP!";

    // 创建 SCTP 套接字
    sockfd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (sockfd < 0) {
        perror("socket creation failed");
        return 1;
    }

    // 配置目标服务器地址
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_ADDR, &server_addr.sin_addr);

    // 设置 SCTP 初始化选项
    memset(&initmsg, 0, sizeof(initmsg));
    initmsg.sinit_num_ostreams = 5;
    initmsg.sinit_max_instreams = 5;
    initmsg.sinit_max_attempts = 4;

    if (setsockopt(sockfd, SOL_SCTP, SCTP_INITMSG, &initmsg, sizeof(initmsg)) < 0) {
        perror("setsockopt SCTP_INITMSG failed");
        close(sockfd);
        return 1;
    }

    // 配置消息发送信息
    memset(&sndrcv_info, 0, sizeof(sndrcv_info));
    sndrcv_info.sinfo_stream = 0;
    sndrcv_info.sinfo_flags = SCTP_EOF;  // 发送结束标志

    // 发送 SCTP 数据包
    if (sctp_sendmsg(sockfd, buffer, strlen(buffer), (struct sockaddr *)&server_addr, sizeof(server_addr), 0, 0, sndrcv_info.sinfo_stream, 0, 0) < 0) {
        perror("sctp_sendmsg failed");
        close(sockfd);
        return 1;
    }

    printf("Message sent successfully.\n");

    // 关闭套接字
    close(sockfd);
    return 0;
}