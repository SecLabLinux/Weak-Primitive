#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/pfkeyv2.h>
#include <arpa/inet.h>
#include <netinet/in.h>

int main() {
    int sock, ret;
    struct sadb_msg msg;
    struct sadb_sa sa;
    struct sockaddr_in sa_local, sa_remote;

    // 创建 PF_KEY 套接字
    sock = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if (sock < 0) {
        perror("socket failed");
        return 1;
    }

    // 初始化消息结构体
    memset(&msg, 0, sizeof(msg));
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_ADD;
    msg.sadb_msg_len = sizeof(msg) / 8 + sizeof(sa) / 8;
    msg.sadb_msg_satype = SADB_X_CFG_DFLT;
    msg.sadb_msg_seq = 1;
    msg.sadb_msg_pid = getpid();

    // 初始化安全关联
    memset(&sa, 0, sizeof(sa));
    sa.sadb_sa_len = sizeof(sa) / 8;
    sa.sadb_sa_spi = htonl(0x10001);  // 设置 SPI
    sa.sadb_sa_auth = SADB_AH_ALG_HMAC_SHA1;
    sa.sadb_sa_encrypt = SADB_EALG_NULL;

    // 配置源和目的地址
    memset(&sa_local, 0, sizeof(sa_local));
    sa_local.sin_family = AF_INET;
    sa_local.sin_port = 0;
    sa_local.sin_addr.s_addr = inet_addr("192.168.0.1");

    memset(&sa_remote, 0, sizeof(sa_remote));
    sa_remote.sin_family = AF_INET;
    sa_remote.sin_port = 0;
    sa_remote.sin_addr.s_addr = inet_addr("192.168.0.2");

    // 发送 PF_KEY 消息
    ret = send(sock, &msg, sizeof(msg), 0);
    if (ret < 0) {
        perror("send failed");
        close(sock);
        return 1;
    }

    ret = send(sock, &sa, sizeof(sa), 0);
    if (ret < 0) {
        perror("send failed");
        close(sock);
        return 1;
    }

    // 关闭套接字
    close(sock);
    printf("PF_KEY message sent\n");

    return 0;
}