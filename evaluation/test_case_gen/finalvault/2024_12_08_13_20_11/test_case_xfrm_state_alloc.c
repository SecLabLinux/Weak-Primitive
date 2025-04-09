#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/ipsec.h>
#include <linux/netlink.h>
#include <linux/pfkeyv2.h>

#define PFKEY_VERSION 2
#define PFKEY_MSG_TIMEOUT 5

int main() {
    int sockfd;
    struct sockaddr_nl sa;
    struct sadb_msg msg;
    struct sadb_sa *sadb_sa;
    struct sadb_address *src, *dst;
    struct sockaddr_in src_addr, dst_addr;

    // 创建 PF_KEY 套接字
    sockfd = socket(AF_NETLINK, SOCK_RAW, PF_KEY);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();
    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        close(sockfd);
        return -1;
    }

    // 初始化 PF_KEY 消息
    memset(&msg, 0, sizeof(msg));
    msg.sadb_msg_version = PFKEY_VERSION;
    msg.sadb_msg_type = SADB_ADD;
    // 计算整个消息长度，包括sadb_msg和sadb_sa及地址扩展
    msg.sadb_msg_len = (sizeof(struct sadb_msg) + sizeof(struct sadb_sa) + 
                        sizeof(struct sadb_address) * 2) / 8;
    msg.sadb_msg_satype = SADB_SATYPE_AH; // 示例SA类型，可根据需要调整
    msg.sadb_msg_seq = 1;
    msg.sadb_msg_pid = getpid();

    // 配置 SA 信息
    sadb_sa = (struct sadb_sa *)((char *)&msg + sizeof(struct sadb_msg));
    sadb_sa->sadb_sa_len = sizeof(struct sadb_sa) / 8;
    sadb_sa->sadb_sa_exttype = SADB_EXT_SA;
    sadb_sa->sadb_sa_spi = 0xdeadbeef; // SPI
    sadb_sa->sadb_sa_replay = 0;
    sadb_sa->sadb_sa_state = SADB_SASTATE_MATURE;
    sadb_sa->sadb_sa_auth = SADB_AALG_NONE;
    sadb_sa->sadb_sa_encrypt = SADB_EALG_NONE;
    sadb_sa->sadb_sa_flags = 0;

    // 配置源地址
    src = (struct sadb_address *)((char *)sadb_sa + sizeof(struct sadb_sa));
    src->sadb_address_len = sizeof(struct sadb_address) / 8;
    src->sadb_address_exttype = SADB_EXT_ADDRESS_SRC;
    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.sin_family = AF_INET;
    src_addr.sin_addr.s_addr = inet_addr("192.168.1.1");
    memcpy(&src->sadb_address, &src_addr, sizeof(src_addr));

    // 配置目标地址
    dst = (struct sadb_address *)((char *)src + sizeof(struct sadb_address));
    dst->sadb_address_len = sizeof(struct sadb_address) / 8;
    dst->sadb_address_exttype = SADB_EXT_ADDRESS_DST;
    memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_addr.s_addr = inet_addr("192.168.1.2");
    memcpy(&dst->sadb_address, &dst_addr, sizeof(dst_addr));

    // 发送消息
    if (send(sockfd, &msg, sizeof(struct sadb_msg) + sizeof(struct sadb_sa) + 
             sizeof(struct sadb_address) * 2, 0) < 0) {
        perror("send");
        close(sockfd);
        return -1;
    }

    printf("PF_KEY message sent successfully\n");
    close(sockfd);
    return 0;
}