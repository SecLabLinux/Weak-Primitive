#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/ioctl.h>  
#include <net/if.h>  
#include <linux/if_arp.h>  // 修改为 linux/if_arp.h  
#include <linux/if_ether.h>  // 添加以太网头文件
#include <sys/socket.h>  
#include <arpa/inet.h>  

// 该测试用例触发 ARP 请求，间接引发调用栈中的 make_entry
int main() {  
    int sockfd;  
    struct ifreq ifr;  
    struct sockaddr_in dest_addr;  
    char packet[42];  

    // 创建原始套接字
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {  
        perror("Socket creation failed");  
        return 1;  
    }  

    // 获取网络接口信息
    memset(&ifr, 0, sizeof(ifr));  
    strncpy(ifr.ifr_name, "eth0", IFNAMSIZ - 1);  

    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {  
        perror("IOCTL failed");  
        close(sockfd);  
        return 1;  
    }  

    // 设置目的地址
    memset(&dest_addr, 0, sizeof(dest_addr));  
    dest_addr.sin_family = AF_INET;  
    dest_addr.sin_addr.s_addr = inet_addr("192.168.1.1");  

    // 填充 ARP 包头
    memset(packet, 0, sizeof(packet));  
    struct ethhdr *eth_hdr = (struct ethhdr *)packet;  
    eth_hdr->h_proto = htons(ETH_P_ARP);  

    // 发送 ARP 请求包
    if (sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {  
        perror("Send failed");  
        close(sockfd);  
        return 1;  
    }  

    printf("ARP request sent\n");  
    close(sockfd);  
    return 0;  
}