#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <sys/socket.h>  
#include <sys/ioctl.h>  
#include <unistd.h>  
#include <bluetooth/bluetooth.h>  
#include <bluetooth/rfcomm.h>  

#define RFCOMM_IOCTL_CMD 0x80045559  // RFCOMM相关IOCTL命令（假设一个可能的命令）

int main() {  
    int sock;  
    struct sockaddr_rc addr = { 0 };  

    // 创建一个 RFCOMM 套接字  
    sock = socket(AF_BLUETOOTH, SOCK_STREAM, BTPROTO_RFCOMM);  
    if (sock < 0) {  
        perror("Socket creation failed");  
        return -1;  
    }

    // 设置 RFCOMM 地址  
    addr.rc_family = AF_BLUETOOTH;  
    str2ba("00:11:22:33:44:55", &addr.rc_bdaddr);  // 用合适的设备地址

    // 连接到远程 RFCOMM 设备  
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {  
        perror("Connection failed");  
        close(sock);  
        return -1;  
    }

    // 发送 IOCTL 命令来触发内核的 __rfcomm_dev_add 调用  
    if (ioctl(sock, RFCOMM_IOCTL_CMD) < 0) {  
        perror("IOCTL failed");  
        close(sock);  
        return -1;  
    }

    printf("RFCOMM device added successfully\n");

    // 关闭套接字  
    close(sock);  
    return 0;  
}