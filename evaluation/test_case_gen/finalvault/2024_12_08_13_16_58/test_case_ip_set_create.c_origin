#include <stdio.h>
#include <stdlib.h>

int main() {
    // 调用 ipset 工具来创建一个 IP 集合
    // 这个命令会触发内核的 ip_set_create 函数
    int result = system("ipset create myset hash:ip");
    
    if (result == -1) {
        perror("system call failed");
        return 1;
    }

    printf("ipset create executed successfully\n");

    return 0;
}