#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    // 创建一个 TC 过滤器命令
    const char *tc_command = "tc qdisc add dev eth0 root handle 1: htb default 12";
    const char *filter_command = "tc filter add dev eth0 parent 1: protocol ip prio 1 u32 match ip dst 192.168.0.1 flowid 1:1";

    // 执行创建过滤器的命令
    if (system(tc_command) == -1) {
        perror("Failed to create qdisc");
        return 1;
    }

    if (system(filter_command) == -1) {
        perror("Failed to add filter");
        return 1;
    }

    printf("Traffic control filter successfully created and applied.\n");

    return 0;
}