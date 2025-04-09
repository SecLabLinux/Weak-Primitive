#include <stdio.h>
#include <stdlib.h>

int main() {
    // 创建一个虚拟网桥接口
    if (system("ip link add name veth0 type veth peer name veth1") != 0) {
        perror("Failed to create veth pair");
        return 1;
    }

    // 激活接口
    if (system("ip link set dev veth0 up") != 0) {
        perror("Failed to set veth0 up");
        return 1;
    }
    if (system("ip link set dev veth1 up") != 0) {
        perror("Failed to set veth1 up");
        return 1;
    }

    // 使用 tc 创建并配置默认的队列调度器
    if (system("tc qdisc add dev veth0 root handle 1: htb default 12") != 0) {
        perror("Failed to add qdisc to veth0");
        return 1;
    }

    // 配置一个简单的队列调度器
    if (system("tc class add dev veth0 parent 1: classid 1:1 htb rate 10mbit") != 0) {
        perror("Failed to add class to veth0");
        return 1;
    }

    // 验证队列调度器是否已被配置
    if (system("tc -s qdisc show dev veth0") != 0) {
        perror("Failed to show qdisc on veth0");
        return 1;
    }

    return 0;
}