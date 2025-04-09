#include <stdio.h>
#include <stdlib.h>

int main() {
    // 1. 创建一个虚拟网卡接口
    system("ip link add name tap0 type dummy");

    // 2. 启用接口
    system("ip link set tap0 up");

    // 3. 将接口的队列调度器设置为 taprio
    system("tc qdisc add dev tap0 root handle 1: taprio");

    // 4. 配置 taprio 调度器的属性
    system("tc qdisc change dev tap0 root handle 1: taprio "
           "num_tc 4 default 3 "
           "interval 1000 "
           "port 0 tc 1 rate 1000 "
           "port 1 tc 2 rate 1000 "
           "port 2 tc 3 rate 1000");

    // 5. 进行一些网络操作，以确保调度器配置生效并触发内核函数
    system("ping -c 1 127.0.0.1");

    // 6. 清理环境
    system("ip link set tap0 down");
    system("ip link delete tap0");

    return 0;
}