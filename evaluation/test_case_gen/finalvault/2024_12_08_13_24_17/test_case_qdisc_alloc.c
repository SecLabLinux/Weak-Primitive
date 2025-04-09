#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    // Step 1: 创建一个虚拟网络接口
    system("ip link add name test0 type veth peer name test1");

    // Step 2: 启动网络接口
    system("ip link set dev test0 up");
    system("ip link set dev test1 up");

    // Step 3: 创建一个 HTB Qdisc
    system("tc qdisc add dev test0 root handle 1: htb default 12");

    // Step 4: 修改 Qdisc，触发 qdisc_alloc
    system("tc qdisc change dev test0 root handle 1: htb default 12");

    // Step 5: 清理资源
    system("ip link set dev test0 down");
    system("ip link set dev test1 down");
    system("ip link delete test0");
    system("ip link delete test1");

    return 0;
}