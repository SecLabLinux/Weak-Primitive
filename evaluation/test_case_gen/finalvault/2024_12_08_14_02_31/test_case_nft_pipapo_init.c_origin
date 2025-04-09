#include <stdio.h>
#include <stdlib.h>

int main() {
    // 创建一个 nftables 表
    system("nft add table inet test_table");
    
    // 创建一个链
    system("nft add chain inet test_table test_chain { type filter hook input priority 0; }");

    // 创建一个规则
    system("nft add rule inet test_table test_chain ip saddr 192.168.1.1 accept");

    // 进行一些操作，以触发内核中的初始化
    printf("nftables configuration completed, triggering nft_pipapo_init...\n");

    return 0;
}