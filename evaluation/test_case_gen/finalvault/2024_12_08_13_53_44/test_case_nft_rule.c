#include <stdio.h>
#include <stdlib.h>

int main() {
    // 使用系统命令 nft 创建一个新的过滤规则
    // 这里使用简单的命令创建一个允许所有流量通过的规则
    printf("Creating nf_tables rule...\n");

    // 创建一个表（若不存在），然后创建一个链
    system("nft add table inet filter");
    system("nft add chain inet filter input { type filter hook input priority 0 \; }");

    // 创建规则：允许所有流量通过
    system("nft add rule inet filter input accept");

    printf("nf_tables rule created successfully!\n");

    return 0;
}