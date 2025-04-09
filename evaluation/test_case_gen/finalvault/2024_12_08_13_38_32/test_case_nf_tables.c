#include <stdio.h>
#include <stdlib.h>

int main() {
    // 使用 system 调用创建一个新的 netfilter 表和集合，触发 nf_tables_newset 函数
    printf("Creating a new netfilter table and set...\n");

    // 创建新的 nf_tables 表
    system("iptables -t raw -N my_raw_table");

    // 创建新的集合（假设有支持的命令来操作集合）
    system("iptables -t raw -A my_raw_table -m set --match-set my_set src");

    printf("Netfilter table and set created.\n");

    return 0;
}