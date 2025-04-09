#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ipset/ipset.h>

int main() {
    struct ipset *set;
    struct ipset_create_param create_param;
    int ret;

    // 初始化 IP set 创建参数
    memset(&create_param, 0, sizeof(create_param));
    create_param.type = IPSET_HASH_IP;
    create_param.size = 1024;
    strcpy(create_param.name, "test_ipset");

    // 创建 IP set
    ret = ipset_create(&set, &create_param);
    if (ret != 0) {
        fprintf(stderr, "Failed to create IP set\n");
        return 1;
    }

    printf("IP set created successfully\n");

    // 释放资源
    ipset_destroy(set);

    return 0;
}