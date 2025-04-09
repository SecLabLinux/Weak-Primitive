#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <string.h>

int main() {
    const char *filename = "/tmp/testfile";
    const char *acl_name = "user.test_acl";
    const char *acl_value = "sample_acl_data"; // 模拟一个简单的 ACL 数据
    ssize_t ret;

    // 创建文件
    FILE *file = fopen(filename, "w");
    if (!file) {
        perror("Failed to create file");
        return 1;
    }
    fclose(file);

    // 设置 ACL
    ret = setxattr(filename, acl_name, acl_value, strlen(acl_value) + 1, 0);
    if (ret == -1) {
        perror("Failed to setxattr");
        return 1;
    }

    printf("ACL successfully set on %s\n", filename);

    return 0;
}