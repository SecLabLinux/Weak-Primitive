#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>

int main() {
    const char *path = "/mnt/ceph/testfile";  // 假设文件在 Ceph 文件系统挂载点上
    char list[1024];
    ssize_t len;

    // 列出指定文件的所有扩展属性
    len = listxattr(path, list, sizeof(list));
    if (len == -1) {
        perror("listxattr failed");
        return 1;
    }

    // 打印所有扩展属性名称
    printf("Extended attributes of %s:\n", path);
    for (ssize_t i = 0; i < len; i += strlen(&list[i]) + 1) {
        printf("%s\n", &list[i]);
    }

    return 0;
}