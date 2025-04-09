#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>  // 包含 mkdir 函数定义

int main() {
    const char *nfs_server = "192.168.1.100:/nfs_share";  // NFS 服务器地址
    const char *mount_point = "/mnt/nfs";  // 挂载点

    // 创建挂载点目录
    if (mkdir(mount_point, 0777) == -1) {
        perror("mkdir");
        return 1;
    }

    // 执行挂载操作，模拟 NFS 客户端的挂载过程
    if (mount(nfs_server, mount_point, "nfs", 0, NULL) == -1) {
        perror("mount");
        return 1;
    }

    printf("NFS mount successful. Triggered RPC client creation.\n");

    // 卸载操作，模拟卸载 NFS 文件系统
    if (umount(mount_point) == -1) {
        perror("umount");
        return 1;
    }

    printf("NFS umount successful.\n");

    return 0;
}