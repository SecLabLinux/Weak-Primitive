#include <stdio.h>
#include <stdlib.h>
#include <libnfs.h>

int main() {
    struct nfs_context *nfs;
    struct nfs_fh *fh;
    int ret;

    // 初始化 NFS4 客户端
    nfs = nfs_init_context();
    if (nfs == NULL) {
        fprintf(stderr, "nfs_init_context failed\n");
        return EXIT_FAILURE;
    }

    // 连接到 NFS 服务器（假设服务器地址为 localhost，导出路径为 /export）
    if (!nfs_mount(nfs, "localhost", "/export")) {
        fprintf(stderr, "nfs_mount failed: %s\n", nfs_get_error(nfs));
        nfs_destroy_context(nfs);
        return EXIT_FAILURE;
    }

    // 获取文件句柄（假设文件路径为 /export/testfile）
    fh = nfs_getfh(nfs, "/testfile");
    if (fh == NULL) {
        fprintf(stderr, "nfs_getfh failed: %s\n", nfs_get_error(nfs));
        nfs_umount(nfs);
        nfs_destroy_context(nfs);
        return EXIT_FAILURE;
    }

    // 打开文件（发起一个锁定请求）
    ret = nfs_open(nfs, "/testfile", O_RDWR);
    if (ret < 0) {
        fprintf(stderr, "nfs_open failed: %s\n", nfs_get_error(nfs));
    } else {
        printf("NFS4 lock request successful.\n");
    }

    // 清理资源
    nfs_close(nfs, ret);
    nfs_umount(nfs);
    nfs_destroy_context(nfs);
    
    return EXIT_SUCCESS;
}