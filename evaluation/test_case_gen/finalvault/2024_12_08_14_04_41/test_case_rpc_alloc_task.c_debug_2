#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <nfs/nfs4.h>
#include <nfs/nfs.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <server> <file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *server = argv[1];
    const char *filename = argv[2];

    // 创建 NFS 客户端
    struct nfs_client *clnt;
    clnt = nfs_client_create(server, 2049, 0, 0);
    if (clnt == NULL) {
        perror("Failed to create NFS client");
        exit(EXIT_FAILURE);
    }

    // 打开文件
    nfsfh4 file_handle;
    int result = nfs4_open(clnt, filename, O_RDONLY, &file_handle);
    if (result != 0) {
        fprintf(stderr, "Failed to open file: %s\n", filename);
        nfs_client_destroy(clnt);
        exit(EXIT_FAILURE);
    }

    printf("File %s opened successfully\n", filename);

    // 进行简单的读取操作
    char buffer[1024];
    result = nfs4_read(clnt, &file_handle, 0, 1024, buffer);
    if (result < 0) {
        fprintf(stderr, "Failed to read from file\n");
        nfs4_close(clnt, &file_handle);
        nfs_client_destroy(clnt);
        exit(EXIT_FAILURE);
    }

    printf("Read %d bytes from file\n", result);

    // 关闭文件
    nfs4_close(clnt, &file_handle);

    // 销毁客户端
    nfs_client_destroy(clnt);

    return 0;
}