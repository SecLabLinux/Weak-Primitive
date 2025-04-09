#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/syscall.h>

int main() {
    const char *source = "/tmp/test_source"; // 原挂载源
    const char *target = "/tmp/test_target"; // 目标挂载点
    const char *filesystemtype = "tmpfs";    // 挂载类型
    unsigned long mountflags = MS_BIND;      // 绑定挂载
    void *data = NULL;

    // 创建源目录和目标目录
    if (mkdir(source, 0755) == -1) {
        perror("mkdir source failed");
        return 1;
    }
    if (mkdir(target, 0755) == -1) {
        perror("mkdir target failed");
        return 1;
    }

    // 执行挂载操作
    if (mount(source, target, filesystemtype, mountflags, data) == -1) {
        perror("mount failed");
        return 1;
    }

    // 使用 syscall 来执行 move_mount 系统调用
    // move_mount 的系统调用号是 438
    if (syscall(SYS_move_mount, source, target, target, filesystemtype, MS_MOVE, NULL) == -1) {
        perror("move_mount failed");
        return 1;
    }

    printf("Move mount operation successful\n");

    // 清理目录
    if (umount(target) == -1) {
        perror("umount failed");
    }

    rmdir(source);
    rmdir(target);

    return 0;
}