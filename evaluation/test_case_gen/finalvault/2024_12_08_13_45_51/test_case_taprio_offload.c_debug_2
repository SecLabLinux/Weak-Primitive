#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>  // 添加头文件，定义 open 和 O_RDWR

#define TAPIRO_ENABLE_OFFLOAD 1
#define TAPIRO_DISABLE_OFFLOAD 0

// 模拟 ioctl 命令触发
int toggle_taprio_offload(int enable) {
    int fd = open("/dev/net/tap", O_RDWR);
    if (fd == -1) {
        perror("open");
        return -1;
    }

    // 模拟调用 ioctl 进行 offload 配置
    int ret = ioctl(fd, enable ? TAPIRO_ENABLE_OFFLOAD : TAPIRO_DISABLE_OFFLOAD);
    if (ret == -1) {
        perror("ioctl");
    }

    close(fd);
    return ret;
}

int main() {
    printf("Testing Taprio offload allocation...\n");

    // 启用 Taprio offload
    if (toggle_taprio_offload(1) == -1) {
        return -1;
    }

    // 禁用 Taprio offload
    if (toggle_taprio_offload(0) == -1) {
        return -1;
    }

    printf("Test completed.\n");
    return 0;
}