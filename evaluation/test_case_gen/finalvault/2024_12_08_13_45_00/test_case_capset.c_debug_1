#include <stdio.h>
#include <sys/capability.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/securebits.h>
#include <sys/syscall.h>

#define _GNU_SOURCE

// 结构体用于设置新的能力集
struct __user_cap_header_struct header;
struct __user_cap_data_struct data[2];

int main() {
    // 初始化capset header和数据结构
    header.pid = getpid();  // 设置为当前进程
    header.version = _LINUX_CAPABILITY_VERSION_3;

    data[0].effective = CAP_SETPCAP;
    data[0].permitted = CAP_SETPCAP;
    data[0].inheritable = 0;

    data[1].effective = 0;
    data[1].permitted = 0;
    data[1].inheritable = 0;

    // 调用syscall进行capset
    if (syscall(SYS_capset, &header, data) == -1) {
        perror("syscall capset failed");
        return 1;
    }

    printf("Successfully called capset\n");

    return 0;
}