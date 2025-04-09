#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    // Step 1: 设置网络接口的 SFQ 调度器
    const char *interface = "eth0";  // 选择目标接口，可以修改为实际的网络接口名称
    char command[256];

    // Step 2: 添加 SFQ 调度器
    snprintf(command, sizeof(command), "tc qdisc add dev %s root handle 1: sfq", interface);
    if (system(command) == -1) {
        perror("Failed to add SFQ scheduler");
        return 1;
    }

    printf("SFQ scheduler added successfully to %s\n", interface);

    // Step 3: 验证设置是否成功
    snprintf(command, sizeof(command), "tc qdisc show dev %s", interface);
    if (system(command) == -1) {
        perror("Failed to show qdisc");
        return 1;
    }

    return 0;
}