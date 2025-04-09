#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <linux/firmware.h>

int main() {
    const char *firmware_name = "non_existent_firmware.bin"; // 固件名称，可以是任何名称
    const struct firmware *fw = NULL;
    
    // 请求固件
    int ret = request_firmware(&fw, firmware_name, "/lib/firmware");
    if (ret != 0) {
        printf("Failed to request firmware: %d\n", ret);
        return -1;
    }

    printf("Firmware loaded successfully.\n");

    // 在这里我们可以触发内核函数
    release_firmware(fw);  // 释放固件资源

    return 0;
}