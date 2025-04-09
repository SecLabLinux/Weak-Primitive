#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    // 设定网卡接口名，通常是 wlan0 或其他
    const char *interface = "wlan0";
    
    // 配置 SSID 和信道
    const char *ssid = "TestAP";
    int channel = 6;
    
    // 使用 iw 工具设置无线网卡
    char command[256];

    // 1. 设置无线网卡工作模式为 AP
    snprintf(command, sizeof(command), "iw dev %s set type ap", interface);
    system(command);

    // 2. 设置信道
    snprintf(command, sizeof(command), "iw dev %s set channel %d", interface, channel);
    system(command);

    // 3. 启动一个简单的接入点
    snprintf(command, sizeof(command), "hostapd -B -P /var/run/hostapd.pid /etc/hostapd/hostapd.conf");
    system(command);

    // 打印成功信息
    printf("AP is started on interface %s with SSID: %s on channel %d\n", interface, ssid, channel);

    // 持续运行，保持 AP 存在
    while(1) {
        sleep(10);
    }

    return 0;
}