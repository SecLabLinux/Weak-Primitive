#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

int main() {
    uid_t new_uid = 1001;  // 设置一个新的 UID
    if (setuid(new_uid) == -1) {
        perror("setuid failed");
        return 1;
    }
    printf("UID set to %d successfully.\n", new_uid);
    return 0;
}