#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sched.h>
#include <unistd.h>

int main() {
    // 使用 unshare 创建新的用户命名空间
    if (unshare(CLONE_NEWUSER) == -1) {
        perror("unshare");
        return 1;
    }

    // 成功创建新的用户命名空间
    printf("Created new user namespace\n");

    // 继续执行其它操作，确保新的命名空间生效
    // 此处可以添加更多逻辑以验证命名空间的创建和使用

    return 0;
}