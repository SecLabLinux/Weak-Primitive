#include <stdio.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <linux/fanotify.h>
#include <fcntl.h>

int main() {
    int fanotify_fd;
    fanotify_fd = syscall(SYS_fanotify_init, FAN_CLOEXEC | FAN_NONBLOCK, O_RDONLY);
    
    if (fanotify_fd == -1) {
        perror("fanotify_init failed");
        return 1;
    }

    printf("Fanotify initialized successfully with fd: %d\n", fanotify_fd);
    close(fanotify_fd);
    return 0;
}