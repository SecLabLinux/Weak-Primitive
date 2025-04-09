#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

#define STACK_SIZE (1024 * 1024)

static char child_stack[STACK_SIZE];

int child_func(void *arg) {
    printf("In new PID namespace. PID: %ld\n", (long)getpid());
    // Keep the child process alive to inspect the namespace
    sleep(10);
    return 0;
}

int main() {
    printf("Parent PID: %ld\n", (long)getpid());

    // Unshare the PID namespace
    if (unshare(CLONE_NEWPID | CLONE_NEWTIME) == -1) {
        perror("unshare");
        exit(EXIT_FAILURE);
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (pid == 0) {
        // In child process within the new PID namespace
        printf("Child PID: %ld\n", (long)getpid());
        execlp("/bin/bash", "/bin/bash", NULL);
        perror("execlp");
        exit(EXIT_FAILURE);
    } else {
        // In parent process
        printf("Forked child PID: %d\n", pid);
        wait(NULL);
    }

    return 0;
}