#include <stdio.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>  
#include <sys/ioctl.h>  
#include <fcntl.h>  
#include <liburing.h>  

#define QUEUE_DEPTH 1  
#define BLOCK_SIZE 1024  

int main() {  
    struct io_uring ring;  
    struct io_uring_params params;  
    int ret, fd;  

    // Initialize io_uring structure  
    memset(&params, 0, sizeof(params));  
    ret = io_uring_queue_init_params(QUEUE_DEPTH, &ring, &params);  
    if (ret) {  
        perror("io_uring_queue_init_params");  
        return 1;  
    }  

    // Open a file to perform I/O operations  
    fd = open("/tmp/testfile", O_RDWR | O_CREAT | O_TRUNC, 0666);  
    if (fd < 0) {  
        perror("open");  
        return 1;  
    }  

    // Prepare a simple read/write operation  
    struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);  
    char *buf = (char *)malloc(BLOCK_SIZE);  
    memset(buf, 'A', BLOCK_SIZE);  

    io_uring_prep_write(sqe, fd, buf, BLOCK_SIZE, 0);  
    io_uring_sqe_set_data(sqe, buf);  

    // Submit the request  
    io_uring_submit(&ring);  

    // Wait for completion  
    struct io_uring_cqe *cqe;  
    ret = io_uring_wait_cqe(&ring, &cqe);  
    if (ret) {  
        perror("io_uring_wait_cqe");  
        return 1;  
    }  

    // Check if the operation was successful  
    if (cqe->res < 0) {  
        fprintf(stderr, "Async I/O operation failed: %d\n", cqe->res);  
        return 1;  
    }  
    printf("I/O operation completed successfully\n");  

    // Clean up  
    io_uring_cqe_seen(&ring, cqe);  
    close(fd);  
    io_uring_queue_exit(&ring);  
    free(buf);  

    return 0;  
}