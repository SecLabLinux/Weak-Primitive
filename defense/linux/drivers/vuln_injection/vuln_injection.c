#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

#ifdef CONFIG_SHADOW_HEAP
// extern void *kmalloc_shadow(size_t size, gfp_t flags);
// extern void kfree_shadow(void *ptr);
#include "../../mm/shadow_heap/shadow_heap.h"
#endif

#define DEVICE_NAME "vuln_inj"
#define CLASS_NAME "vuln_inj_class"

#ifdef DEBUG
#define my_log(fmt, ...) \
    printk(KERN_DEBUG "my_log: " fmt, ##__VA_ARGS__)
#else
#define my_log(fmt, ...) \
    do { } while (0)
#endif

#ifdef CONFIG_TEST_IPI
extern unsigned long test_ipi_wq_head;
extern unsigned long long test_ipi_tsc_start;
extern unsigned long long test_ipi_tsc_end;
extern unsigned long long test_ipi_tsc_early_delay;
extern unsigned long long test_ipi_tsc_later_delay;
#endif

// 设备号变量
static dev_t dev_num;
// cdev结构
static struct cdev my_cdev;
// 设备类和设备结构
static struct class *vuln_inj_class = NULL;
static struct device *vuln_inj_device = NULL;
static void *vuln_inj_buf[0x1000];

enum vuln_inj_cmd {
    VULN_ARB_READ = 0xdeadcaf0,
    VULN_ARB_WRITE,
    VULN_READ,
    VULN_WRITE,
    VULN_ALLOC,
    VULN_FREE,
#ifdef CONFIG_TEST_IPI
    VULN_IPI,
#endif
#ifdef CONFIG_TEST_HRTIMER
    VULN_HRTIMER,
#endif
};

struct vuln_inj_req {
    union {
        // arbitrary read / write
        struct {
            unsigned int length;
            unsigned long addr;
            unsigned long *pval;
        } arb_read_write;
        // read / write
        struct {
            unsigned int index;
            unsigned int length;
            unsigned long offset;
            unsigned char *pval;
        } read_write;
        // alloc
        struct {
            unsigned int index;
            unsigned long size;
            unsigned long gfp_flags;
        } alloc;
        // free
        struct {
            unsigned int index;
        } free;
#ifdef CONFIG_TEST_IPI
        // ipi
        struct {
            unsigned long long start;
            unsigned long long end;
            unsigned long long diff_tsc;
            unsigned long long test_ipi_tsc_start;
            unsigned long long test_ipi_tsc_end;
            unsigned long loop_cnt;
            unsigned long loop_cnt_prepare;
            unsigned long long test_ipi_tsc_early_delay;
            unsigned long long test_ipi_tsc_later_delay;
            unsigned long long *s_array;
        } ipi;
#endif
    };
};

unsigned long long bss_s_array[0x1000];


// 设备操作函数原型
static int dev_open(struct inode *, struct file *);
static int dev_release(struct inode *, struct file *);
// static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
// static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);
static long dev_ioctl(struct file *, unsigned int, unsigned long);

static int dev_open(struct inode *inode, struct file *filp) {
    my_log(KERN_INFO "%s: Device has been opened\n", DEVICE_NAME);
    return 0;
}

static int dev_release(struct inode *inode, struct file *filp) {
    my_log(KERN_INFO "%s: Device has been released\n", DEVICE_NAME);
    return 0;
}

static long dev_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct vuln_inj_req req;
    char tmp_buf[0x100];
    int ret;

    if (copy_from_user(&req, (void *)arg, sizeof(req))) {
        my_log(KERN_INFO "Failed to copy from user\n");
        return -EFAULT;
    }

    switch (cmd) {
        case VULN_ARB_READ:
            my_log(KERN_INFO "Arbitrary read: addr = %lx\n", req.arb_read_write.addr);
            memcpy(tmp_buf, (void *)req.arb_read_write.addr, req.arb_read_write.length);
            ret = copy_to_user(req.arb_read_write.pval, tmp_buf, req.arb_read_write.length);
            break;
        case VULN_ARB_WRITE:
            my_log(KERN_INFO "Arbitrary write: addr = %lx, pval = %lx\n", req.arb_read_write.addr,
                   (unsigned long)req.arb_read_write.pval);
            ret = copy_from_user((void *)tmp_buf, req.arb_read_write.pval, req.arb_read_write.length);
            memcpy((void *)req.arb_read_write.addr, tmp_buf, req.arb_read_write.length);
            break;
        case VULN_READ:
            my_log(KERN_INFO "Read: offset = %lx\n", req.read_write.offset);
#ifdef CONFIG_SHADOW_HEAP
            OBJECT_CRUCIAL_MEMCPY_CHECK(vuln_inj_buf[req.read_write.index] + req.read_write.offset, req.read_write.length);
#endif
            memcpy(tmp_buf, vuln_inj_buf[req.read_write.index] + req.read_write.offset, req.read_write.length);
            ret = copy_to_user(req.read_write.pval, tmp_buf, req.read_write.length);
            break;
        case VULN_WRITE:
            my_log(KERN_INFO "Write: offset = %lx, pval = %lx\n", req.read_write.offset,
                   (unsigned long)req.read_write.pval);
            ret = copy_from_user(tmp_buf, req.read_write.pval, req.read_write.length);
#ifdef CONFIG_SHADOW_HEAP 
            OBJECT_CRUCIAL_MEMCPY_WRITE(vuln_inj_buf[req.read_write.index] + req.read_write.offset, tmp_buf, req.read_write.length);
#else
            memcpy(vuln_inj_buf[req.read_write.index] + req.read_write.offset, tmp_buf, req.read_write.length);
#endif
            break;
        case VULN_ALLOC:
            my_log(KERN_INFO "Alloc: index = %d, size = %lx, gfp_flags = %lx\n", req.alloc.index, req.alloc.size,
                   req.alloc.gfp_flags);
#ifdef CONFIG_SHADOW_HEAP
            vuln_inj_buf[req.alloc.index] = kmalloc_shadow(req.alloc.size, req.alloc.gfp_flags);
#else
            vuln_inj_buf[req.alloc.index] = kmalloc(req.alloc.size, req.alloc.gfp_flags);
#endif
            ret = 0;
            break;
        case VULN_FREE:
            my_log(KERN_INFO "Free: index = %d\n", req.free.index);
#ifdef CONFIG_SHADOW_HEAP
            kfree_shadow(vuln_inj_buf[req.free.index]);
#else
            kfree(vuln_inj_buf[req.free.index]);
#endif
            ret = 0;
            break;
#ifdef CONFIG_TEST_IPI
        case VULN_IPI:
            unsigned long long start_tsc, end_tsc;
            unsigned long long *s_array;
            if (req.ipi.loop_cnt + req.ipi.loop_cnt_prepare > 0x1000) {
                s_array = kmalloc(sizeof(unsigned long long) * (req.ipi.loop_cnt + req.ipi.loop_cnt_prepare), GFP_KERNEL);
                if (!s_array) {
                    my_log(KERN_INFO "Failed to allocate memory\n");
                    return -ENOMEM;
                }
            } else {
                s_array = bss_s_array;
            }

            for (int i = 0; i < req.ipi.loop_cnt_prepare; i++) {
                // asm volatile(
                //     ".intel_syntax noprefix\n\t"
                //     "xor rax, rax\n\t"
                //     ".att_syntax prefix\n\t"
                //     :       // 输出操作数为空
                //     :       // 输入操作数为空
                //     : "rax" // 被修改的寄存器列表
                // );
                s_array[i] = rdtsc();
            }
            start_tsc = rdtsc();
            for (int i = 0; i < req.ipi.loop_cnt; i++) {
                // asm volatile(
                //     ".intel_syntax noprefix\n\t"
                //     "xor rax, rax\n\t"
                //     ".att_syntax prefix\n\t"
                //     :       // 输出操作数为空
                //     :       // 输入操作数为空
                //     : "rax" // 被修改的寄存器列表
                // );
                s_array[i + req.ipi.loop_cnt_prepare] = rdtsc();
            }
            end_tsc = rdtsc();
            my_log(KERN_INFO "IPI: start_tsc = %llu, end_tsc = %llu, diff = %llu\n", start_tsc, end_tsc,
                   end_tsc - start_tsc);
            req.ipi.diff_tsc = end_tsc - start_tsc;
            req.ipi.start = start_tsc;
            req.ipi.end = end_tsc;
            msleep(50);
            req.ipi.test_ipi_tsc_start = test_ipi_tsc_start;
            req.ipi.test_ipi_tsc_end = test_ipi_tsc_end;
            req.ipi.test_ipi_tsc_early_delay = test_ipi_tsc_early_delay;
            req.ipi.test_ipi_tsc_later_delay = test_ipi_tsc_later_delay;
            ret = copy_to_user((void *)arg, &req, sizeof(req));
            if (req.ipi.s_array) {
                ret = copy_to_user(req.ipi.s_array, s_array, sizeof(unsigned long long) * (req.ipi.loop_cnt + req.ipi.loop_cnt_prepare));
            }
            if (req.ipi.loop_cnt + req.ipi.loop_cnt_prepare > 0x1000) {
                kfree(s_array);
            } else {
                memset(bss_s_array, 0, sizeof(bss_s_array));
            }
            break;
#endif
#ifdef CONFIG_TEST_HRTIMER
        case VULN_HRTIMER:
#ifdef CONFIG_TEST_IPI
            test_ipi_wq_head = (unsigned long)NULL;
#endif
            ret = 0;
            break;
#endif
        default:
            my_log(KERN_INFO "Unknown command\n");
            break;
    }

    return ret;
}

// 文件操作结构
static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    // .read = dev_read,
    // .write = dev_write,
    .unlocked_ioctl = dev_ioctl,
};

static int __init vuln_inj_init(void) {
    int ret;

    // 分配设备号
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        my_log(KERN_ALERT "Failed to allocate a device number\n");
        return ret;
    }

    // 创建设备类
    vuln_inj_class = class_create(CLASS_NAME);
    if (IS_ERR(vuln_inj_class)) {
        unregister_chrdev_region(dev_num, 1);
        my_log(KERN_ALERT "Failed to register device class\n");
        return PTR_ERR(vuln_inj_class);
    }

    // 创建设备
    vuln_inj_device = device_create(vuln_inj_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(vuln_inj_device)) {
        class_destroy(vuln_inj_class);
        unregister_chrdev_region(dev_num, 1);
        my_log(KERN_ALERT "Failed to create the device\n");
        return PTR_ERR(vuln_inj_device);
    }

    // 初始化cdev结构并添加到内核
    cdev_init(&my_cdev, &fops);
    ret = cdev_add(&my_cdev, dev_num, 1);
    if (ret < 0) {
        device_destroy(vuln_inj_class, dev_num);
        class_destroy(vuln_inj_class);
        unregister_chrdev_region(dev_num, 1);
        my_log(KERN_ALERT "Failed to add cdev\n");
        return ret;
    }

    my_log(KERN_INFO "%s: device class created correctly\n", DEVICE_NAME);
    return 0;
}

static void __exit vuln_inj_exit(void) {
    cdev_del(&my_cdev);
    device_destroy(vuln_inj_class, dev_num);
    class_destroy(vuln_inj_class);
    unregister_chrdev_region(dev_num, 1);
    my_log(KERN_INFO "%s: Goodbye from the LKM!\n", DEVICE_NAME);
}

module_init(vuln_inj_init);
module_exit(vuln_inj_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple vuln_inj Linux module.");
MODULE_VERSION("0.1");