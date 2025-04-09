#include <linux/cdev.h> /* cdev_ */
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/uaccess.h> /* put_user */
#include <linux/io.h>
#include <asm/io.h>
#include <linux/mutex.h>
#include <linux/semaphore.h>
#include <linux/dma-mapping.h>
#include <linux/workqueue.h>


#include <linux/back_trace_alloc.h>

#define BAR 0
#define CDEV_NAME "back_trace_alloc_print"
#define BACK_TRACE_ALLOC_DEVICE_ID 0x11e8
#define QEMU_VENDOR_ID 0x1234

/* Registers. */
#define IO_DMA_SRC 0x80
#define IO_DMA_DST 0x88
#define IO_DMA_CNT 0x90
#define IO_DMA_CMD 0x98
#define IO_DMA_RUN 0xa0

#define BACK_TRACE_ALLOC_DMA_RUN 0x1

/* Constants. */
#define DMA_TO_DEV 0x2 // FIXME: what is this?

static struct pci_device_id pci_ids[] = {{
                                             PCI_DEVICE(QEMU_VENDOR_ID, BACK_TRACE_ALLOC_DEVICE_ID),
                                         },
                                         {
                                             0,
                                         }};
MODULE_DEVICE_TABLE(pci, pci_ids);

static int major;
static struct pci_dev *pdev;
static void __iomem *mmio;
struct mutex dma_mutex = __MUTEX_INITIALIZER(dma_mutex);
struct semaphore dma_sem;
spinlock_t dma_lock;

static ssize_t read(struct file *filp, char __user *buf, size_t len, loff_t *off) {
    ssize_t ret = 0;
    uint64_t kbuf;

    if (*off % 4 == 0 && len == 4) {
        kbuf = ioread32(mmio + *off);
        if (copy_to_user(buf, (void *)&kbuf, 4)) {
            ret = -EFAULT;
        } else {
            ret = 4;
            (*off) += 4;
        }
    } else if (*off % 8 == 0 && len == 8) {
        kbuf = readq(mmio + *off);
        if (copy_to_user(buf, (void *)&kbuf, 8)) {
            ret = -EFAULT;
        } else {
            ret = 8;
            (*off) += 8;
        }
    }
    return ret;
}

static ssize_t write(struct file *filp, const char __user *buf, size_t len, loff_t *off) {
    ssize_t ret = 0;
    uint64_t kbuf;

    if (*off % 4 == 0 && len == 4) {
        if (copy_from_user((void *)&kbuf, buf, 4)) {
            ret = -EFAULT;
        } else {
            iowrite32(kbuf, mmio + *off);
            ret = 4;
            (*off) += 4;
        }
    } else if (*off % 8 == 0 && len == 8) {
        if (copy_from_user((void *)&kbuf, buf, 8)) {
            ret = -EFAULT;
        } else {
            writeq(kbuf, mmio + *off);
            ret = 8;
            (*off) += 8;
        }
    }
    return ret;
}

static loff_t llseek(struct file *filp, loff_t off, int whence)
{
	filp->f_pos = off;
	return off;
}

static struct file_operations fops = {
	.owner   = THIS_MODULE,
	.llseek  = llseek,
	.read    = read,
	.write   = write,
};

int back_trace_alloc_dma_read(char *buf, uint64_t dma_addr, uint64_t cnt)
{
    dma_addr_t mapped_addr;

    mapped_addr = dma_map_single(&pdev->dev, buf, cnt, DMA_FROM_DEVICE);
    if (dma_mapping_error(&pdev->dev, mapped_addr)) {
        return -EIO;
    }

    // down(&dma_sem);
    // mutex_lock(&dma_mutex);
    spin_lock(&dma_lock);
    writeq(dma_addr, mmio + IO_DMA_SRC);
    writeq(mapped_addr, mmio + IO_DMA_DST);
    writeq(cnt, mmio + IO_DMA_CNT);
    writeq(0, mmio + IO_DMA_CMD);
    writeq(1, mmio + IO_DMA_RUN);
    spin_unlock(&dma_lock);
    // mutex_unlock(&dma_mutex);
    // up(&dma_sem);

    dma_unmap_single(&pdev->dev, mapped_addr, cnt, DMA_FROM_DEVICE);

    return 0;
}
EXPORT_SYMBOL(back_trace_alloc_dma_read);

struct dma_work {
    struct work_struct work;
    uint64_t dma_addr;
    char *buf;
    uint64_t cnt;
};

static struct workqueue_struct *dma_wq;

static void dma_write_work_func(struct work_struct *w) {
    struct dma_work *work = container_of(w, struct dma_work, work);
    dma_addr_t mapped_addr;

    atomic_set(&current->back_trace_alloc_meta.do_not_record_alloc_page, 1);
    atomic_set(&current->back_trace_alloc_meta.do_not_record_kmalloc, 1);

    mapped_addr = dma_map_single(&pdev->dev, work->buf, work->cnt, DMA_TO_DEVICE);
    if (dma_mapping_error(&pdev->dev, mapped_addr)) {
        return;
    }

    // down(&dma_sem);
    // mutex_lock(&dma_mutex);
    spin_lock(&dma_lock);
    writeq(mapped_addr, mmio + IO_DMA_SRC);
    writeq(work->dma_addr, mmio + IO_DMA_DST);
    writeq(work->cnt, mmio + IO_DMA_CNT);
    writeq(DMA_TO_DEV, mmio + IO_DMA_CMD);
    writeq(1, mmio + IO_DMA_RUN);
    spin_unlock(&dma_lock);
    // mutex_unlock(&dma_mutex);
    // up(&dma_sem);

    dma_unmap_single(&pdev->dev, mapped_addr, work->cnt, DMA_TO_DEVICE);
    kfree(work->buf);
    kfree(work);
    atomic_set(&current->back_trace_alloc_meta.do_not_record_alloc_page, 0);
    atomic_set(&current->back_trace_alloc_meta.do_not_record_kmalloc, 0);
}

int back_trace_alloc_dma_write(uint64_t dma_addr, char *buf, uint64_t cnt) {
    struct dma_work *work;
    work = kmalloc(sizeof(struct dma_work), GFP_KERNEL);
    work->dma_addr = dma_addr;
    work->buf = buf;
    work->cnt = cnt;
    INIT_WORK(&work->work, dma_write_work_func);
    queue_work(dma_wq, &work->work);
    // schedule_work(&work->work);
    return 0;
}
EXPORT_SYMBOL(back_trace_alloc_dma_write);

static int pci_probe(struct pci_dev *dev, const struct pci_device_id *id)
{
	dev_info(&(dev->dev), "pci_probe\n");
	major = register_chrdev(0, CDEV_NAME, &fops);
	pdev = dev;
	if (pci_enable_device(dev) < 0) {
		dev_err(&(dev->dev), "pci_enable_device\n");
		goto error;
	}
	if (pci_request_region(dev, BAR, "myregion0")) {
		dev_err(&(dev->dev), "pci_request_region\n");
		goto error;
	}
	mmio = pci_iomap(dev, BAR, pci_resource_len(dev, BAR));

    dma_wq = create_singlethread_workqueue("dma_wq");
    if (!dma_wq) {
        dev_err(&(dev->dev), "create_singlethread_workqueue\n");
        goto error;
    }

    register_back_trace_alloc_print_callback(back_trace_alloc_dma_write, back_trace_alloc_dma_read);

    pci_set_master(dev);

    sema_init(&dma_sem, 1);
    spin_lock_init(&dma_lock);


	return 0;
error:
	return 1;
}

static void pci_remove(struct pci_dev *dev)
{
	pr_info("pci_remove\n");
    flush_workqueue(dma_wq);
    destroy_workqueue(dma_wq);
	pci_release_region(dev, BAR);
	unregister_chrdev(major, CDEV_NAME);
}

static struct pci_driver pci_driver = {
	.name     = CDEV_NAME,
	.id_table = pci_ids,
	.probe    = pci_probe,
	.remove   = pci_remove,
};

static int myinit(void)
{
	if (pci_register_driver(&pci_driver) < 0) {
		return 1;
	}
	return 0;
}

static void myexit(void)
{
	pci_unregister_driver(&pci_driver);
}

module_init(myinit);
module_exit(myexit);
MODULE_LICENSE("GPL");