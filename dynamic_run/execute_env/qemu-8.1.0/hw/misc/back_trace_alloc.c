#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/pci/pci.h"
#include "hw/hw.h"
#include "hw/pci/msi.h"
#include "qemu/timer.h"
#include "qom/object.h"
#include "qemu/main-loop.h" /* iothread mutex */
#include "qemu/module.h"
#include "qapi/visitor.h"

#define TYPE_PCI_BACK_TRACE_ALLOC_DEVICE "back-trace-alloc"
typedef struct BackTraceAllocState BackTraceAllocState;
DECLARE_INSTANCE_CHECKER(BackTraceAllocState, BACKTRACEALLOC,
                         TYPE_PCI_BACK_TRACE_ALLOC_DEVICE)

#define DMA_START       0x40000
#define DMA_SIZE        4096

struct BackTraceAllocState {
    PCIDevice pdev;
    MemoryRegion mmio;

    uint32_t status;

    QemuMutex lock;

# define BACK_TRACE_ALLOC_DMA_RUN            0x1
# define BACK_TRACE_ALLOC_DMA_DIR(cmd)       (((cmd) & 0x2) >> 1)
# define BACK_TRACE_ALLOC_DMA_FROM_PCI       0
# define BACK_TRACE_ALLOC_DMA_TO_PCI         1
    struct dma_state {
        dma_addr_t src;
        dma_addr_t dst;
        dma_addr_t cnt;
        dma_addr_t cmd;
    } dma;
    char dma_buf[DMA_SIZE];
    uint64_t dma_mask;
};


static bool within(uint64_t addr, uint64_t start, uint64_t end)
{
    return start <= addr && addr < end;
}

static void back_trace_alloc_check_range(uint64_t addr, uint64_t size1, uint64_t start,
                uint64_t size2)
{
    uint64_t end1 = addr + size1;
    uint64_t end2 = start + size2;

    if (within(addr, start, end2) &&
            end1 > addr && within(end1, start, end2)) {
        return;
    }

    hw_error("BACK_TRACE_ALLOC: DMA range 0x%016"PRIx64"-0x%016"PRIx64
             " out of bounds (0x%016"PRIx64"-0x%016"PRIx64")!",
            addr, end1 - 1, start, end2 - 1);
}

static dma_addr_t back_trace_alloc_clamp_addr(const BackTraceAllocState *back_trace_alloc, dma_addr_t addr)
{
    // dma_addr_t res = addr & back_trace_alloc->dma_mask;
    dma_addr_t res = addr;

    if (addr != res) {
        printf("BACK_TRACE_ALLOC: clamping DMA %#.16"PRIx64" to %#.16"PRIx64"!\n", addr, res);
    }

    return res;
}

int fd;

static void dma_rw(BackTraceAllocState *back_trace_alloc, dma_addr_t src, dma_addr_t dst, dma_addr_t cnt, dma_addr_t cmd) {

    // write(fd, "Triggered 2\n", 12);
    // qatomic_or(&back_trace_alloc->status, BACK_TRACE_ALLOC_DMA_RUN);
    qemu_mutex_lock(&back_trace_alloc->lock);

    // DMA read (From vitrual machine physical memory to PCI host memery)
    if (BACK_TRACE_ALLOC_DMA_DIR(cmd) == BACK_TRACE_ALLOC_DMA_TO_PCI) {
        uint64_t o_dst = dst;
        back_trace_alloc_check_range(o_dst, cnt, DMA_START, DMA_SIZE);
        o_dst -= DMA_START;
        pci_dma_read(&back_trace_alloc->pdev, back_trace_alloc_clamp_addr(back_trace_alloc, src), back_trace_alloc->dma_buf + o_dst, cnt);

        write(fd, back_trace_alloc->dma_buf + o_dst, cnt);
    }
    // DMA write (From PCI host memery to vitrual machine physical memory)
    else {
        uint64_t o_src = src;
        back_trace_alloc_check_range(o_src, cnt, DMA_START, DMA_SIZE);
        o_src -= DMA_START;
        pci_dma_write(&back_trace_alloc->pdev, back_trace_alloc_clamp_addr(back_trace_alloc, dst), back_trace_alloc->dma_buf + o_src, cnt);
    }

    qemu_mutex_unlock(&back_trace_alloc->lock);

    // qatomic_and(&back_trace_alloc->status, ~BACK_TRACE_ALLOC_DMA_RUN);
}

static uint64_t back_trace_alloc_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    BackTraceAllocState *back_trace_alloc = opaque;
    uint64_t val = ~0ULL;

    if (addr < 0x80 && size != 4) {
        return val;
    }

    if (addr >= 0x80 && size != 4 && size != 8) {
        return val;
    }

    switch (addr) {
    case 0x00:
        val = 0xdeadbeef;
        break;
    case 0x20:
        val = qatomic_read(&back_trace_alloc->status);
        break;
    }

    return val;
}

static void back_trace_alloc_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                unsigned size)
{
    BackTraceAllocState *back_trace_alloc = opaque;

    if (addr < 0x80 && size != 4) {
        return;
    }

    if (addr >= 0x80 && size != 4 && size != 8) {
        return;
    }

    switch (addr) {
    case 0x80:
        back_trace_alloc->dma.src = val;
        break;
    case 0x88:
        back_trace_alloc->dma.dst = val;
        break;
    case 0x90:
        back_trace_alloc->dma.cnt = val;
        break;
    case 0x98:
        back_trace_alloc->dma.cmd = val;
        break;
    case 0xa0:
        // write(fd, "Triggered 1\n", 12);
        dma_rw(back_trace_alloc, back_trace_alloc->dma.src, back_trace_alloc->dma.dst, back_trace_alloc->dma.cnt, back_trace_alloc->dma.cmd);
        break;
    }
}

static const MemoryRegionOps back_trace_alloc_mmio_ops = {
    .read = back_trace_alloc_mmio_read,
    .write = back_trace_alloc_mmio_write,
    .endianness = DEVICE_NATIVE_ENDIAN,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 8,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 8,
    },

};


static void pci_back_trace_alloc_realize(PCIDevice *pdev, Error **errp)
{
    BackTraceAllocState *back_trace_alloc = BACKTRACEALLOC(pdev);

    memory_region_init_io(&back_trace_alloc->mmio, OBJECT(back_trace_alloc), &back_trace_alloc_mmio_ops, back_trace_alloc, "back_trace_alloc-mmio", 1 * 0x1000);
    pci_register_bar(pdev, 0, PCI_BASE_ADDRESS_SPACE_MEMORY, &back_trace_alloc->mmio);

    back_trace_alloc->status = 0;

    qemu_mutex_init(&back_trace_alloc->lock);

    if (!fd) {
        char filename[256];
        time_t current_time;
        current_time = time(NULL);
        sprintf(filename, "/root/pwn/data/back_trace_alloc/%d_%llu", getpid(), current_time);
        fd = open(filename, O_RDWR | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) {
            printf("open /tmp/back_trace_alloc failed\n");
            exit(1);
        }
    }
}

static void pci_back_trace_alloc_uninit(PCIDevice *pdev)
{
    BackTraceAllocState *back_trace_alloc = BACKTRACEALLOC(pdev);
    qemu_mutex_destroy(&back_trace_alloc->lock);
    if (fd) {
        close(fd);
    }
}

static void back_trace_alloc_instance_init(Object *obj)
{
    BackTraceAllocState *back_trace_alloc = BACKTRACEALLOC(obj);

    back_trace_alloc->dma_mask = (1UL << 31) - 1;
    object_property_add_uint64_ptr(obj, "dma_mask",
                                   &back_trace_alloc->dma_mask, OBJ_PROP_FLAG_READWRITE);
}

static void back_trace_alloc_class_init(ObjectClass *class, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(class);
    PCIDeviceClass *k = PCI_DEVICE_CLASS(class);

    k->realize = pci_back_trace_alloc_realize;
    k->exit = pci_back_trace_alloc_uninit;
    k->vendor_id = PCI_VENDOR_ID_QEMU;
    k->device_id = 0x11e8;
    k->revision = 0x10;
    k->class_id = PCI_CLASS_OTHERS;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
}

static void pci_back_trace_alloc_register_types(void)
{
    static InterfaceInfo interfaces[] = {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    };
    static const TypeInfo back_trace_alloc_info = {
        .name          = TYPE_PCI_BACK_TRACE_ALLOC_DEVICE,
        .parent        = TYPE_PCI_DEVICE,
        .instance_size = sizeof(BackTraceAllocState),
        .instance_init = back_trace_alloc_instance_init,
        .class_init    = back_trace_alloc_class_init,
        .interfaces = interfaces,
    };

    type_register_static(&back_trace_alloc_info);
}
type_init(pci_back_trace_alloc_register_types)
