#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <uapi/linux/kvm_para.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>
#include <asm/tdx.h>
#include <asm/page.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/kasan.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <asm/apic.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "fuzz_ctrl"
#define CLASS_NAME  "fuzz"

#define FUZZ_MAGIC   0xF5
#define FUZZ_ENABLE  _IOW(FUZZ_MAGIC, 0x01, int)
#define FUZZ_DISABLE _IO(FUZZ_MAGIC, 0x02)
#define IRQ_DUMP _IO(FUZZ_MAGIC, 0x07)
#define INJECT_IRQ_TEST _IO(FUZZ_MAGIC, 0x9) 
#define TEST_KASAN _IO(FUZZ_MAGIC, 0x0a)
#define PREPARE_DATA    _IO(FUZZ_MAGIC, 0x10)
#define TDX_FUZZ_INTERRUPT 256

#define MAX_IRQS 16

struct addr_irq_entry {
    u64 addr;
    int irqs[MAX_IRQS];
    int irq_cnt;
    struct list_head list;
};

static dev_t dev_num;
static struct cdev fuzz_cdev;
static struct class *fuzz_class = NULL;
static struct device *fuzz_device = NULL;
static LIST_HEAD(addr_irq_list);

#define BUF_LEN 0x400
#define DMA_BUF_LEN	0x10000

extern int tdx_fuzz_target;
extern bool kasan_watch_table_ready;
extern char tdx_fuzz_dma_data[DMA_BUF_LEN];
extern void kasan_poison(const void *addr, size_t size, u8 value, bool init);
extern int kasan_add_watch(unsigned long addr, int irqs[], int count);

typedef struct fuzz_input {
    char msr_data[BUF_LEN];
    char cpuid_data[BUF_LEN];
    char pio_data[BUF_LEN];
    char mmio_data[BUF_LEN];
    char dma_data[DMA_BUF_LEN];
}fuzz_input;

typedef struct guest_msix_inject {
    uint16_t domain;
    uint8_t  bus;
    uint8_t  slot;
    uint8_t  func;
    uint16_t entry;
}guest_msix_inject_t;

#define MY_POISON_BYTE 0xA5
char my_test_global_array[16] = "this is a test!";

static bool is_msix_desc(struct msi_desc *mdesc)
{
    if (!mdesc || !mdesc->dev)
        return false;

    if (!dev_is_pci(mdesc->dev))
        return false;

    return pci_find_capability(to_pci_dev(mdesc->dev),
                               PCI_CAP_ID_MSIX) != 0;
}

static bool irq_is_msi(struct irq_data *d)
{
    if (!d || !d->chip)
        return false;

    /* x86 MSI/MSI-X */
    if (!strcmp(d->chip->name, "MSI") ||
        !strcmp(d->chip->name, "MSIX"))
        return true;

    return false;
}

static const char *irq_trigger_type(struct irq_desc *desc)
{
    if (!desc->action)
        return "";

    if (desc->action->flags & IRQF_TRIGGER_RISING)
        return "edge";
    if (desc->action->flags & IRQF_TRIGGER_FALLING)
        return "edge";
    if (desc->action->flags & IRQF_TRIGGER_HIGH)
        return "level";
    if (desc->action->flags & IRQF_TRIGGER_LOW)
        return "level";

    /* MSI/MSI-X 默认 edge */
    return "edge";
}

int irq_get_msi_addr_data(unsigned int irq, u64 *addr, u32 *data)
{
    struct msi_desc *desc;
    struct msi_msg msg;

    desc = irq_get_msi_desc(irq);
    if (!desc)
        return -ENODEV;   // 不是 MSI / MSI-X

    __pci_read_msi_msg(desc, &msg);

    *addr = ((u64)msg.address_hi << 32) | msg.address_lo;
    *data = msg.data;
    return 0;
}

static bool dump_irq_info(unsigned int irq, guest_msix_inject_t *info)
{
    struct irq_desc *desc;
    struct irq_data *d;
    struct msi_desc *mdesc;
    struct irqaction *act;

    desc = irq_to_desc(irq);
    if (!desc)
        return false;

    d = &desc->irq_data;
    act = desc->action;

    if (!act)
        return false; /* /proc/interrupts 里也不显示 */

    mdesc = irq_data_get_msi_desc(d);

    if (mdesc && mdesc->dev && dev_is_pci(mdesc->dev)) {
        struct pci_dev *pdev = to_pci_dev(mdesc->dev);
        info->domain = pci_domain_nr(pdev->bus);
        info->bus = pdev->bus->number;
        info->slot = PCI_SLOT(pdev->devfn);
        info->func = PCI_FUNC(pdev->devfn);
        info->entry = mdesc->msi_index;
        pr_info("IRQ %-3u  PCI-MSIX-%04x:%02x:%02x.%d  %d-%s  %s\n",
                irq,
                info->domain,
                info->bus,
                info->slot,
                info->func,
                info->entry,                 /* ★ MSI-X entry */
                irq_trigger_type(desc),
                act->name ? act->name : "");
    } else {
        /* LEGACY / 非 MSI-X */
        pr_info("IRQ %-3u  LEGACY  %s\n",
                irq,
                act->name ? act->name : "");
    }
    return true;
}

static char *read_file_to_buf(const char *path, ssize_t *out_len)
{
    struct file *filp;
    char *buf;
    loff_t pos = 0;
    ssize_t size;

    filp = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(filp))
        return NULL;

    size = i_size_read(file_inode(filp));
    buf = kzalloc(size + 1, GFP_KERNEL);
    if (!buf)
        goto out;

    kernel_read(filp, buf, size, &pos);
    *out_len = size;

out:
    filp_close(filp, NULL);
    return buf;
}

static int parse_irq_array(char *p, int *irqs)
{
    int cnt = 0;
    int val = 0;
    bool in_num = false;

    while (*p && *p != ']') {
        if (*p >= '0' && *p <= '9') {
            val = val * 10 + (*p - '0');
            in_num = true;
        } else {
            if (in_num) {
                irqs[cnt++] = val;
                if (cnt >= MAX_IRQS)
                    return cnt;
                val = 0;
                in_num = false;
            }
        }
        p++;
    }

    /* 处理 "]" 前刚好是数字的情况 */
    if (in_num && cnt < MAX_IRQS)
        irqs[cnt++] = val;

    return cnt;
}

static int parse_json(char *buf)
{
    char *p = buf;

    while (1) {
        char *key_start, *key_end;
        char *arr_start, *arr_end;
        char keybuf[32];
        int len;
        struct addr_irq_entry *e;

        /* 找 key 起始 */
        key_start = strchr(p, '"');
        if (!key_start)
            break;

        key_end = strchr(key_start + 1, '"');
        if (!key_end)
            break;

        len = key_end - (key_start + 1);
        if (len <= 0 || len >= sizeof(keybuf)) {
            p = key_end + 1;
            continue;
        }

        memcpy(keybuf, key_start + 1, len);
        keybuf[len] = '\0';

        e = kzalloc(sizeof(*e), GFP_KERNEL);
        if (!e)
            return -ENOMEM;
        pr_info("parse_json: %s",keybuf);

        if (kstrtoull(keybuf, 0, &e->addr)) {
            kfree(e);
            p = key_end + 1;
            continue;
        }
        pr_info("parse_json: %s %lx",keybuf,e->addr);
        /* 找数组 */
        arr_start = strchr(key_end + 1, '[');
        if (!arr_start) {
            kfree(e);
            break;
        }

        e->irq_cnt = parse_irq_array(arr_start + 1, e->irqs);

        INIT_LIST_HEAD(&e->list);
        list_add_tail(&e->list, &addr_irq_list);

        arr_end = strchr(arr_start, ']');
        if (!arr_end)
            break;

        p = arr_end + 1;   // 单调向前，绝不回头
    }

    return 0;
}


int load_addr_irq_json(const char *path)
{
    char *buf;
    ssize_t len;
    int ret;

    buf = read_file_to_buf(path, &len);
    if (!buf)
        return -ENOENT;

    ret = parse_json(buf);
    kfree(buf);
    return ret;
}

static void poison_entries(void)
{
    struct addr_irq_entry *e;
    int i;

    list_for_each_entry(e, &addr_irq_list, list) {
        pr_info("addr: 0x%llx irqs:", e->addr);
        for (i = 0; i < e->irq_cnt; i++)
            pr_cont(" %d", e->irqs[i]);
        pr_cont("\n");
        kasan_add_watch(e->addr, e->irqs, e->irq_cnt);
        kasan_poison((void *)e->addr, 8, MY_POISON_BYTE, false);
    }
}

static long fuzz_ctrl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int target;
    struct irq_desc *desc;
    struct msi_desc *mdesc;
    struct irqaction *action;
    int irq;
    int i;
    int ret;
    u64 addr;
    u32 data;
    int test_irq[]={2};
    struct msi_msg *msg = kmalloc(sizeof(*msg), GFP_KERNEL);

    fuzz_input *fuzz_tdx_input = kmalloc(sizeof(*fuzz_tdx_input), GFP_KERNEL);
    guest_msix_inject_t *info = kmalloc(sizeof(guest_msix_inject_t), GFP_KERNEL);

    switch (cmd) {
    case FUZZ_ENABLE:
        if (copy_from_user(&target, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        pr_info("fuzz_ctrl: Enabling fuzz on target: %d\n", target);
	    tdx_fuzz_target = target;
        kvm_hypercall2(KVM_HC_FUZZ_CTRL, 1, target);
        if (tdx_fuzz_target & TDX_FUZZ_INTERRUPT) {
            kasan_watch_table_ready = true;
        }
        return 0;

    case FUZZ_DISABLE:
        pr_info("fuzz_ctrl: Disabling fuzz\n");
	    tdx_fuzz_target = 0;
        kvm_hypercall2(KVM_HC_FUZZ_CTRL, 0, 0);
        return 0;
    case IRQ_DUMP:
	    pr_info("[irq_dump] Dumping IRQ handlers:\n");
	    pr_info("[irq_dump] nr_irq: %d\n",nr_irqs);
    	for (irq = 0; irq < nr_irqs; irq++) {
        	dump_irq_info(irq, info);
            if (!irq_get_msi_addr_data(irq, &addr, &data)) {
                pr_info("IRQ %u MSI addr=%#llx data=%#x\n",
                        irq, addr, data);
            }
        }
	    return 0;
    case INJECT_IRQ_TEST:
        irq = 2;
        
        // if(!dump_irq_info(irq, info)) {
        //     pr_info("info is NULL");
        //     return 0;
        // }
        mdesc = irq_get_msi_desc(irq);
        if (!mdesc)
            return -ENODEV;   // 不是 MSI / MSI-X

        __pci_read_msi_msg(mdesc, msg);
        addr = ((u64)msg->address_hi << 32) | msg->address_lo;
        data = msg->data;
        pr_info("before inject, info:%d,addr:{%ld},data:{%d}",__pa(msg),addr,data);
        kvm_hypercall1(KVM_HC_INJECT_IRQ, __pa(msg));
        pr_info("After triggering");
        return 0;
    case TEST_KASAN:
        pr_info("test kasan");
        kasan_poison(my_test_global_array, 16, MY_POISON_BYTE, false);
        
        kasan_add_watch((unsigned long)my_test_global_array, test_irq, 1);
        kasan_watch_table_ready = true;
        int index = irq/16;
        char val = my_test_global_array[index]; 
        pr_info("after test, index = %d, my_test_global_array[index] = %p, val = %c...\n",index,&my_test_global_array[index],val);
        return 0;

    case PREPARE_DATA:
        if (fuzz_tdx_input == NULL || copy_from_user(fuzz_tdx_input, (void __user *)arg, sizeof(fuzz_input)))
                return -EFAULT;
        pr_info("prepare data: msr_data: %s;\ncpuid_data: %s\npio_data: %s\nmmio_data: %s\ndma_data: %s\n", 
            fuzz_tdx_input->msr_data, fuzz_tdx_input->cpuid_data, fuzz_tdx_input->pio_data, 
            fuzz_tdx_input->mmio_data, fuzz_tdx_input->dma_data);
            
        kvm_hypercall1(KVM_HC_PREPARE_DATA, __pa(fuzz_tdx_input));
        memcpy(tdx_fuzz_dma_data, fuzz_tdx_input->dma_data, DMA_BUF_LEN);
        load_addr_irq_json("/root/addr_irq.json");
        poison_entries();
        return 0;
    default:
        pr_info("Not_found!");
        return -ENOTTY;
    }
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = fuzz_ctrl_ioctl,
};

static int __init fuzz_ctrl_init(void)
{
    int ret;
    ret = alloc_chrdev_region(&dev_num, 0, 1, DEVICE_NAME);
    if (ret < 0) {
        pr_err("fuzz_ctrl: failed to alloc_chrdev_region\n");
        return ret;
    }

    cdev_init(&fuzz_cdev, &fops);
    fuzz_cdev.owner = THIS_MODULE;

    ret = cdev_add(&fuzz_cdev, dev_num, 1);
    if (ret < 0) {
        unregister_chrdev_region(dev_num, 1);
        pr_err("fuzz_ctrl: failed to add cdev\n");
        return ret;
    }

    fuzz_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(fuzz_class)) {
        cdev_del(&fuzz_cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(fuzz_class);
    }

    fuzz_device = device_create(fuzz_class, NULL, dev_num, NULL, DEVICE_NAME);
    if (IS_ERR(fuzz_device)) {
        class_destroy(fuzz_class);
        cdev_del(&fuzz_cdev);
        unregister_chrdev_region(dev_num, 1);
        return PTR_ERR(fuzz_device);
    }

    pr_info("fuzz_ctrl: device initialized\n");
    return 0;
}

static void __exit fuzz_ctrl_exit(void) {
}

module_init(fuzz_ctrl_init);
module_exit(fuzz_ctrl_exit);

MODULE_LICENSE("GPL");
