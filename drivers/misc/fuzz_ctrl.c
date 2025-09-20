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

#define DEVICE_NAME "fuzz_ctrl"
#define CLASS_NAME  "fuzz"

#define FUZZ_MAGIC   0xF5
#define FUZZ_ENABLE  _IOW(FUZZ_MAGIC, 0x01, int)
#define FUZZ_DISABLE _IO(FUZZ_MAGIC, 0x02)
#define READ_PORT8  _IOW(FUZZ_MAGIC, 4, int)
#define READ_PORT16 _IOW(FUZZ_MAGIC, 5, int)
#define READ_PORT32 _IOW(FUZZ_MAGIC, 6, int)
#define ALLOC_DMA _IO(FUZZ_MAGIC, 0x03)
#define IRQ_DUMP _IO(FUZZ_MAGIC, 0x07)
#define IDT_DUMP _IO(FUZZ_MAGIC, 0x08)
#define INJECT_IRQ_TEST _IOW(FUZZ_MAGIC, 0x9, int) 

static dev_t dev_num;
static struct cdev fuzz_cdev;
static struct class *fuzz_class = NULL;
static struct device *fuzz_device = NULL;
static struct device *dma_dev;
static void *coherent_buf;
static dma_addr_t coherent_dma_handle;
#define BUF_SIZE 4096
#define IDT_ENTRIES 256
#define BUF_LEN 0x400
#define DMA_BUF_LEN	0x10000

extern int tdx_fuzz_target;
extern char tdx_fuzz_dma_data[DMA_BUF_LEN];

typedef struct fuzz_input {
    char msr_data[BUF_LEN];
    char cpuid_data[BUF_LEN];
    char pio_data[BUF_LEN];
    char mmio_data[BUF_LEN];
    char dma_data[DMA_BUF_LEN];
}fuzz_input;
#define PREPARE_DATA    _IO(FUZZ_MAGIC, 0x10)
// static fuzz_input fuzz_tdx_input;
// IDT 结构
struct my_desc_ptr {
    unsigned short size;
    unsigned long address;
} __attribute__((packed));

// 每个 IDT 描述符是 16 字节
struct gate_desc {
    u16 offset_low;
    u16 segment;
    u8 ist;
    u8 type_attr;
    u16 offset_middle;
    u32 offset_high;
    u32 zero;
} __attribute__((packed));

// 获取中断入口地址
static unsigned long get_gate_offset(struct gate_desc *desc) {
    return ((unsigned long)desc->offset_low) |
           ((unsigned long)desc->offset_middle << 16) |
           ((unsigned long)desc->offset_high << 32);
}

static int global_var = 100;

static long fuzz_ctrl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int target;
    struct irq_desc *desc;
    struct irqaction *action;
    int irq;
    struct my_desc_ptr idtr;
    struct gate_desc *idt;
    int i;
    int ret;
    fuzz_input *fuzz_tdx_input = kmalloc(sizeof(*fuzz_tdx_input), GFP_KERNEL);;

    switch (cmd) {
    case FUZZ_ENABLE:
        if (copy_from_user(&target, (int __user *)arg, sizeof(int)))
            return -EFAULT;
        pr_info("fuzz_ctrl: Enabling fuzz on target: %d\n", target);
	tdx_fuzz_target = target;
        kvm_hypercall2(KVM_HC_FUZZ_CTRL, 1, target);
        return 0;

    case FUZZ_DISABLE:
        pr_info("fuzz_ctrl: Disabling fuzz\n");
	tdx_fuzz_target = 0;
        kvm_hypercall2(KVM_HC_FUZZ_CTRL, 0, 0);
        return 0;
    case READ_PORT8:
    case READ_PORT16:
    case READ_PORT32:
        if (copy_from_user(&target, (int __user *)arg, sizeof(int)))
            return -EFAULT;

        switch (cmd) {
        case READ_PORT8:
            pr_info("PIO:%d %d",target, inb(target));
            break;
        case READ_PORT16:
            pr_info("PIO:%d %d",target, inw(target));
            break;
        case READ_PORT32:
            pr_info("PIO:%d %d",target, inl(target));
            break;
        }
        return 0;
    case ALLOC_DMA:
	pr_info("dma_test: init\n");

	// 获取一个 dummy 虚拟设备（可以绑定到真实 platform/pci device）
	dma_dev = kzalloc(sizeof(struct device), GFP_KERNEL);
	if (!dma_dev)
		return -ENOMEM;

	dev_set_name(dma_dev, "dma_test_dev");
	device_initialize(dma_dev);

	// 设置 dma_mask 和 coherent_dma_mask
	dma_dev->coherent_dma_mask = DMA_BIT_MASK(64);
	dma_dev->dma_mask = &dma_dev->coherent_dma_mask;


	/* -------- 1. coherent buffer 分配并访问 -------- */
	coherent_buf = dma_alloc_coherent(dma_dev, BUF_SIZE, &coherent_dma_handle, GFP_KERNEL);
	if (!coherent_buf) {
		pr_err("dma_test: Failed to alloc coherent buffer\n");
		return -ENOMEM;
	}

	pr_info("dma_test: coherent buffer vaddr=%p, dma_handle=0x%llx\n",
	        coherent_buf, (unsigned long long)coherent_dma_handle);
	kvm_hypercall2(KVM_HC_FUZZ_CTRL, coherent_dma_handle, BUF_SIZE);
	// 写入内容
	strcpy(coherent_buf, "hello from coherent dma buffer");
	pr_info("dma_test: readback: %s\n", (char *)coherent_buf);
	strcpy(coherent_buf, "hello from coherent dma buffer");
        pr_info("dma_test: readback: %s\n", (char *)coherent_buf);
	return 0;
    case IRQ_DUMP:
	pr_info("[irq_dump] Dumping IRQ handlers:\n");
	pr_info("[irq_dump] nr_irq: %d\n",nr_irqs);
    	for (irq = 0; irq < nr_irqs; irq++) {
        	desc = irq_to_desc(irq);
        	if (!desc)
            		continue;
		pr_info("[irq_dump] IRQ %d: handler=%p\n",
                                irq, desc->handle_irq);	
        	for (action = desc->action; action != NULL; action = action->next) {
			char sym[KSYM_NAME_LEN];
            		sprint_symbol(sym, (unsigned long)action->handler);
            		pr_info("[irq_dump] IRQ %d: action_handler=%p(%s), name=%s\n",
                    		irq, action->handler, sym, action->name ? action->name : "(null)");
        	}
    	}
	return 0;
    case IDT_DUMP:
    	// 获取 IDT 地址
    	asm volatile("sidt %0" : "=m"(idtr));
    	idt = (struct gate_desc *)idtr.address;

    	pr_info("[idt_dump] Dumping IDT entries (base=%px, entries=%d):\n", idt, IDT_ENTRIES);

    	for (i = 0; i < IDT_ENTRIES; i++) {
        	unsigned long addr = get_gate_offset(&idt[i]);
        	// const char *name = kallsyms_lookup(addr, NULL, NULL, NULL, NULL);

        	if (addr == 0)
            		continue;
        	pr_info("[idt_dump] Vector %3d: address=%px\n", i, (void *)addr);
    	}

    	return 0;	
    case INJECT_IRQ_TEST:
	irq = 33;
	pr_info("before inject");
	kvm_hypercall1(KVM_HC_INJECT_IRQ, irq);
    	pr_info("After triggering");

    	return 0;

    case PREPARE_DATA:
	if (fuzz_tdx_input == NULL || copy_from_user(fuzz_tdx_input, (void __user *)arg, sizeof(fuzz_input)))
            return -EFAULT;
        pr_info("prepare data: msr_data: %s;\ncpuid_data: %s\npio_data: %s\n mmio_data: %s\ndma_data: %s\n", fuzz_tdx_input->msr_data, fuzz_tdx_input->cpuid_data, fuzz_tdx_input->pio_data, fuzz_tdx_input->mmio_data, fuzz_tdx_input->dma_data);
        
	kvm_hypercall1(KVM_HC_PREPARE_DATA, __pa(fuzz_tdx_input));
	memcpy(tdx_fuzz_dma_data, fuzz_tdx_input->dma_data, DMA_BUF_LEN);
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
