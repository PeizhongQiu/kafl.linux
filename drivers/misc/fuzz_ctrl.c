#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <uapi/linux/kvm_para.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/dma-direct.h>
#include <asm/tdx.h>

#define DEVICE_NAME "fuzz_ctrl"
#define CLASS_NAME  "fuzz"

#define FUZZ_MAGIC   0xF5
#define FUZZ_ENABLE  _IOW(FUZZ_MAGIC, 0x01, int)
#define FUZZ_DISABLE _IO(FUZZ_MAGIC, 0x02)
#define READ_PORT8  _IOW(FUZZ_MAGIC, 4, int)
#define READ_PORT16 _IOW(FUZZ_MAGIC, 5, int)
#define READ_PORT32 _IOW(FUZZ_MAGIC, 6, int)
#define ALLOC_DMA _IO(FUZZ_MAGIC, 0x03)

static dev_t dev_num;
static struct cdev fuzz_cdev;
static struct class *fuzz_class = NULL;
static struct device *fuzz_device = NULL;
static struct device *dma_dev;
static void *coherent_buf;
static dma_addr_t coherent_dma_handle;
#define BUF_SIZE 4096

extern int tdx_fuzz_target;

static long fuzz_ctrl_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int target;
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
