#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>

#define DEVICE_NAME "fuzz_ctrl"
#define CLASS_NAME  "fuzz"

#define FUZZ_MAGIC   0xF5
#define FUZZ_ENABLE  _IO(FUZZ_MAGIC, 0x01)
#define FUZZ_DISABLE _IO(FUZZ_MAGIC, 0x02)

static dev_t dev_num;
static struct cdev fuzz_cdev;
static struct class *fuzz_class = NULL;
static struct device *fuzz_device = NULL;

static long fuzz_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    switch (cmd) {
        case FUZZ_ENABLE:
            pr_info("fuzz_ctrl: Request to ENABLE fuzz\n");
            asm volatile("vmcall" ::: "memory");
            break;

        case FUZZ_DISABLE:
            pr_info("fuzz_ctrl: Request to DISABLE fuzz\n");
            asm volatile("vmcall" ::: "memory");
            break;

        default:
            return -EINVAL;
    }

    return 0;
}

static struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = fuzz_ioctl,
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
