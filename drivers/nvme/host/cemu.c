#include <linux/cdev.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci-p2pdma.h>

#include "cemu.h"

#define CEMU_DEVICE_NAME	"cemu"
#define CEMU_MAX_MINOR		64
#define CEMU_SLM_BAR		2

static int cemu_major;
static int cemu_minor;
static struct class *cemu_class;
static struct cemu_device_data *cemu_dev_data[CEMU_MAX_MINOR];

struct cemu_device_data {
	struct cdev cdev;
	int minor;
	size_t size;
	void __iomem *bar2_addr;
};

static int cemu_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	struct cemu_device_data *dev = filp->private_data;

	if (size > dev->size) {
		return -EINVAL;
	}

	printk(KERN_INFO "CEMU CSD mmap called, size: %ld, pfn: %lx\n",
		size, vmalloc_to_pfn(dev->bar2_addr));
	// vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	return remap_pfn_range(vma,
				vma->vm_start,
				vmalloc_to_pfn(dev->bar2_addr),
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot) ? -EAGAIN : 0;
}

static int cemu_dev_open(struct inode *inode, struct file *filp)
{
	struct cemu_device_data *dev = container_of(inode->i_cdev, struct cemu_device_data, cdev);
	filp->private_data = dev; // For other methods to have access to the device
	return 0;
}

static ssize_t cemu_read(struct file *filp, char __user *buf, size_t size, loff_t *off)
{
	return size;
}

static ssize_t cemu_write(struct file *filp, const char __user *buf, size_t size, loff_t *off)
{
	return size;
}

static struct file_operations cemu_fops = {
	.owner = THIS_MODULE,
	.open = cemu_dev_open,
	.read = cemu_read,
	.write = cemu_write,
	.mmap = cemu_dev_mmap,
};

int cemu_dev_add(struct pci_dev *pdev, struct nvme_ctrl *ctrl)
{
	struct cemu_device_data *dev_data;
	int err;

	printk(KERN_INFO "CEMU cemu_dev_add\n");

	dev_data = kzalloc(sizeof(struct cemu_device_data), GFP_KERNEL);
	if (!dev_data) {
		return -ENOMEM;
	}

	dev_data->size = pci_resource_len(pdev, CEMU_SLM_BAR);
	// dev_data->bar2_addr = pci_iomap(pdev, CEMU_SLM_BAR, dev_data->size);
	// if (!dev_data->bar2_addr) {
	// 	kfree(dev_data);
	// 	return -EIO;
	// }

	printk(KERN_INFO "CEMU CSD bar 2 size: %zu\n", dev_data->size);

	err = pci_p2pdma_add_resource(pdev, CEMU_SLM_BAR, 0, 0);
	if (err) {
		printk(KERN_ERR "CEMU CSD p2pdma add resource failed\n");
		return err;
	}

	printk(KERN_INFO "CEMU p2pdma added!\n");

	// printk(KERN_INFO "CEMU CSD bar 2 size: %zu, addr: %p, phy addr: %llu\n",
	// 	dev_data->size, dev_data->bar2_addr,
	// 	virt_to_phys(dev_data->bar2_addr));

	cdev_init(&dev_data->cdev, &cemu_fops);
	dev_data->cdev.owner = THIS_MODULE;

	dev_data->minor = cemu_minor++;
	err = cdev_add(&dev_data->cdev, MKDEV(cemu_major, dev_data->minor), 1);
	if (err) {
		pci_iounmap(pdev, dev_data->bar2_addr);
		kfree(dev_data);
		return err;
	}

	device_create(cemu_class, &pdev->dev,
			MKDEV(cemu_major, dev_data->minor), NULL,
			"cemu%d", dev_data->minor);

	printk(KERN_INFO "CEMU cemu_dev_add: add /dev/cemu%d\n", dev_data->minor);
	cemu_dev_data[dev_data->minor] = dev_data;
	ctrl->cemu_dev_data = dev_data;

	return 0;
}
EXPORT_SYMBOL_GPL(cemu_dev_add);

void cemu_dev_remove(struct pci_dev *pdev, struct nvme_ctrl *ctrl)
{
	struct cemu_device_data *dev_data = (struct cemu_device_data*)ctrl->cemu_dev_data;

	printk(KERN_INFO "CEMU cemu_dev_remove\n");
	cemu_dev_data[dev_data->minor] = NULL;
	device_destroy(cemu_class, MKDEV(cemu_major, dev_data->minor));
	cdev_del(&dev_data->cdev);
	pci_iounmap(pdev, dev_data->bar2_addr);
	kfree(dev_data);
}
EXPORT_SYMBOL_GPL(cemu_dev_remove);

static int __init cemu_init(void)
{
	int result;

	result = register_chrdev(0, CEMU_DEVICE_NAME, &cemu_fops);
	if (result < 0)
		return result;

	cemu_major = result;
	cemu_minor = 0;

	cemu_class = class_create(CEMU_DEVICE_NAME);
	if (IS_ERR(cemu_class)) {
		unregister_chrdev(cemu_major, CEMU_DEVICE_NAME);
		return PTR_ERR(cemu_class);
	}

	return 0;
}

static void __exit cemu_exit(void)
{
	class_destroy(cemu_class);
	unregister_chrdev(cemu_major, CEMU_DEVICE_NAME);
}

module_init(cemu_init);
module_exit(cemu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiuyang Zhang");
MODULE_DESCRIPTION("CEMU CSD Driver");
