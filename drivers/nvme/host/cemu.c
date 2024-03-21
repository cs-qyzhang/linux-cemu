#include <linux/cdev.h>
#include <linux/dma-mapping.h>
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
	struct device *dev;
	struct pci_dev *pdev;
	struct scatterlist *dma_sgl;
	int sgl_nents;
	int minor;
	size_t size;
	dma_addr_t p2p_addr;
};

static int cemu_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	struct cemu_device_data *dev = filp->private_data;
	struct mm_struct *mm = current->mm;
	int err = 0;

	if (size > dev->size) {
		return -EINVAL;
	}

	printk(KERN_INFO "CEMU CSD mmap called, size: %ld, pfn: %llx\n",
		size, dev->p2p_addr >> PAGE_SHIFT);

	// vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	err = remap_pfn_range(vma,
				vma->vm_start,
				dev->p2p_addr >> PAGE_SHIFT,
				vma->vm_end - vma->vm_start,
				vma->vm_page_prot) ? -EAGAIN : 0;
	if (err) {
		printk(KERN_ERR "CEMU CSD remap_pfn_range failed!!!\n");
		return err;
	}

	// copied from xilinx XRT xocl driver, see xocl/userpf/xocl_drm.c:xocl_bo_map()
	vm_flags_clear(vma, VM_PFNMAP | VM_IO);
	vm_flags_set(vma, VM_MIXEDMAP | mm->def_flags);
	if (vma->vm_flags & (VM_READ | VM_MAYREAD))
		vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
	else
		vma->vm_page_prot = pgprot_writecombine(
			vm_get_page_prot(vma->vm_flags));

	return 0;
}

static int cemu_dev_open(struct inode *inode, struct file *filp)
{
	struct cemu_device_data *dev = container_of(inode->i_cdev, struct cemu_device_data, cdev);
	filp->private_data = dev; // For other methods to have access to the device
	return 0;
}

static ssize_t cemu_read(struct file *filp, char __user *buf, size_t size, loff_t *off)
{
	printk(KERN_INFO "CEMU CSD cemu_read, size: %ld, off: %lld\n", size, *off);
	*off += size;
	return size;
}

static ssize_t cemu_write(struct file *filp, const char __user *buf, size_t size, loff_t *off)
{
	printk(KERN_INFO "CEMU CSD cemu_write, size: %ld, off: %lld\n", size, *off);
	*off += size;
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
	struct scatterlist *sgl;
	int nents = 10;
	int err;

	printk(KERN_INFO "CEMU cemu_dev_add\n");

	dev_data = kzalloc(sizeof(struct cemu_device_data), GFP_KERNEL);
	if (!dev_data) {
		return -ENOMEM;
	}
	dev_data->pdev = pdev;

	dev_data->size = pci_resource_len(pdev, CEMU_SLM_BAR);
	printk(KERN_INFO "CEMU CSD bar 2 size: %zu\n", dev_data->size);

	err = pci_p2pdma_add_resource(pdev, CEMU_SLM_BAR, dev_data->size, 0);
	if (err) {
		printk(KERN_ERR "CEMU CSD p2pdma add resource failed\n");
		return err;
	}
	pci_p2pmem_publish(pdev, true);
	WARN(pci_has_p2pmem(pdev) == false, "CEMU CSD p2pmem not enabled!\n");

	int dis = pci_p2pdma_distance(pdev, &pdev->dev, true);
	printk(KERN_INFO "CEMU CSD p2pdma_distance %d\n", dis);

	sgl = pci_p2pmem_alloc_sgl(pdev, &nents, 4096);
	if (sgl == NULL) {
		printk(KERN_ERR "CEMU CSD pci_p2pmem_alloc_sgl failed\n");
	}
	printk(KERN_INFO "CEMU CSD sgl: %p, nents: %d\n", sgl, nents);

	err = dma_map_sg(&pdev->dev, sgl, nents, DMA_BIDIRECTIONAL);
	if (err != nents) {
		printk(KERN_ERR "CEMU CSD dma_map_sg failed\n");
	}
	printk(KERN_INFO "CEMU CSD dma_map_sg success\n");
	for (int i = 0; i < nents; i++) {
		printk(KERN_INFO "CEMU CSD sgl[%d]: dma_address: %llu, length: %u, page_link: %lu\n", i, sgl[i].dma_address, sgl[i].length, sgl[i].page_link);
		printk(KERN_INFO "CEMU CSD sgl[%d]: offset: %u, dma_flags: %u\n", i, sgl[i].offset, sgl[i].dma_flags);
	}

	dev_data->dma_sgl = sgl;
	dev_data->sgl_nents = nents;
	dev_data->p2p_addr = dev_data->dma_sgl[0].dma_address;

	// create char device
	cdev_init(&dev_data->cdev, &cemu_fops);
	dev_data->cdev.owner = THIS_MODULE;

	dev_data->minor = cemu_minor++;
	err = cdev_add(&dev_data->cdev, MKDEV(cemu_major, dev_data->minor), 1);
	if (err) {
		dma_unmap_sg(ctrl->dev, dev_data->dma_sgl, dev_data->sgl_nents, DMA_BIDIRECTIONAL);
		pci_p2pmem_free_sgl(pdev, dev_data->dma_sgl);
		kfree(dev_data);
		return err;
	}

	dev_data->dev = device_create(cemu_class, &pdev->dev,
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
	dma_unmap_sg(ctrl->dev, dev_data->dma_sgl, dev_data->sgl_nents, DMA_BIDIRECTIONAL);
	pci_p2pmem_free_sgl(pdev, dev_data->dma_sgl);
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
