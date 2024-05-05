#include <linux/blkdev.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci-p2pdma.h>

#include "cemu.h"

#define CEMU_BLKDEV_NAME	"cemu"
#define CEMU_MAX_MINOR		64
#define CEMU_SLM_BAR		2

struct cemu_dev {
	struct cdev cdev;
	struct gendisk *disk;
	struct request_queue *rq;
	struct request_queue *admin_q;
	struct device *dev;
	struct block_device *nvme_bdev;
	struct pci_dev *pdev;
	struct scatterlist *dma_sgl;
	int sgl_nents;
	int minor;
	size_t size;
	dma_addr_t p2p_addr;
	struct kobject *sys_fs;
};

static int cemu_major;
static int cemu_minor;
static struct class *cemu_class;
static struct cemu_dev *cemu_dev[CEMU_MAX_MINOR];

size_t cemu_dev_get_size(struct block_device *bdev)
{
	struct cemu_dev *dev = bdev->bd_disk->private_data;
	return dev->size;
}

void *cemu_dev_get_p2p_addr(struct block_device *bdev)
{
	struct cemu_dev *dev = bdev->bd_disk->private_data;
	return (void *)phys_to_virt(dev->p2p_addr);
}

static int cemu_dev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	size_t size = vma->vm_end - vma->vm_start;
	struct cemu_dev *dev = filp->private_data;
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

static int cemu_bdev_open(struct gendisk *bdev, blk_mode_t mode)
{
	printk(KERN_INFO "CEMU CSD cemu_blkdev_open\n");
	return 0;
}

static void cemu_bdev_release(struct gendisk *disk)
{
	printk(KERN_INFO "CEMU CSD cemu_blkdev_release\n");
}

struct cemu_bio {
	atomic_t		ref;
	unsigned		flags;
	int			error;
	size_t			done_before;
	bool			wait_for_completion;

	union {
		/* used during submission and for synchronous completion: */
		struct {
			struct iov_iter		*iter;
			struct task_struct	*waiter;
		} submit;

		/* used for aio completion: */
		struct {
			struct work_struct	work;
		} aio;
	};
};

static void cemu_bio_end_io(struct bio *bio)
{
	struct cemu_bio *cio = bio->bi_private;
	if (!atomic_dec_and_test(&cio->ref))
		goto release_bio;
	if (cio->wait_for_completion) {
		struct task_struct *waiter = cio->submit.waiter;

		WRITE_ONCE(cio->submit.waiter, NULL);
		blk_wake_io_task(waiter);
		goto release_bio;
	}
release_bio:
	bio_release_pages(bio, false);
	bio_put(bio);
}

static void cemu_bdev_submit_bio(struct bio *bio)
{
	struct cemu_dev *dev = bio->bi_bdev->bd_disk->private_data;

	printk(KERN_INFO "cemu_bdev_submit_bio: len %u, offset %u, sector %llu\n", bio->bi_io_vec->bv_len, bio->bi_io_vec->bv_offset, bio->bi_iter.bi_sector);

	if (dev == NULL) {
		bio_io_error(bio);
		return;
	}

	// /* bio could be mergeable after passing to underlayer */
	// bio->bi_opf &= ~REQ_NOMERGE;

	bio_set_dev(bio, dev->nvme_bdev);
	bio_set_flag(bio, BIO_NVME_MEMORY_CMD);
	bio = bio_split_to_limits(bio);
	if (!bio)
		return;
	submit_bio_noacct(bio);
}

enum {
	IOCTL_CEMU_DOWNLOAD,
	IOCTL_CEMU_ACTIVATE,
	IOCTL_CEMU_EXECUTE,
};

struct cemu_download {
	uint64_t addr;
	uint64_t size;
};

static int cemu_bdev_ioctl(struct block_device *bdev, blk_mode_t mode,
		unsigned ioctl_cmd, unsigned long arg)
{
	struct cemu_dev *dev = bdev->bd_disk->private_data;

	printk(KERN_INFO "cemu_bdev_ioctl\n");

	struct cemu_download download;
	if (copy_from_user(&download, (void *)arg, sizeof(download)))
		return -EFAULT;

	struct bio *bio;
	struct iov_iter iter;
	struct cemu_bio *cio = kzalloc(sizeof(*cio), GFP_KERNEL);
	cio->submit.waiter = current;
	cio->submit.iter = &iter;
	blk_opf_t bio_opf;
	iov_iter_ubuf(&iter, ITER_SOURCE, (void __user *)download.addr, download.size);

	loff_t pos = 0;
	size_t count = iov_iter_count(&iter);
	printk(KERN_INFO "cemu_bdev_ioctl: addr %llx, size %llx, iov_iter_count %lu\n", download.addr, download.size, count);
	size_t copied = 0;
	int ret = 0;

	int nr_pages = bio_iov_vecs_to_alloc(&iter, BIO_MAX_VECS);
	// bio_opf = REQ_OP_WRITE;
	bio_opf = REQ_OP_LOAD_PROGRAM;
	do {
		bio = bio_alloc(dev->disk->part0, nr_pages, bio_opf, GFP_KERNEL);
		bio->bi_iter.bi_sector = 0;
		bio->bi_ioprio = 0;
		bio->bi_private = cio;
		bio->bi_end_io = cemu_bio_end_io;
		ret = bio_iov_iter_get_pages(bio, &iter);
		if (unlikely(ret)) {
			/*
			 * We have to stop part way through an IO. We must fall
			 * through to the sub-block tail zeroing here, otherwise
			 * this short IO may expose stale data in the tail of
			 * the block we haven't written data to.
			 */
			bio_put(bio);
			goto out;
		}

		size_t n = bio->bi_iter.bi_size;
		printk(KERN_INFO "cemu_bdev_ioctl: bio size %lu\n", n);
		copied += n;
		nr_pages = bio_iov_vecs_to_alloc(&iter, BIO_MAX_VECS);
		atomic_inc(&cio->ref);
		submit_bio(bio);
		pos += n;
	} while (nr_pages);

out:
	if (copied)
		return copied;
	return ret;
}

const struct block_device_operations cemu_bdev_ops =
{
	.owner		= THIS_MODULE,
	.submit_bio	= cemu_bdev_submit_bio,
	.open		= cemu_bdev_open,
	.release	= cemu_bdev_release,
	.ioctl 		= cemu_bdev_ioctl,
};

static int cemu_p2pmem_setup(struct pci_dev *pdev, struct cemu_dev *dev)
{
	struct scatterlist *sgl;
	int nents;
	int err;

	dev->size = pci_resource_len(pdev, CEMU_SLM_BAR);
	printk(KERN_INFO "CEMU CSD bar 2 size: %zu\n", dev->size);

	err = pci_p2pdma_add_resource(pdev, CEMU_SLM_BAR, dev->size, 0);
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
		printk(KERN_INFO "CEMU CSD sgl[%d]: dma_address: %p, length: %u, page_link: %lu\n", i, (void*)sgl[i].dma_address, sgl[i].length, sgl[i].page_link);
		printk(KERN_INFO "CEMU CSD sgl[%d]: offset: %u, dma_flags: %u\n", i, sgl[i].offset, sgl[i].dma_flags);
	}

	dev->dma_sgl = sgl;
	dev->sgl_nents = nents;
	dev->p2p_addr = dev->dma_sgl[0].dma_address;

	return 0;
}

int cemu_dev_add(struct pci_dev *pdev, struct nvme_ctrl *ctrl)
{
	struct cemu_dev *dev;
	struct gendisk *disk;
	struct nvme_ns *ns;
	int err;

	printk(KERN_INFO "CEMU cemu_dev_add\n");

	dev = kzalloc(sizeof(struct cemu_dev), GFP_KERNEL);
	if (!dev) {
		return -ENOMEM;
	}
	dev->pdev = pdev;

	ns = nvme_find_get_ns(ctrl, 1);	// FIXME: nsid
	if (ns == NULL) {
		printk(KERN_ERR "CEMU cemu_dev_add: nvme_find_get_ns failed\n");
	}
	dev->nvme_bdev = ns->disk->part0;
	dev->admin_q = ctrl->admin_q;

	cemu_p2pmem_setup(pdev, dev);

	printk(KERN_INFO "CEMU cemu_dev_add start alloc_disk\n");
	disk = blk_alloc_disk(ctrl->numa_node);
	if (IS_ERR(disk)) {
		return PTR_ERR(disk);
	}

	disk->major = cemu_major;
	disk->first_minor = dev->minor;
	disk->minors = 1;
	disk->fops = &cemu_bdev_ops;
	disk->private_data = dev;
	sprintf(disk->disk_name, "cemu%d", dev->minor);
	blk_set_stacking_limits(&disk->queue->limits);
	disk->queue->limits.logical_block_size = 1;	// required for load program, since program size is arbitrary
	disk->queue->limits.physical_block_size = 1;
	set_capacity(disk, dev->size / SECTOR_SIZE);
	// blk_queue_write_cache(disk->queue, true, true);

	// blk_queue_flag_set(QUEUE_FLAG_NONROT, disk->queue);
	// blk_queue_flag_set(QUEUE_FLAG_PCI_P2PDMA, disk->queue);

	printk(KERN_INFO "CEMU cemu_dev_add start device_add_disk\n");
	err = add_disk(disk);
	if (err)
		return err;

	dev->disk = disk;
	dev->rq = disk->queue;
	cemu_dev[dev->minor] = dev;
	ctrl->cemu_dev = dev;
	ctrl->cemu_p2p_start = dev->p2p_addr;
	ctrl->cemu_p2p_end = ctrl->cemu_p2p_start + dev->size;

	// create /sys/fs for compute namespace
	dev->sys_fs = kobject_create_and_add(disk->disk_name, fs_kobj);
	if (!dev->sys_fs)
		return -ENOMEM;

	printk(KERN_INFO "CEMU cemu_dev_add: add /dev/cemu%d\n", dev->minor);
	return 0;
}
EXPORT_SYMBOL_GPL(cemu_dev_add);

void cemu_dev_remove(struct pci_dev *pdev, struct nvme_ctrl *ctrl)
{
	struct cemu_dev *dev = (struct cemu_dev*)ctrl->cemu_dev;

	printk(KERN_INFO "CEMU cemu_dev_remove\n");
	cemu_dev[dev->minor] = NULL;
	dma_unmap_sg(ctrl->dev, dev->dma_sgl, dev->sgl_nents, DMA_BIDIRECTIONAL);
	pci_p2pmem_free_sgl(pdev, dev->dma_sgl);
	kobject_put(dev->sys_fs);
	kfree(dev);
}
EXPORT_SYMBOL_GPL(cemu_dev_remove);

static int __init cemu_init(void)
{
	cemu_major = register_blkdev(0, CEMU_BLKDEV_NAME);
	cemu_minor = 0;
	return 0;
}

static void __exit cemu_exit(void)
{
	class_destroy(cemu_class);
	unregister_blkdev(cemu_major, CEMU_BLKDEV_NAME);
}

module_init(cemu_init);
module_exit(cemu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiuyang Zhang");
MODULE_DESCRIPTION("CEMU CSD Driver");
