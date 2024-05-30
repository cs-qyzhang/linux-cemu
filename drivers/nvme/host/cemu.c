#include <linux/blkdev.h>
#include <linux/dma-mapping.h>
#include <linux/pci.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/pci-p2pdma.h>
#include <linux/list.h>
#include <linux/io_uring/cmd.h>

#include "cemu.h"
#include "../../../fs/fdmfs/fdmfs.h"

#define CEMU_BLKDEV_NAME	"cemu"
#define CEMU_CHRDEV_NAME	"cemuc"
#define CEMU_MAX_MINOR		64
#define CEMU_SLM_BAR		2
#define to_sysfs_program(x)	container_of(x, struct sysfs_program, attr)

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
	int cur_pind;
	int cur_rsid;
	struct list_head prog_list;
};

struct sysfs_program {
	struct kobj_attribute attr;
	struct list_head list;
	int pind;
	int ptype;
	int is_active;
	size_t size;
	const char *name;
};

static int bdev_major;
static int bdev_minor;
static int cdev_major;
static int cdev_minor;
static struct class *bdev_class;
static struct class *cdev_class;
static struct cemu_dev *cemu_bdev[CEMU_MAX_MINOR];

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

static void cemu_bdev_submit_bio(struct bio *bio)
{
	struct cemu_dev *dev = bio->bi_bdev->bd_disk->private_data;

	// printk(KERN_INFO "cemu_bdev_submit_bio: len %u, offset %u, sector %llu\n", bio->bi_io_vec->bv_len, bio->bi_io_vec->bv_offset, bio->bi_iter.bi_sector);

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

const struct block_device_operations cemu_bdev_ops =
{
	.owner		= THIS_MODULE,
	.submit_bio	= cemu_bdev_submit_bio,
	.open		= cemu_bdev_open,
	.release	= cemu_bdev_release,
};


/********************* Char Device *********************/
void cemu_bio_end_io(struct bio *bio)
{
	struct cemu_bio *cio = bio->bi_private;
	if (bio->bi_status)
		cio->error = bio->bi_status;

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

static ssize_t cemu_sysfs_show(struct kobject *kobj,
		struct kobj_attribute *attr, char *buf)
{
	struct sysfs_program *program = to_sysfs_program(attr);
	return sprintf(buf, "%s %d %d %d %ld\n", program->name,
		program->pind, program->ptype, program->is_active, program->size);
}

static struct sysfs_program *find_program_by_id(struct cemu_dev *dev, int pind)
{
	struct sysfs_program *prog = NULL;
	list_for_each_entry(prog, &dev->prog_list, list) {
		if (prog->pind == pind) {
			return prog;
		}
	}
	return NULL;
}

static struct sysfs_program *find_program_by_name(struct cemu_dev *dev, const char *name)
{
	struct sysfs_program *prog = NULL;
	list_for_each_entry(prog, &dev->prog_list, list) {
		if (strcmp(prog->name, name) == 0) {
			return prog;
		}
	}
	return NULL;
}

static int cemu_load_program(struct cemu_dev *dev, unsigned long arg)
{
	struct ioctl_download download;
	if (copy_from_user(&download, (void *)arg, sizeof(download)))
		return -EFAULT;

	char prog_name[256];
	int ret = strncpy_from_user((char *)prog_name, download.name, 256);
	if (ret < 0 || ret >= 256)
		return -EFAULT;

	// TODO: LOCK
	struct sysfs_program *prog = find_program_by_name(dev, prog_name);
	if (prog) {
		if (copy_to_user(&((struct ioctl_download *)arg)->pind,
				&prog->pind, sizeof(prog->pind))) {
			printk(KERN_ERR "CEMU CSD copy_to_user failed\n");
		}
		printk(KERN_ERR "CEMU CSD program %s already exists\n", prog_name);
		return -EEXIST;
	}

	struct iov_iter iter;
	iov_iter_ubuf(&iter, ITER_SOURCE, (void __user *)download.addr, download.size);

	struct cemu_bio *cio = kzalloc(sizeof(*cio), GFP_KERNEL);
	cio->submit.waiter = current;
	cio->submit.iter = &iter;
	cio->wait_for_completion = true;
	cio->error = 0;
	cio->pind = dev->cur_pind++;
	cio->psize = download.size;
	cio->jit = download.jit;
	cio->runtime = download.runtime;
	cio->runtime_scale = download.runtime_scale;
	cio->ptype = download.ptype;
	cio->indirect = download.indirect;
	cio->sel = 0;
	atomic_set(&cio->ref, 1);

	size_t count = iov_iter_count(&iter);
	printk(KERN_INFO "cemu_bdev_ioctl: addr %p, size %x, iov_iter_count %lu\n", download.addr, download.size, count);

	/* borrowed from iomap */
	int nr_pages = bio_iov_vecs_to_alloc(&iter, BIO_MAX_VECS);
	// bio_opf = REQ_OP_WRITE;
	blk_opf_t bio_opf = REQ_OP_LOAD_PROGRAM;
	size_t copied = 0;

	struct blk_plug plug;
	blk_start_plug(&plug);
	do {
		struct bio *bio = bio_alloc(dev->disk->part0, nr_pages, bio_opf, GFP_KERNEL);
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
		copied += n;
		nr_pages = bio_iov_vecs_to_alloc(&iter, BIO_MAX_VECS);
		atomic_inc(&cio->ref);
		submit_bio(bio);
	} while (nr_pages);
	blk_finish_plug(&plug);

	if (!atomic_dec_and_test(&cio->ref)) {
		for (;;) {
			set_current_state(TASK_UNINTERRUPTIBLE);
			if (!READ_ONCE(cio->submit.waiter))
				break;

			blk_io_schedule();
		}
		__set_current_state(TASK_RUNNING);
	}

out:
	if (cio->error) {
		printk(KERN_ERR "CEMU CSD load program failed\n");
		return cio->error;
	}
	if (copied) {
		// create sysfs entry
		prog = kzalloc(sizeof(struct sysfs_program), GFP_KERNEL);
		struct kobj_attribute *attr = &prog->attr;
		sysfs_attr_init(attr);
		attr->attr.mode = 0440;
		attr->attr.name = kstrdup((char *)prog_name, GFP_KERNEL);
		attr->show = cemu_sysfs_show;
		prog->name = attr->attr.name;
		prog->is_active = 0;
		prog->pind = cio->pind++;
		prog->ptype = download.ptype;
		prog->size = download.size;
		list_add(&prog->list, &dev->prog_list);
		ret = sysfs_create_file(dev->sys_fs, &attr->attr);
		if (ret)
			pr_err("CEMU CSD sysfs_create_file failed\n");

		if (copy_to_user(&((struct ioctl_download *)arg)->pind,
				&prog->pind, sizeof(prog->pind))) {
			printk(KERN_ERR "CEMU CSD copy_to_user failed\n");
		}
		return copied;
	}
	return ret;
}

static int cemu_program_activation(struct cemu_dev *dev, unsigned long arg)
{
	struct ioctl_download download;
	if (copy_from_user(&download, (void *)arg, sizeof(download)))
		return -EFAULT;

	struct sysfs_program *prog = find_program_by_id(dev, download.pind);
	if (!prog)
		return -ENOENT;

	struct nvme_command cmd = {};
	cmd.activation.nsid = 3;
	cmd.activation.opcode = 0x23;
	cmd.activation.pind = download.pind;
	cmd.activation.sel = 1;
	int ret = nvme_submit_sync_cmd(dev->admin_q, &cmd, NULL, 0);
	if (ret == 0)
		prog->is_active = 1;
	return ret;
}

static int cemu_program_execute(struct cemu_dev *dev, unsigned long arg)
{
	struct ioctl_execute execute;
	if (copy_from_user(&execute, (void *)arg, sizeof(execute)))
		return -EFAULT;

	struct sysfs_program *prog = find_program_by_id(dev, execute.pind);
	if (!prog)
		return -ENOENT;

	if (prog->is_active == 0)
		return -EINVAL;

	return 0;
}

static int cemu_create_mrs(struct cemu_dev *dev, unsigned long arg)
{
	struct ioctl_create_mrs create;
	if (copy_from_user(&create, (void *)arg, sizeof(create)))
		return -EFAULT;
	if (create.nr_fd <= 0 || create.nr_fd >= 128)
		return -EINVAL;

	void *buf = kmalloc((sizeof(int) * create.nr_fd) +
				(sizeof(long long) * create.nr_fd * 2) +
				(sizeof(struct nvme_memory_range) * create.nr_fd),
				GFP_KERNEL);
	int *mr_fd = buf;
	long long *off = buf + sizeof(int) * create.nr_fd;
	long long *size = (void *)off + sizeof(long long) * create.nr_fd;
	struct nvme_memory_range *mr = (void *)size + sizeof(long long) * create.nr_fd;
	int ret = -EFAULT;
	if (copy_from_user(mr_fd, create.fd, sizeof(int) * create.nr_fd))
		goto err;
	if (copy_from_user(off, create.off, sizeof(long long) * create.nr_fd))
		goto err;
	if (copy_from_user(size, create.size, sizeof(long long) * create.nr_fd))
		goto err;
	ret = 0;

	for (int i = 0; i < create.nr_fd; i++) {
		struct file *file = fget(mr_fd[i]);
		ret = fdmfs_get_memory_range(file, &mr[i]);
		if (ret) {
			pr_err("CEMU CSD fdmfs_get_memory_range failed\n");
			goto err;
		}
		if (mr[i].len < off[i] + size[i]) {
			pr_err("CEMU CSD ioctl cemu_create_mrs: off+size bigger than fd %d's size!", mr_fd[i]);
			goto err;
		}
		mr[i].sb += off[i];
		if (size[i] == 0)
			mr[i].len -= off[i];
		else
			mr[i].len = size[i];
	}

	union nvme_result result;
	struct nvme_command cmd = {};
	cmd.mrs_manage.nsid = 3;
	cmd.mrs_manage.opcode = 0x21;
	cmd.mrs_manage.rsid = 0;
	cmd.mrs_manage.sel = 0;
	cmd.mrs_manage.numr = create.nr_fd;
	int mr_len = sizeof(struct nvme_memory_range) * create.nr_fd;
	ret = __nvme_submit_sync_cmd(dev->admin_q, &cmd, &result,
			mr, mr_len, NVME_QID_ANY, 0);
	if (ret != 0)
		goto err;
	uint16_t rsid = result.u16;
	if (copy_to_user(&((struct ioctl_create_mrs *)arg)->rsid, &rsid, sizeof(rsid)))
		ret = -EFAULT;
err:
	kfree(buf);
	return ret;
}

static long cemu_cdev_ioctl(struct file *filp, unsigned int ioctl_cmd,
		unsigned long arg)
{
	struct cemu_dev *dev = filp->private_data;
	printk(KERN_INFO "cemu_cdev_ioctl\n");

	switch (ioctl_cmd) {
	case IOCTL_CEMU_DOWNLOAD:
		return cemu_load_program(dev, arg);
	case IOCTL_CEMU_ACTIVATE:
		return cemu_program_activation(dev, arg);
	case IOCTL_CEMU_EXECUTE:
		return cemu_program_execute(dev, arg);
	case IOCTL_CEMU_CREATE_MRS:
		return cemu_create_mrs(dev, arg);
	default:
		printk(KERN_ERR "CEMU CSD ioctl: unknown ioctl cmd %d!!!\n", ioctl_cmd);
		return -ENOTTY;
	}
}

static int cemu_cdev_open(struct inode *inode, struct file *filp)
{
	struct cemu_dev *dev = container_of(inode->i_cdev, struct cemu_dev, cdev);
	filp->private_data = dev;
	pr_info("cemu_cdev_open\n");
	return 0;
}

static void cemu_uring_task_cb(struct io_uring_cmd *ioucmd,
			       unsigned issue_flags)
{
	io_uring_cmd_done(ioucmd, 0, 0, issue_flags);
}

static void uring_bio_end_io(struct bio *bio)
{
	struct cemu_bio *cio = bio->bi_private;
	if (bio->bi_status)
		cio->error = bio->bi_status;
	struct io_uring_cmd *ioucmd = cio->cmd;

	bio_release_pages(bio, false);
	bio_put(bio);
	io_uring_cmd_do_in_task_lazy(ioucmd, cemu_uring_task_cb);
}

static int program_execute(struct cemu_dev *dev, struct io_uring_cmd *ioucmd)
{
	// const struct ioctl_execute *execute = io_uring_sqe_cmd(ioucmd->sqe);

	struct sysfs_program *prog = find_program_by_id(dev, 1);
	if (!prog)
		return -ENOENT;

	if (prog->is_active == 0)
		return -EINVAL;

	struct cemu_bio *cio = kzalloc(sizeof(*cio), GFP_KERNEL);
	cio->wait_for_completion = false;
	cio->error = 0;
	cio->pind = 1;

	blk_opf_t bio_opf = REQ_OP_PROGRAM_EXECUTE;
	struct bio *bio = bio_alloc(dev->disk->part0, 0, bio_opf, GFP_KERNEL);
	if (bio == NULL) {
		pr_err("bio_alloc failed\n");
		return -ENOMEM;
	}
	bio->bi_ioprio = 0;
	bio->bi_private = cio;
	bio->bi_end_io = uring_bio_end_io;

	submit_bio(bio);
	return -EIOCBQUEUED;
}

static int cemu_cdev_uring_cmd(struct io_uring_cmd *ioucmd, unsigned int issue_flags)
{
	struct cemu_dev *dev = ioucmd->file->private_data;
	pr_info("cemu_cdev_uring_cmd\n");

	if (issue_flags & IO_URING_F_IOPOLL)
		return -EOPNOTSUPP;

	int ret;
	switch (ioucmd->cmd_op) {
	case IOCTL_CEMU_EXECUTE:
		ret = program_execute(dev, ioucmd);
		break;
	default:
		ret = -ENOTTY;
		break;
	}

	return ret;
}

static struct file_operations cdev_fops = {
	.owner		= THIS_MODULE,
	.open		= cemu_cdev_open,
	.uring_cmd	= cemu_cdev_uring_cmd,
	.unlocked_ioctl	= cemu_cdev_ioctl,
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

	disk->major = bdev_major;
	disk->first_minor = dev->minor;
	disk->minors = 1;
	disk->fops = &cemu_bdev_ops;
	disk->private_data = dev;
	sprintf(disk->disk_name, "cemu%d", dev->minor);
	blk_set_stacking_limits(&disk->queue->limits);
	disk->queue->limits.logical_block_size = 1;	// required for load program, since program size is arbitrary
	disk->queue->limits.physical_block_size = 1;
	set_capacity(disk, dev->size / SECTOR_SIZE);

	// enable IOURING_IOPOLL
	blk_queue_flag_set(QUEUE_FLAG_POLL, disk->queue);

	printk(KERN_INFO "CEMU cemu_dev_add start device_add_disk\n");
	err = add_disk(disk);
	if (err)
		return err;

	dev->disk = disk;
	dev->rq = disk->queue;
	cemu_bdev[dev->minor] = dev;
	ctrl->cemu_dev = dev;
	ctrl->cemu_p2p_start = dev->p2p_addr;
	ctrl->cemu_p2p_end = ctrl->cemu_p2p_start + dev->size;

	// create /sys/fs for compute namespace
	dev->sys_fs = kobject_create_and_add(disk->disk_name, fs_kobj);
	dev->cur_pind = 1;
	dev->cur_rsid = 1;
	if (!dev->sys_fs)
		return -ENOMEM;
	INIT_LIST_HEAD(&dev->prog_list);

	printk(KERN_INFO "CEMU cemu_dev_add: add /dev/cemu%d\n", dev->minor);

	/* Add char device for compute namespace */
	cdev_init(&dev->cdev, &cdev_fops);
	dev->cdev.owner = THIS_MODULE;

	err = cdev_add(&dev->cdev, MKDEV(cdev_major, dev->minor), 1);
	if (err)
		return err;

	device_create(cdev_class, &pdev->dev,
			MKDEV(cdev_major, dev->minor), NULL,
			"cemuc%d", dev->minor);

	printk(KERN_INFO "CEMU cemu_dev_add: add /dev/cemuc%d\n", dev->minor);
	return 0;
}
EXPORT_SYMBOL_GPL(cemu_dev_add);

void cemu_dev_remove(struct pci_dev *pdev, struct nvme_ctrl *ctrl)
{
	struct cemu_dev *dev = (struct cemu_dev*)ctrl->cemu_dev;

	printk(KERN_INFO "CEMU cemu_dev_remove\n");
	cemu_bdev[dev->minor] = NULL;
	dma_unmap_sg(ctrl->dev, dev->dma_sgl, dev->sgl_nents, DMA_BIDIRECTIONAL);
	pci_p2pmem_free_sgl(pdev, dev->dma_sgl);
	kobject_put(dev->sys_fs);
	device_destroy(cdev_class, MKDEV(cdev_major, dev->minor));
	cdev_del(&dev->cdev);
	kfree(dev);
}
EXPORT_SYMBOL_GPL(cemu_dev_remove);

static int __init cemu_init(void)
{
	bdev_major = register_blkdev(0, CEMU_BLKDEV_NAME);
	bdev_minor = 0;

	cdev_major = register_chrdev(0, CEMU_CHRDEV_NAME, &cdev_fops);
	cdev_minor = 0;

	cdev_class = class_create(CEMU_CHRDEV_NAME);
	if (IS_ERR(cdev_class)) {
		unregister_chrdev(cdev_major, CEMU_CHRDEV_NAME);
		return PTR_ERR(cdev_class);
	}
	return 0;
}

static void __exit cemu_exit(void)
{
	class_destroy(bdev_class);
	unregister_blkdev(bdev_major, CEMU_BLKDEV_NAME);
	unregister_chrdev(cdev_major, CEMU_CHRDEV_NAME);
}

module_init(cemu_init);
module_exit(cemu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Qiuyang Zhang");
MODULE_DESCRIPTION("CEMU CSD Driver");
