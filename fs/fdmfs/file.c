#include <linux/bio.h>
#include <linux/fs.h>
#include <linux/falloc.h>
#include <linux/iomap.h>

#include "fdmfs.h"

static int fdmfs_open(struct inode *inode, struct file *filp) {
	pr_info("FDMFS: open\n");
	filp->private_data = inode->i_private;
	return 0;
}

static int fdmfs_release(struct inode *inode, struct file *filp) {
	pr_info("FDMFS: close\n");
	return 0;
}

static ssize_t fdmfs_rw_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	pr_info("FDMFS: rw_iter, size %lu, off %llu\n", iov_iter_count(iter), iocb->ki_pos);
	if (iocb->ki_pos % 512) {
		pr_err("FDMFS: rw_iter require 512-aligned offset!\n");
		return -EINVAL;
	}
	struct inode *ino = file_inode(iocb->ki_filp);

	inode_lock_shared(ino);
	ssize_t ret = iomap_dio_rw(iocb, iter, &fdmfs_iomap_ops, NULL, 0, NULL, 0);
	inode_unlock_shared(ino);
	file_accessed(iocb->ki_filp);
	return ret;
}

ssize_t fdmfs_copy_file_range(struct file *file_in, loff_t pos_in,
				     struct file *file_out, loff_t pos_out,
				     size_t size, unsigned int flags)
{
	bool in_is_fdmfs = file_in->f_op == &fdmfs_fops;
	bool out_is_fdmfs = file_out->f_op == &fdmfs_fops;
	struct fdmfs_inode *inode = in_is_fdmfs ? file_in->private_data : file_out->private_data;
	struct kiocb kiocb;
	struct iov_iter iter;
	struct bio_vec bvec;
	ssize_t ret;

	pr_info("FDMFS: copy_file_range %zu bytes, pos_in %llu, pos_out %llu, in_is_fdmfs %d, out_is_fdmfs %d\n", size, pos_in, pos_out, in_is_fdmfs, out_is_fdmfs);

	if (in_is_fdmfs)
		init_sync_kiocb(&kiocb, file_out);
	else
		init_sync_kiocb(&kiocb, file_in);
	kiocb.ki_pos = pos_out;

	bvec_set_virt(&bvec, fdmfs_region_addr(inode) + pos_out, size);
	unsigned int dir = in_is_fdmfs ? ITER_SOURCE : ITER_DEST;
	iov_iter_bvec(&iter, dir, &bvec, 1, size);

	if (in_is_fdmfs)
		ret = call_write_iter(file_out, &kiocb, &iter);
	else
		ret = call_read_iter(file_in, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	return ret;
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

static long fdmfs_ioctl(struct file *file, unsigned int cmd,
			unsigned long arg)
{
	printk(KERN_INFO "FDMFS: fdmfs_ioctl, cmd %d, arg %lx\n", cmd, arg);

	struct cemu_download download;
	if (copy_from_user(&download, (void *)arg, sizeof(download)))
		return -EFAULT;
	void *user_code;
	struct iov_iter iter;
	struct kiocb kiocb;
	printk(KERN_INFO "FDMFS: fdmfs_ioctl, addr %llx, size %llx\n", download.addr, download.size);

	init_sync_kiocb(&kiocb, file);
	// kiocb.ki_flags |= IOCB_LOAD_PROGRAM;
	iov_iter_ubuf(&iter, ITER_SOURCE, (void __user *)download.addr, download.size);
	int ret = call_write_iter(file, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	return ret;

	blk_opf_t op = REQ_SYNC | REQ_IDLE | REQ_OP_WRITE;
	switch (cmd) {
	case IOCTL_CEMU_DOWNLOAD:
		user_code = (void *)arg;
		break;
	case IOCTL_CEMU_ACTIVATE:
		break;
	case IOCTL_CEMU_EXECUTE:
		break;
	default:
		printk(KERN_ERR "FDMFS fdmfs_ioctl: unknown ioctl cmd %d!!!\n", cmd);
		return -ENOTTY;
	}
	return 0;
}

void fdmfs_deallocate(struct fdmfs_inode *inode)
{
	struct fdmfs_sb_info *sbi = inode->sbi;
	struct fdm_region *region = inode->region;
	struct fdm_region *r;

	if (region == NULL)
		return;

	list_for_each_entry(r, &sbi->fdm_free, list) {
		if (region->off + region->size == r->off) {
			r->size += region->size;
			r->off -= region->size;
			list_del(&region->list);
			kfree(region);
			goto out;
		} else if (region->off + region->size < region->off) {
			list_del(&region->list);
			list_add_tail(&region->list, &r->list);
			goto out;
		}
	}

	list_del(&region->list);
	list_add_tail(&region->list, &sbi->fdm_free);

out:
	inode->region = NULL;
	i_size_write(inode->inode, 0);
	return;
}

static long fdmfs_fallocate(struct file *filp, int mode,
				loff_t offset, loff_t length)
{
	struct inode *inode = file_inode(filp);
	struct fdmfs_inode *fdmfs_inode = filp->private_data;
	struct fdmfs_sb_info *sbi = fdmfs_inode->sbi;
	struct fdm_region *region;
	struct fdm_region *new_region;
	int ret = 0;

	pr_info("FDMFS: fallocate mode %d, offset %lld, length %lld\n",
		mode, offset, length);

	if (mode != 0) {
		pr_err("FDMFS: fallocate doesn't support mode!\n");
		return -EINVAL;
	}

	if (offset != 0) {
		pr_err("FDMFS: fallocate doesn't support offset!\n");
		return -EINVAL;
	}

	if (length % 512) {
		pr_err("FDMFS: fallocate require 512-aligned length!\n");
		return -EINVAL;
	}

	inode_lock(inode);

	if (filp->f_inode->i_size != 0 || offset != 0) {
		pr_err("FDMFS: fallocate doesn't support truncate\n");
		ret = -EOPNOTSUPP;
		goto err;
	}

	ret = inode_newsize_ok(inode, length);
	if (ret)
		goto err;

	ret = file_modified(filp);
	if (ret)
		goto err;

	// find free region with equal size first
	list_for_each_entry(region, &sbi->fdm_free, list) {
		if (region->size == length) {
			list_del(&region->list);
			new_region = region;
			goto out;
		}
	}

	list_for_each_entry(region, &sbi->fdm_free, list) {
		if (region->size > length) {
			new_region = kzalloc(sizeof(struct fdm_region), GFP_KERNEL);
			new_region->off = region->off;
			new_region->size = length;
			region->size -= length;
			region->off += length;
			goto out;
		}
	}

	ret = -ENOMEM;
	goto err;
out:
	list_add(&new_region->list, &sbi->fdm_used);
	FDMFS_I(inode)->region = new_region;
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		i_size_write(inode, length);
		inode->i_blocks = (length+(1<<inode->i_blkbits)-1) >> inode->i_blkbits;
	}
	inode_set_ctime_current(inode);
	pr_info("FDMFS: fallocate success, inode size %lld\n", filp->f_inode->i_size);
err:
	inode_unlock(inode);
	return ret;
}

const struct file_operations fdmfs_fops = {
	.open			= fdmfs_open,
	.release		= fdmfs_release,
	// .read			= fdmfs_read,
	// .write			= fdmfs_write,
	.read_iter		= fdmfs_rw_iter,
	.write_iter		= fdmfs_rw_iter,
	.copy_file_range	= fdmfs_copy_file_range,
	.fallocate		= fdmfs_fallocate,
	.fsync			= noop_fsync,
	.unlocked_ioctl		= fdmfs_ioctl,
	.llseek			= generic_file_llseek,
};
