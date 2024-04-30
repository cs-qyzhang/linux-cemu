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

static ssize_t fdmfs_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos) {
	pr_info("FDMFS: read %zu bytes\n", len);
	return len;
}

static ssize_t fdmfs_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos) {
	struct inode *inode = file_inode(filp);
	pr_info("FDMFS: write %zu bytes\n", len);
	return len;
}

static ssize_t fdmfs_read_iter(struct kiocb *iocb, struct iov_iter *iter)
{
	pr_info("FDMFS: read_iter\n");
	struct inode *ino = file_inode(iocb->ki_filp);

	inode_lock_shared(ino);
	// struct bio *bio = bio_alloc(sbi->cemu_bdev, nr_vecs, opf, GFP_KERNEL);
	ssize_t ret = iomap_dio_rw(iocb, iter, &fdmfs_iomap_ops, NULL, 0, NULL, 0);
	inode_unlock_shared(ino);
	file_accessed(iocb->ki_filp);
	return ret;
}

static ssize_t fdmfs_write_iter(struct kiocb *iocb, struct iov_iter *from)
{
	pr_info("FDMFS: write_iter\n");
	return 0;
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

	bvec_set_virt(&bvec, fdmfs_region_addr(inode), size);
	iov_iter_bvec(&iter, ITER_DEST, &bvec, 1, size);

	if (in_is_fdmfs)
		ret = call_read_iter(file_out, &kiocb, &iter);
	else
		ret = call_read_iter(file_in, &kiocb, &iter);
	BUG_ON(ret == -EIOCBQUEUED);
	return ret;
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
		pr_err("FDMFS: fallocate doesn't support mode\n");
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
	FDMFS_I(inode)->region = region;
	if (!(mode & FALLOC_FL_KEEP_SIZE)) {
		i_size_write(inode, length);
		inode->i_blocks = (length + 511) >> 9;
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
	.read_iter		= fdmfs_read_iter,
	.write_iter		= fdmfs_write_iter,
	.copy_file_range	= fdmfs_copy_file_range,
	.fallocate		= fdmfs_fallocate,
	.fsync			= noop_fsync,
	.llseek			= generic_file_llseek,
};
