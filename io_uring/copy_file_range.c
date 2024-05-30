// SPDX-License-Identifier: GPL-2.0
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/io_uring.h>

#include <uapi/linux/io_uring.h>

#include "io_uring.h"
#include "opdef.h"
#include "copy_file_range.h"

/* borrowed from splice.c */
struct io_copy_file_range {
	struct file			*file_out;
	loff_t				off_out;
	loff_t				off_in;
	u64				len;
	int				copy_fd_in;
	unsigned int			flags;
};

int io_copy_file_range_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_copy_file_range *cp = io_kiocb_to_cmd(req, struct io_copy_file_range);

	cp->off_in = READ_ONCE(sqe->splice_off_in);
	cp->off_out = READ_ONCE(sqe->off);

	cp->len = READ_ONCE(sqe->len);
	cp->copy_fd_in = READ_ONCE(sqe->splice_fd_in);
	cp->flags = READ_ONCE(sqe->splice_flags);
	return 0;
}

int io_copy_file_range(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_copy_file_range *cp = io_kiocb_to_cmd(req, struct io_copy_file_range);
	struct file *out = cp->file_out;
	struct file *in;
	ssize_t ret = 0;

	if (cp->flags & SPLICE_F_FD_IN_FIXED)
		in = io_file_get_fixed(req, cp->copy_fd_in, issue_flags);
	else
		in = io_file_get_normal(req, cp->copy_fd_in);
	if (!in) {
		ret = -EBADF;
		goto done;
	}

	if (cp->len)
		ret = vfs_copy_file_range(in, cp->off_in, out, cp->off_out, cp->len, COPY_FILE_ASYNC);

	if (!(cp->flags & SPLICE_F_FD_IN_FIXED))
		fput(in);
done:
	if (ret != cp->len)
		req_set_fail(req);
	io_req_set_res(req, ret, 0);
	return IOU_OK;
}