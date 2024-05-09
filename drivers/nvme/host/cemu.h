#ifndef __LINUX_CEMU_H__
#define __LINUX_CEMU_H__

#include <linux/pci.h>
#include <linux/io_uring/cmd.h>
#include "nvme.h"

struct cemu_bio {
	atomic_t		ref;
	unsigned		flags;
	int			error;
	size_t			done_before;
	bool			wait_for_completion;
	struct io_uring_cmd	*cmd;

	struct {
		struct iov_iter		*iter;
		struct task_struct	*waiter;
	} submit;

	/* nvme command field*/
	int pind;
	int ptype;
	int sel;
	int psize;
	int jit;
	int indirect;
	int runtime;
	int runtime_scale;
};

enum {
	IOCTL_CEMU_DOWNLOAD,
	IOCTL_CEMU_ACTIVATE,
	IOCTL_CEMU_EXECUTE,
	IOCTL_CEMU_CREATE_MRS,
};

/* IOCTL_CEMU_DOWNLOAD argument */
struct ioctl_download {
	const char	*name;
	void		*addr;
	int 		size;
	int		ptype;
	int		runtime;
	int		runtime_scale;
	int		jit;
	int		indirect;
	int 		pind;	/* out */
};

/* IOCTL_CEMU_EXECUTE argument */
struct ioctl_execute {
	uint64_t 	cparam1;
	uint64_t 	cparam2;
	int		*memory_fd;
	void 		*buffer;
	uint16_t	nr_fd;
	uint16_t	buffer_len;
	uint16_t	pind;
	uint16_t	rsid;
	uint16_t	memory_range_set;
};

/* IOCTL_CREATE_MRS argument */
struct ioctl_create_mrs {
	int		*fd;	// fd array of FDMFS
	long long	*off;	// offset array
	long long	*size;	// size array
	int		nr_fd;
	uint16_t	rsid;
};

int cemu_dev_add(struct pci_dev *pdev, struct nvme_ctrl *ctrl);
void cemu_dev_remove(struct pci_dev *pdev, struct nvme_ctrl *ctrl);
size_t cemu_dev_get_size(struct block_device *bdev);
void *cemu_dev_get_p2p_addr(struct block_device *bdev);
void cemu_bio_end_io(struct bio *bio);

#endif /* __LINUX_CEMU_H__ */