#ifndef __LINUX_CEMU_H__
#define __LINUX_CEMU_H__

#include <linux/pci.h>
#include "nvme.h"

int cemu_dev_add(struct pci_dev *pdev, struct nvme_ctrl *ctrl);
void cemu_dev_remove(struct pci_dev *pdev, struct nvme_ctrl *ctrl);
size_t cemu_dev_get_size(struct block_device *bdev);
void *cemu_dev_get_p2p_addr(struct block_device *bdev);

#endif /* __LINUX_CEMU_H__ */