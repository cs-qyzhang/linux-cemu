#ifndef __LINUX_CEMU_H__
#define __LINUX_CEMU_H__

#include <linux/pci.h>
#include "nvme.h"

int cemu_dev_add(struct pci_dev *pdev, struct nvme_ctrl *ctrl);
void cemu_dev_remove(struct pci_dev *pdev, struct nvme_ctrl *ctrl);

#endif /* __LINUX_CEMU_H__ */