
#ifndef __DEVMAPPER_DEVICE_SETUP_H
#define __DEVMAPPER_DEVICE_SETUP_H

#include <stdint.h>
#include "image_devmapper_direct_lvm_config.h"


#ifdef __cplusplus
extern "C" {
#endif

// struct image_devmapper_direct_lvm_config {
//     char *device;
//     uint64_t thinp_percent;
//     uint64_t thinp_meta_percent;
//     uint64_t auto_extend_percent;
//     uint64_t auto_extend_threshold;
// };

int validate_lvm_config(image_devmapper_direct_lvm_config *cfg);
int check_dev_available(const char *dev);
int check_dev_invg(const char *dev);
int check_dev_hasfs(const char *dev);
int verify_block_device(const char *dev, bool force);
image_devmapper_direct_lvm_config *read_lvm_config(const char *root);
int write_lvm_config(const char *root, image_devmapper_direct_lvm_config *cfg);
int setup_direct_lvm(image_devmapper_direct_lvm_config *cfg);

#ifdef __cplusplus
}
#endif


#endif