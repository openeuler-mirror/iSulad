
/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: gaohuatao
 * Create: 2020-06-12
 * Description: provide overlay2 function definition
 ******************************************************************************/
#ifndef __DEVMAPPER_DEVICE_SETUP_H
#define __DEVMAPPER_DEVICE_SETUP_H

#include <stdint.h>
#include "isula_libutils/image_devmapper_direct_lvm_config.h"

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
char *probe_fs_type(const char *device);
void append_mount_options(char **dest, const char *suffix);

#ifdef __cplusplus
}
#endif

#endif