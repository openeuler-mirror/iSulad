/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide specs definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_SPEC_SPECS_MOUNT_H
#define DAEMON_MODULES_SPEC_SPECS_MOUNT_H

#include <stdint.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/defs.h>
#include <stdbool.h>
#include <stddef.h>

#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config_v2.h"
#include "isula_libutils/oci_runtime_hooks.h"
#include "isula_libutils/oci_runtime_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

int adapt_settings_for_mounts(oci_runtime_spec *oci_spec, container_config *container_spec);

int merge_conf_mounts(oci_runtime_spec *oci_spec, host_config *host_spec,
                      container_config_v2_common_config *common_config);

int add_rootfs_mount(const container_config *container_spec);

int set_mounts_readwrite_option(const oci_runtime_spec *oci_spec);

int merge_all_devices_and_all_permission(oci_runtime_spec *oci_spec);

int merge_conf_devices(oci_runtime_spec *oci_spec, host_config *host_spec);

int merge_conf_blkio_device(oci_runtime_spec *oci_spec, host_config *host_spec);

int setup_ipc_dirs(host_config *host_spec, container_config_v2_common_config *v2_spec);

int update_devcies_for_oci_spec(oci_runtime_spec *oci_spec, host_config *hostconfig);

#ifdef ENABLE_CDI
int inject_CDI_devcies_for_oci_spec(oci_runtime_spec *oci_spec, host_config *hostconfig);
#endif /* ENABLE_CDI */

#ifdef __cplusplus
}
#endif

#endif
