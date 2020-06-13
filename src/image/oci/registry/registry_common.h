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
 * Author: WuJing
 * Create: 2020-06-13
 * Description: provide registry common functions
 ********************************************************************************/

#ifndef __OCI_REGISTRY_COMMON_H
#define __OCI_REGISTRY_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include "isula_libutils/docker_image_config_v2.h"
#include "isula_libutils/registry_manifest_schema1.h"
#include "isula_libutils/image_manifest_v1_compatibility.h"
#include "registry_type.h"
#include "types_def.h"

#ifdef __cplusplus
extern "C" {
#endif

void free_items_not_inherit(docker_image_config_v2 *config);
int add_rootfs_and_history(const layer_blob *layers, size_t layers_len,
                           const registry_manifest_schema1 *manifest, docker_image_config_v2 *config);
char *without_sha256_prefix(char *digest);
types_timestamp_t created_to_timestamp(char *created);

#ifdef __cplusplus
}
#endif

#endif /* __OCI_REGISTRY_COMMON_H */

