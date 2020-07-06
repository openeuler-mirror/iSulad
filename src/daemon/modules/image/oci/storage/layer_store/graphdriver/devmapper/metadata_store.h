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
#ifndef __METADATA_STORE_H
#define __METADATA_STORE_H

#include <stdbool.h>
#include <stdint.h>

#include "devices_constants.h"
#include "isula_libutils/image_devmapper_device_info.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _devmapper_device_info_t_ {
    image_devmapper_device_info *info;
    uint64_t refcnt;
} devmapper_device_info_t;

void devmapper_device_info_ref_inc(devmapper_device_info_t *device_info);
void devmapper_device_info_ref_dec(devmapper_device_info_t *device_info);

metadata_store_t *metadata_store_new(void);

bool metadata_store_add(const char *hash, image_devmapper_device_info *device, metadata_store_t *meta_store);

devmapper_device_info_t *metadata_store_get(const char *hash, metadata_store_t *meta_store);

bool metadata_store_remove(const char *hash, metadata_store_t *meta_store);

char **metadata_store_list_hashes(metadata_store_t *meta_store);

#ifdef __cplusplus
}
#endif
#endif