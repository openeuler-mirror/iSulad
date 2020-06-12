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

#include "map.h"
#include "isula_libutils/image_devmapper_device_info.h"

#ifdef __cplusplus
extern "C" {
#endif

int metadata_store_init(void);

bool metadata_store_add(const char *hash, image_devmapper_device_info *device);

image_devmapper_device_info *metadata_store_get(const char *hash);

bool metadata_store_remove(const char *hash);

char **metadata_store_list_hashes(void);

#ifdef __cplusplus
}
#endif
#endif