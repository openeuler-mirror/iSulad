/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide containers store definition
 ******************************************************************************/
#ifndef __ISULAD_IMAGE_STORE_H__
#define __ISULAD_IMAGE_STORE_H__

#include "oci_image_unix.h"
#include "map.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

int oci_images_store_init(void);

int load_all_oci_images();

oci_image_t *oci_images_store_get(const char *id_or_name);

size_t oci_images_store_size(void);

int oci_images_store_list(oci_image_t ***out, size_t *size);

int image_name_id_init(void);

int register_new_oci_image_into_memory(const char *name);

int remove_oci_image_from_memory(const char *name_or_id);

int oci_image_store_init();

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_MEMORY_STORE_H__ */

