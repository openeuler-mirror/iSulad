/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula image prepare operator implement
*******************************************************************************/
#ifndef __IMAGE_ISULA_PREPARE_H
#define __IMAGE_ISULA_PREPARE_H

#include "image.h"
#include "oci_image_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

int isula_rootfs_prepare_and_get_image_conf(const char *container_id, const char *image_name,
                                            const json_map_string_string *storage_opt,
                                            char **real_rootfs, oci_image_spec **spec);

#ifdef __cplusplus
}
#endif

#endif
