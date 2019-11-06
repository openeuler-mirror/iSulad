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
 * Author: 李峰
 * Create: 2018-11-08
 * Description: provide oci prepare rootfs functions
 ******************************************************************************/

#ifndef __OCI_PREPARE_ROOTFS_H_
#define __OCI_PREPARE_ROOTFS_H_

#include "imagetool_prepare_response.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *image;
    char *name;
    char *id;
    char **storage_opts;
    size_t storage_opts_len;
} rootfs_prepare_request;

typedef struct {
    char *errmsg;
    char *rootfs;
} rootfs_prepare_response;

typedef struct {
    char *errmsg;
    imagetool_prepare_response *raw_response;
} rootfs_prepare_and_get_image_conf_response;

void free_rootfs_prepare_request(rootfs_prepare_request *ptr);

int prepare_rootfs_and_get_image_conf(rootfs_prepare_request *request,
                                      rootfs_prepare_and_get_image_conf_response **response);
void free_rootfs_prepare_and_get_image_conf_response(rootfs_prepare_and_get_image_conf_response *ptr);

#ifdef __cplusplus
}
#endif

#endif

