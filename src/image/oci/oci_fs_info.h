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
 * Description: provide oci image fs functions
 ******************************************************************************/

#ifndef __OCI_FS_INFO_H_
#define __OCI_FS_INFO_H_

#include "oci_image_type.h"
#include "imagetool_fs_info.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    imagetool_fs_info *fs_info;
    char *errmsg;
} image_fs_info_response;

int get_fs_info(image_fs_info_response **response);

void free_image_fs_info_response(image_fs_info_response *ptr);

#ifdef __cplusplus
}
#endif

#endif
