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
 * Description: provide oci image status functions
 ******************************************************************************/

#ifndef __OCI_IMAGE_STATUS_H_
#define __OCI_IMAGE_STATUS_H_

#include "image.h"
#include "oci_image_type.h"
#include "imagetool_image_status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    // Spec of the image.
    image_spec image;
    // Verbose indicates whether to return extra information about the image.
    bool verbose;
} oci_image_status_request;

typedef struct {
    imagetool_image_status *image_info;
    char *errmsg;
} oci_image_status_response;

void free_oci_image_status_request(oci_image_status_request *ptr);

void free_oci_image_status_response(oci_image_status_response *ptr);

imagetool_image *oci_image_get_image_info_by_name(const char *image_name);

#ifdef __cplusplus
}
#endif

#endif
