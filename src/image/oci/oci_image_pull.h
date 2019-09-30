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
 * Description: provide oci image pull functions
 ******************************************************************************/

#ifndef __OCI_IMAGE_PULL_H_
#define __OCI_IMAGE_PULL_H_

#include "oci_image_type.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    image_spec image;
    auth_config auth;
} image_pull_request;

typedef struct {
    // Reference to the image in use. For most runtimes, this should be an
    // image ID or digest.
    char *image_ref;
    char *errmsg;
} image_pull_response;

int pull_image(image_pull_request *request, image_pull_response **response);

void free_image_pull_request(image_pull_request *ptr);

void free_image_pull_response(image_pull_response *ptr);

#ifdef __cplusplus
}
#endif

#endif
