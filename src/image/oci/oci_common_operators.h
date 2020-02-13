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
 * Create: 2019-07-23
 * Description: provide image common function definition
 ******************************************************************************/
#ifndef __OCI_COMMON_OPERATORS_H
#define __OCI_COMMON_OPERATORS_H

#include <stdint.h>
#include "image.h"
#include "imagetool_image.h"
#include "oci_image_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

char *oci_normalize_image_name(const char *name);

bool oci_detect(const char *image_name);
char *oci_resolve_image_name(const char *name);
int oci_get_user_conf(const char *basefs, host_config *hc, const char *userstr, defs_process_user *puser);
int oci_list_images(const im_list_request *request, imagetool_images_list **images);
int oci_status_image(im_status_request *request, im_status_response **response);
int oci_inspect_image(const im_inspect_request *request, char **inspected_json);

imagetool_image *oci_get_image_info_by_name(const char *id);
int oci_get_all_images(const im_list_request *request, imagetool_images_list **images);

int oci_image_conf_merge_into_spec(const char *image_name, container_config *container_spec);

#ifdef __cplusplus
}
#endif

#endif
