/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuhao
 * Create: 2019-07-23
 * Description: provide image common function definition
 ******************************************************************************/
#ifndef __OCI_COMMON_OPERATORS_H
#define __OCI_COMMON_OPERATORS_H

#include <stdint.h>
#include "image.h"
#include "isula_libutils/imagetool_image.h"
#include "isula_libutils/oci_image_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

char *oci_resolve_image_name(const char *name);
bool oci_detect(const char *image_name);
int oci_get_user_conf(const char *basefs, host_config *hc, const char *userstr, defs_process_user *puser);
int oci_list_images(const im_list_request *request, imagetool_images_list **images);
int oci_status_image(im_status_request *request, im_status_response **response);
int oci_inspect_image(const im_inspect_request *request, char **inspected_json);

int oci_image_conf_merge_into_spec(const char *image_name, container_config *container_spec);

size_t oci_get_images_count(void);
#ifdef __cplusplus
}
#endif

#endif
