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

#define HTTPS_PREFIX "https://"
#define HTTP_PREFIX "http://"

#ifdef __cplusplus
extern "C" {
#endif

char *oci_get_host(const char *name);
char *oci_host_from_mirror(const char *mirror);
char *oci_default_tag(const char *name);
char *oci_add_host(const char *domain, const char *name);
char *oci_normalize_image_name(const char *name);
int oci_split_image_name(const char *image_name, char **host, char **name, char **tag);
char *oci_full_image_name(const char *host, const char *name, const char *tag);
bool oci_detect(const char *image_name);
char *oci_resolve_image_name(const char *name);
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
