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
 * Author: WuJing
 * Create: 2020-05-09
 * Description: provide isula image common functions
 ********************************************************************************/

#ifndef __UTILS_IMAGES_H
#define __UTILS_IMAGES_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HTTPS_PREFIX "https://"
#define HTTP_PREFIX "http://"

#define DEFAULT_TAG ":latest"
#define DEFAULT_HOSTNAME "docker.io/"
#define DEFAULT_REPO_PREFIX "library/"

char *oci_get_host(const char *name);
char *oci_host_from_mirror(const char *mirror);
char *oci_default_tag(const char *name);
char *oci_add_host(const char *domain, const char *name);
char *oci_normalize_image_name(const char *name);
int oci_split_image_name(const char *image_name, char **host, char **name, char **tag);
char *oci_full_image_name(const char *host, const char *name, const char *tag);
char *oci_strip_dockerio_prefix(const char *name);
char *make_big_data_base_name(const char *key);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_IMAGES_H */

