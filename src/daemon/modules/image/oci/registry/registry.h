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
 * Author: wangfengtu
 * Create: 2020-02-27
 * Description: provide registry definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_REGISTRY_REGISTRY_H
#define DAEMON_MODULES_IMAGE_OCI_REGISTRY_REGISTRY_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *username;
    char *password;
} registry_auth;

typedef struct {
    char *image_name;
    char *dest_image_name;
    registry_auth auth;
    bool skip_tls_verify;
    bool insecure_registry;
} registry_pull_options;

typedef struct {
    char *host;
    registry_auth auth;
    bool skip_tls_verify;
    bool insecure_registry;
} registry_login_options;

int registry_init(char *auths_path, char *certs_dir);
int registry_pull(registry_pull_options *options);
int registry_login(registry_login_options *options);
int registry_logout(char *host);

void free_registry_pull_options(registry_pull_options *options);

#ifdef __cplusplus
}
#endif

#endif

