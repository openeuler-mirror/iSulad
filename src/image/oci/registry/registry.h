/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2020-02-27
 * Description: provide registry definition
 ******************************************************************************/
#ifndef __IMAGE_REGISTRY_H
#define __IMAGE_REGISTRY_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *cert_path;
    char *auth_file_path;
    char *use_decrypted_key;
    bool skip_tls_verify;
} registry_options;

typedef struct {
    char *username;
    char *password;
} registry_auth;

typedef struct {
    registry_options comm_opt;
    registry_auth auth;
    char *image_name;
} registry_pull_options;

typedef struct {
    registry_options comm_opt;
    registry_auth auth;
    char *host;
} registry_login_options;

int registry_pull(registry_pull_options *options);
int registry_login(registry_login_options *options);
int registry_logout(char *auth_file_path, char *host);
void free_registry_pull_options(registry_pull_options *options);
void free_registry_login_options(registry_login_options *options);

#ifdef __cplusplus
}
#endif

#endif

