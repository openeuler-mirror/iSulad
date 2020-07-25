/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide image type definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_IMAGE_OCI_OCI_IMAGE_TYPE_H
#define DAEMON_MODULES_IMAGE_OCI_OCI_IMAGE_TYPE_H

#ifdef __cplusplus
extern "C" {
#endif

/* AuthConfig contains authorization information for connecting to a registry */
typedef struct {
    char *username;
    char *password;
    char *auth;
    char *server_address;

    // IdentityToken is used to authenticate the user and get
    // an access token for the registry.
    char *identity_token;

    // RegistryToken is a bearer token to be sent to a registry
    char *registry_token;
} auth_config;

#ifdef __cplusplus
}
#endif

#endif
