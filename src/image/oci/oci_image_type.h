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
 * Description: provide image type definition
 ******************************************************************************/

#ifndef __OCI_IMAGE_TYPE_H_
#define __OCI_IMAGE_TYPE_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_OCI_IMAGE
/*
 * ImageSpec is an internal representation of an image.  Currently, it wraps the
 * value of a Container's Image field (e.g. imageID or imageDigest), but in the
 * future it will include more detailed information about the different image types.
 */
typedef struct {
    char *image;
} image_spec;
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

#ifdef ENABLE_OCI_IMAGE
typedef struct {
    image_spec image;
} image_filter;
#endif


#ifdef __cplusplus
}
#endif

#endif

