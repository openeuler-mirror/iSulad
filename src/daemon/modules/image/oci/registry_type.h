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
 * Create: 2020-04-23
 * Description: provide registry type definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_IMAGE_OCI_REGISTRY_TYPE_H
#define DAEMON_MODULES_IMAGE_OCI_REGISTRY_TYPE_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>

#include "utils_timestamp.h"

// 8 is enough for challenge, usually only one challenge is provided.
#define CHALLENGE_MAX 8


#define MAX_LAYER_NUM 125
#define ROOTFS_TYPE "layers"

typedef struct {
    char *schema;
    char *realm;
    char *service;
    char *cached_token;
    time_t expires_time;
} challenge;

typedef struct {
    char *media_type;
    size_t size;
    char *digest;
    // Downloaded file path
    char *file;
} manifest_blob;

typedef struct {
    char *media_type;
    size_t size;
    char *digest;
    // Downloaded file path
    char *file;
    types_timestamp_t create_time;
    bool complete;
    int result;
} config_blob;

typedef struct {
    bool empty_layer;
    char *media_type;
    // blob size
    size_t size;
    // compressed digest
    char *digest;
    // uncompressed digest
    char *diff_id;
    // use chainID as layerID
    char *chain_id;
    // Downloaded file path
    char *file;
    // already exist on local store
    bool already_exist;
    // layer have registered to loacal store, this flag used to rollback
    bool registered;
} layer_blob;

typedef struct {
    char *image_name;
    char *dest_image_name;
    char *host;
    char *name;
    char *tag;

    char *username;
    char *password;
    char *auths_dir;

    bool use_decrypted_key;
    bool cert_loaded;
    char *ca_file;
    char *cert_file;
    char *key_file;
    char *certs_dir;

    int pulling_number;
    bool cancel;
    char *errmsg;

    char *blobpath;
    char *protocol;
    bool skip_tls_verify;
    bool insecure_registry;
    char *scope;
    pthread_mutex_t challenges_mutex;
    bool challenges_mutex_inited;
    challenge challenges[CHALLENGE_MAX];
    // This is temporary field. Once http request is performed, it is cleared
    char **headers;

    char *layer_of_hold_refs;

    // Image blobs downloaded
    manifest_blob manifest;
    config_blob config;
    layer_blob *layers;
    size_t layers_len;

    bool rollback_layers_on_failure;
    bool register_layers_complete;
    // used to calc chain id
    char *parent_chain_id;
    // used to register layer
    char *parent_layer_id;
    pthread_mutex_t mutex;
    bool mutex_inited;
    pthread_cond_t cond;
    bool cond_inited;
} pull_descriptor;

void free_challenge(challenge *c);
void free_layer_blob(layer_blob *layer);
void free_pull_desc(pull_descriptor *desc);

#endif // DAEMON_MODULES_IMAGE_OCI_REGISTRY_TYPE_H
