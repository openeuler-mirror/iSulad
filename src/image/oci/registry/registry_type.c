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
 * Create: 2020-06-13
 * Description: provide registry functions
 ******************************************************************************/
#include "registry_type.h"
#include <stdio.h>
#include <stdlib.h>
#include "utils.h"

void free_challenge(challenge *c)
{
    if (c == NULL) {
        return;
    }

    free(c->schema);
    c->schema = NULL;
    free(c->realm);
    c->realm = NULL;
    free(c->service);
    c->service = NULL;
    free(c->cached_token);
    c->cached_token = NULL;
    c->expires_time = 0;

    return;
}

void free_layer_blob(layer_blob *layer)
{
    if (layer == NULL) {
        return;
    }
    layer->empty_layer = false;
    free(layer->media_type);
    layer->media_type = NULL;
    layer->size = 0;
    free(layer->digest);
    layer->digest = NULL;
    free(layer->diff_id);
    layer->diff_id = NULL;
    free(layer->chain_id);
    layer->chain_id = NULL;
    free(layer->file);
    layer->file = NULL;
    layer->already_exist = false;
    return;
}

void free_pull_desc(pull_descriptor *desc)
{
    int i = 0;

    if (desc == NULL) {
        return;
    }

    free(desc->dest_image_name);
    desc->dest_image_name = NULL;
    free(desc->host);
    desc->host = NULL;
    free(desc->name);
    desc->name = NULL;
    free(desc->tag);
    desc->tag = NULL;

    free_sensitive_string(desc->username);
    desc->username = NULL;
    free_sensitive_string(desc->password);
    desc->password = NULL;

    desc->use_decrypted_key = false;
    desc->cert_loaded = false;
    free(desc->ca_file);
    desc->ca_file = NULL;
    free(desc->cert_file);
    desc->cert_file = NULL;
    free(desc->key_file);
    desc->key_file = NULL;

    free(desc->blobpath);
    desc->blobpath = NULL;
    free(desc->protocol);
    desc->protocol = NULL;
    desc->skip_tls_verify = false;
    free(desc->scope);
    desc->scope = NULL;

    for (i = 0; i < CHALLENGE_MAX; i++) {
        free_challenge(&desc->challenges[i]);
    }
    util_free_array(desc->headers);
    desc->headers = NULL;

    free(desc->manifest.media_type);
    desc->manifest.media_type = NULL;
    desc->manifest.size = 0;
    free(desc->manifest.digest);
    desc->manifest.digest = NULL;
    free(desc->manifest.file);
    desc->manifest.file = NULL;

    free(desc->config.media_type);
    desc->config.media_type = NULL;
    desc->config.size = 0;
    free(desc->config.digest);
    desc->config.digest = NULL;
    free(desc->config.file);
    desc->config.file = NULL;
    desc->config.create_time.has_seconds = 0;
    desc->config.create_time.seconds = 0;
    desc->config.create_time.has_nanos = 0;
    desc->config.create_time.nanos = 0;

    for (i = 0; i < desc->layers_len; i++) {
        free_layer_blob(&desc->layers[i]);
    }
    free(desc->layers);
    desc->layers = NULL;
    desc->layers_len = 0;

    free(desc);

    return;
}
