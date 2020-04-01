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
 * Description: provide registry functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "mediatype.h"
#include "log.h"
#include "registry_type.h"
#include "registry.h"
#include "utils.h"
#include "oci_common_operators.h"
#include "registry_apiv2.h"
#include "auths.h"
#include "certs.h"
#include "registry_manifest_schema2.h"
#include "registry_manifest_schema1.h"
#include "docker_image_config_v2.h"
#include "sha256.h"

#define MAX_LAYER_NUM 125

static int parse_manifest_schema1(pull_descriptor *desc)
{
    registry_manifest_schema1 *manifest = NULL;
    parser_error err = NULL;
    int ret = 0;
    int i = 0;
    size_t index = 0;

    manifest = registry_manifest_schema1_parse_file(desc->manifest.file, NULL, &err);
    if (manifest == NULL) {
        ERROR("parse manifest schema1 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    if (manifest->fs_layers_len > MAX_LAYER_NUM || manifest->fs_layers_len == 0) {
        ERROR("Invalid layer number %d, maxium is %d and it can't be 0", manifest->fs_layers_len, MAX_LAYER_NUM);
        ret = -1;
        goto out;
    }

    if (manifest->fs_layers_len != manifest->history_len) {
        ERROR("Invalid layer number %d do not match history number %d", manifest->fs_layers_len, manifest->history_len);
        ret = -1;
        goto out;
    }

    desc->layers = util_common_calloc_s(sizeof(layer_blob) * manifest->fs_layers_len);
    if (desc->layers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    for (i = (int)manifest->fs_layers_len - 1, index = 0; i >= 0; i--, index++) {
        desc->layers[index].media_type = util_strdup_s(DOCKER_IMAGE_LAYER_TAR_GZIP);
        desc->layers[index].digest = util_strdup_s(manifest->fs_layers[i]->blob_sum);
    }
    desc->layers_len = manifest->fs_layers_len;

out:
    if (manifest != NULL) {
        free_registry_manifest_schema1(manifest);
        manifest = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static int parse_manifest_schema2(pull_descriptor *desc)
{
    registry_manifest_schema2 *manifest = NULL;
    parser_error err = NULL;
    int ret = 0;
    size_t i = 0;

    manifest = registry_manifest_schema2_parse_file(desc->manifest.file, NULL, &err);
    if (manifest == NULL) {
        ERROR("parse manifest schema2 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    desc->config.media_type = util_strdup_s(manifest->config->media_type);
    desc->config.digest = util_strdup_s(manifest->config->digest);
    desc->config.size = manifest->config->size;

    if (manifest->layers_len > MAX_LAYER_NUM) {
        ERROR("Invalid layer number %d, maxium is %d", manifest->layers_len, MAX_LAYER_NUM);
        ret = -1;
        goto out;
    }

    desc->layers = util_common_calloc_s(sizeof(layer_blob) * manifest->layers_len);
    if (desc->layers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < manifest->layers_len; i++) {
        desc->layers[i].media_type = util_strdup_s(manifest->layers[i]->media_type);
        desc->layers[i].size = manifest->layers[i]->size;
        desc->layers[i].digest = util_strdup_s(manifest->layers[i]->digest);
    }
    desc->layers_len = manifest->layers_len;

out:
    if (manifest != NULL) {
        free_registry_manifest_schema2(manifest);
        manifest = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static int parse_manifest_ociv1(pull_descriptor *desc)
{
    oci_image_manifest *manifest = NULL;
    parser_error err = NULL;
    int ret = 0;
    size_t i = 0;

    manifest = oci_image_manifest_parse_file(desc->manifest.file, NULL, &err);
    if (manifest == NULL) {
        ERROR("parse manifest oci v1 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    desc->config.media_type = util_strdup_s(manifest->config->media_type);
    desc->config.digest = util_strdup_s(manifest->config->digest);
    desc->config.size = manifest->config->size;

    if (manifest->layers_len > MAX_LAYER_NUM) {
        ERROR("Invalid layer number %d, maxium is %d", manifest->layers_len, MAX_LAYER_NUM);
        ret = -1;
        goto out;
    }

    desc->layers = util_common_calloc_s(sizeof(layer_blob) * manifest->layers_len);
    if (desc->layers == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < manifest->layers_len; i++) {
        desc->layers[i].media_type = util_strdup_s(manifest->layers[i]->media_type);
        desc->layers[i].size = manifest->layers[i]->size;
        desc->layers[i].digest = util_strdup_s(manifest->layers[i]->digest);
    }
    desc->layers_len = manifest->layers_len;

out:
    if (manifest != NULL) {
        free_oci_image_manifest(manifest);
        manifest = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static bool is_manifest_schema1(char *media_type)
{
    if (media_type == NULL) {
        return false;
    }

    if (!strcmp(media_type, DOCKER_MANIFEST_SCHEMA1_JSON) ||
        !strcmp(media_type, DOCKER_MANIFEST_SCHEMA1_PRETTYJWS) ||
        !strcmp(media_type, MEDIA_TYPE_APPLICATION_JSON)) {
        return true;
    }

    return false;
}

static int parse_manifest(pull_descriptor *desc)
{
    char *media_type = NULL;
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    media_type = desc->manifest.media_type;
    if (!strcmp(media_type, DOCKER_MANIFEST_SCHEMA2_JSON)) {
        ret = parse_manifest_schema2(desc);
    } else if (!strcmp(media_type, OCI_MANIFEST_V1_JSON)) {
        ret = parse_manifest_ociv1(desc);
    } else if (is_manifest_schema1(media_type)) {
        WARN("found manifest schema1 %s, it has been deprecated", media_type);
        ret = parse_manifest_schema1(desc);
    } else {
        ERROR("Unsupported manifest media type %s", desc->manifest.media_type);
        return -1;
    }
    if (ret != 0) {
        ERROR("parse manifest failed, media type %s", desc->manifest.media_type);
        return ret;
    }

    return ret;
}

static int check_image(pull_descriptor *desc)
{
    // TODO
    return 0;
}

static int register_image(pull_descriptor *desc)
{
    return 0;
}

static char *calc_chain_id(char *parent_chain_id, char *diff_id)
{
    int sret = 0;
    char tmp_buffer[256] = {0};
    char *digest = NULL;
    char *full_digest = NULL;

    if (parent_chain_id == NULL || diff_id == NULL) {
        ERROR("Invalid NULL param");
        return NULL;
    }

    if (strlen(diff_id) <= strlen(SHA256_PREFIX)) {
        ERROR("Invalid diff id %s found when calc chain id", diff_id);
        return NULL;
    }

    if (strlen(parent_chain_id) == 0) {
        return util_strdup_s(diff_id);
    }

    if (strlen(parent_chain_id) <= strlen(SHA256_PREFIX)) {
        ERROR("Invalid parent chain id %s found when calc chain id", parent_chain_id);
        return NULL;
    }

    sret = snprintf(tmp_buffer, sizeof(tmp_buffer), "%s+%s", parent_chain_id + strlen(SHA256_PREFIX),
                    diff_id + strlen(SHA256_PREFIX));
    if (sret < 0 || (size_t)sret >= sizeof(tmp_buffer)) {
        ERROR("Failed to sprintf chain id original string");
        return NULL;
    }

    digest = sha256_digest_str(tmp_buffer);
    if (digest == NULL) {
        ERROR("Failed to calculate chain id");
        goto out;
    }

    full_digest = util_full_digest(digest);

out:

    free(digest);
    digest = NULL;

    return full_digest;
}

static int parse_docker_config(pull_descriptor *desc)
{
    int ret = 0;
    parser_error err = NULL;
    size_t i = 0;
    docker_image_config_v2 *config = NULL;
    char *diff_id = NULL;
    char *parent_chain_id = "";

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    config = docker_image_config_v2_parse_file(desc->config.file, NULL, &err);
    if (config == NULL) {
        ERROR("parse image config v2 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    if (config->rootfs == NULL || config->rootfs->diff_ids_len == 0) {
        ERROR("No rootfs found in config");
        ret = -1;
        goto out;
    }

    for (i = 0; i < config->rootfs->diff_ids_len; i++) {
        diff_id = config->rootfs->diff_ids[i];
        desc->layers[i].diff_id = util_strdup_s(diff_id);
        desc->layers[i].chain_id = calc_chain_id(parent_chain_id, diff_id);
        if (desc->layers[i].chain_id == NULL) {
            ERROR("calc chain id failed, diff id %s, parent chain id %s", diff_id, parent_chain_id);
            ret = -1;
            goto out;
        }
        parent_chain_id = desc->layers[i].chain_id;
    }

out:

    if (config != NULL) {
        free_docker_image_config_v2(config);
        config = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static int parse_oci_config(pull_descriptor *desc)
{
    int ret = 0;
    parser_error err = NULL;
    size_t i = 0;
    oci_image_spec *config = NULL;
    char *diff_id = NULL;
    char *parent_chain_id = "";

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    config = oci_image_spec_parse_file(desc->config.file, NULL, &err);
    if (config == NULL) {
        ERROR("parse image config v2 failed, err: %s", err);
        ret = -1;
        goto out;
    }

    if (config->rootfs == NULL || config->rootfs->diff_ids_len == 0) {
        ERROR("No rootfs found in config");
        ret = -1;
        goto out;
    }

    for (i = 0; i < config->rootfs->diff_ids_len; i++) {
        diff_id = config->rootfs->diff_ids[i];
        desc->layers[i].diff_id = util_strdup_s(diff_id);
        desc->layers[i].chain_id = calc_chain_id(parent_chain_id, diff_id);
        if (desc->layers[i].chain_id == NULL) {
            ERROR("calc chain id failed, diff id %s, parent chain id %s", diff_id, parent_chain_id);
            ret = -1;
            goto out;
        }
        parent_chain_id = desc->layers[i].chain_id;
    }

out:
    if (config != NULL) {
        free_oci_image_spec(config);
        config = NULL;
    }
    free(err);
    err = NULL;

    return ret;
}

static int parse_config(pull_descriptor *desc)
{
    int ret = 0;
    char *media_type = NULL;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    media_type = desc->config.media_type;
    if (!strcmp(media_type, DOCKER_IMAGE_V1)) {
        ret = parse_docker_config(desc);
    } else if (!strcmp(media_type, OCI_IMAGE_V1)) {
        ret = parse_oci_config(desc);
    } else {
        ERROR("Unsupported config media type %s", media_type);
        return -1;
    }
    if (ret != 0) {
        ERROR("parse config failed, media type %s", media_type);
        return ret;
    }

    return ret;
}

static int fetch_and_parse_config(pull_descriptor *desc)
{
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = fetch_config(desc);
    if (ret != 0) {
        ERROR("fetch config failed");
        goto out;
    }

    ret = parse_config(desc);
    if (ret != 0) {
        ERROR("parse config failed");
        goto out;
    }

out:

    return ret;
}

static int fetch_and_parse_manifest(pull_descriptor *desc)
{
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = fetch_manifest(desc);
    if (ret != 0) {
        ERROR("fetch manifest failed");
        goto out;
    }

    ret = parse_manifest(desc);
    if (ret != 0) {
        ERROR("parse manifest failed");
        goto out;
    }

out:

    return ret;
}

static int fetch_layers(pull_descriptor *desc)
{
    size_t i = 0;
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    for (i = 0; i < desc->layers_len; i++) {
        // TODO:
        // 1. fetch layers only it doesn't exist
        // 2. fetch layers in threads
        // 3. fetch maxium 5 layers concurrently
        ret = fetch_layer(desc, i);
        if (ret != 0) {
            ERROR("fetch layer %d failed", i);
            goto out;
        }
    }

out:

    return ret;
}

static int registry_fetch(pull_descriptor *desc)
{
    int ret = 0;

    if (desc == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = fetch_and_parse_manifest(desc);
    if (ret != 0) {
        ERROR("fetch and parse manifest failed");
        goto out;
    }

    // manifest schema1 cann't pull config, the config is composited by
    // the history[0].v1Compatibility in manifest and rootfs's diffID
    if (!is_manifest_schema1(desc->manifest.media_type)) {
        ret = fetch_and_parse_config(desc);
        if (ret != 0) {
            ERROR("fetch and parse config failed");
            goto out;
        }
    }

    ret = fetch_layers(desc);
    if (ret != 0) {
        ERROR("fetch layers failed");
        goto out;
    }

    // If it's manifest schema1, create config. The config is composited by
    // the history[0].v1Compatibility in manifest and rootfs's diffID
    // note: manifest schema1 has been deprecated.
    if (!is_manifest_schema1(desc->manifest.media_type)) {
        // TODO: transform config
    }

    ret = check_image(desc);
    if (ret != 0) {
        ERROR("check image failed, image invalid");
        goto out;
    }

out:

    return ret;
}

static int prepare_pull_desc(pull_descriptor *desc, registry_pull_options *options)
{
    int ret = 0;
    int sret = 0;
    char blobpath[32] = "/var/tmp/isulad-registry-XXXXXX";
    char scope[PATH_MAX] = {0};

    if (desc == NULL || options == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = oci_split_image_name(options->image_name, &desc->host,
                               &desc->name, &desc->tag);
    if (ret != 0) {
        ERROR("split image name %s failed", options->image_name);
        ret = -1;
        goto out;
    }

    if (desc->host == NULL || desc->name == NULL || desc->tag == NULL) {
        ERROR("Invalid image %s, host or name or tag not found", options->image_name);
        ret = -1;
        goto out;
    }

    // registry-1.docker.io is the real docker.io's registry. index.docker.io is V1 registry, we do not support
    // V1 registry, try use registry-1.docker.io.
    if (!strcmp(desc->host, DOCKER_HOSTNAME) || !strcmp(desc->host, DOCKER_V1HOSTNAME)) {
        free(desc->host);
        desc->host = util_strdup_s(DOCKER_REGISTRY);
    }

    if (mkdtemp(blobpath) == NULL) {
        ERROR("make temporary direcory failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    sret = snprintf(scope, sizeof(scope), "repository:%s:pull", desc->name);
    if (sret < 0 || (size_t)sret >= sizeof(scope)) {
        ERROR("Failed to sprintf scope");
        ret = -1;
        goto out;
    }

    desc->scope = util_strdup_s(scope);
    desc->blobpath = util_strdup_s(blobpath);
    desc->skip_tls_verify = options->comm_opt.skip_tls_verify;

out:

    return ret;
}

int registry_pull(registry_pull_options *options)
{
    int ret = 0;
    pull_descriptor *desc = NULL;

    if (options == NULL || options->image_name == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    desc = util_common_calloc_s(sizeof(pull_descriptor));
    if (desc == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = prepare_pull_desc(desc, options);
    if (ret != 0) {
        ERROR("registry prepare failed");
        ret = -1;
        goto out;
    }

    ret = registry_fetch(desc);
    if (ret != 0) {
        ERROR("error fetching %s", options->image_name);
        ret = -1;
        goto out;
    }

    ret = register_image(desc);
    if (ret != 0) {
        ERROR("error register image %s to store", options->image_name);
        ret = -1;
        goto out;
    }

    INFO("Pull images %s success", options->image_name);

out:
    if (desc->blobpath != NULL) {
        if (util_recursive_rmdir(desc->blobpath, 0)) {
            WARN("failed to remove directory %s", desc->blobpath);
        }
    }

    free_pull_desc(desc);

    return ret;
}

int registry_login(registry_login_options *options)
{
    return 0;
}

int registry_logout(char *auth_file_path, char *host)
{
    return 0;
}

static void free_registry_options(registry_options *options)
{
    if (options == NULL) {
        return;
    }
    free(options->cert_path);
    options->cert_path = NULL;
    free(options->auth_file_path);
    options->auth_file_path = NULL;
    free(options->use_decrypted_key);
    options->use_decrypted_key = NULL;
    return;
}

static void free_registry_auth(registry_auth *auth)
{
    if (auth == NULL) {
        return;
    }
    free_sensitive_string(auth->username);
    auth->username = NULL;
    free_sensitive_string(auth->password);
    auth->password = NULL;
    return;
}

void free_registry_pull_options(registry_pull_options *options)
{
    free_registry_options(&options->comm_opt);
    free_registry_auth(&options->auth);
    free(options->image_name);
    options->image_name = NULL;
    free(options);
    return;
}

void free_registry_login_options(registry_login_options *options)
{
    free_registry_options(&options->comm_opt);
    free_registry_auth(&options->auth);
    free(options->host);
    options->host = NULL;
    free(options);
    return;
}

void free_pull_desc(pull_descriptor *desc)
{
    return;
}
