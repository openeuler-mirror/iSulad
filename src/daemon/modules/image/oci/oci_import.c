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
* Create: 2020-05-26
* Description: isula image import operator implement
*******************************************************************************/
#include <errno.h>
#include <isula_libutils/container_config.h>
#include <isula_libutils/docker_image_history.h>
#include <isula_libutils/docker_image_rootfs.h>
#include <isula_libutils/imagetool_image.h>
#include <isula_libutils/json_common.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mediatype.h"
#include "oci_import.h"
#include "isula_libutils/log.h"
#include "storage.h"
#include "err_msg.h"
#include "utils.h"
#include "isula_libutils/registry_manifest_schema2.h"
#include "isula_libutils/docker_image_config_v2.h"
#include "util_archive.h"
#include "utils_images.h"
#include "sha256.h"
#include "utils_file.h"
#include "utils_timestamp.h"

#define IMPORT_COMMENT "Imported from tarball"
#define ROOTFS_TYPE "layers"
#define MANIFEST_BIG_DATA_KEY "manifest"
#define TIME_BUF_MAX_LEN 128
#define TEMP_FILE_TEMPLATE IMAGE_TMP_PATH "import-XXXXXX"

typedef struct {
    char *manifest;
    char *manifest_digest;
    char *config;
    char *config_digest;
    char *uncompressed_digest;
    char *compressed_digest;
    int64_t compressed_size;
    types_timestamp_t now_time;
    char *tag;
    char *uncompressed_file;
} import_desc;

static void free_import_desc(import_desc *desc)
{
    if (desc == NULL) {
        return;
    }

    free(desc->manifest);
    desc->manifest = NULL;
    free(desc->manifest_digest);
    desc->manifest_digest = NULL;
    free(desc->config);
    desc->config = NULL;
    free(desc->config_digest);
    desc->config_digest = NULL;
    free(desc->uncompressed_digest);
    desc->uncompressed_digest = NULL;
    free(desc->compressed_digest);
    desc->compressed_digest = NULL;
    free(desc->tag);
    desc->tag = NULL;
    free(desc->uncompressed_digest);
    desc->uncompressed_digest = NULL;
    free(desc->uncompressed_file);
    desc->uncompressed_file = NULL;

    free(desc);

    return;
}

static int register_layer(import_desc *desc)
{
    char *id = NULL;
    struct layer *l = NULL;

    if (desc == NULL || desc->uncompressed_digest == NULL || desc->compressed_digest == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    id = without_sha256_prefix(desc->uncompressed_digest);
    if (id == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    l = storage_layer_get(id);
    if (l != NULL) {
        free_layer(l);
        l = NULL;
        return 0;
    } else {
        storage_layer_create_opts_t copts = {
            .parent = NULL,
            .uncompress_digest = desc->uncompressed_digest,
            .compressed_digest = desc->compressed_digest,
            .writable = false,
            .layer_data_path = desc->uncompressed_file,
        };
        return storage_layer_create(id, &copts);
    }
}

static int create_config(import_desc *desc)
{
    int ret = 0;
    docker_image_config_v2 *config = NULL;
    char *host_os = NULL;
    char *host_arch = NULL;
    char *host_variant = NULL;
    parser_error err = NULL;
    char time_str[TIME_BUF_MAX_LEN] = { 0 };

    if (desc == NULL || desc->uncompressed_digest == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    config = util_common_calloc_s(sizeof(docker_image_config_v2));
    if (config == NULL) {
        ERROR("out of memory");
        return -1;
    }

    ret = normalized_host_os_arch(&host_os, &host_arch, &host_variant);
    if (ret != 0) {
        ERROR("get host os and arch for import failed");
        isulad_try_set_error_message("get host os and arch for import failed");
        goto out;
    }

    config->rootfs = util_common_calloc_s(sizeof(docker_image_rootfs));
    config->config = util_common_calloc_s(sizeof(container_config));
    config->container_config = util_common_calloc_s(sizeof(container_config));
    config->history = util_common_calloc_s(sizeof(docker_image_history *));
    if (config->history == NULL || config->config == NULL || config->container_config == NULL ||
        config->rootfs == NULL) {
        ERROR("out of memory");
        isulad_try_set_error_message("out of memory");
        ret = -1;
        goto out;
    }
    config->history_len = 1;
    config->rootfs->type = util_strdup_s(ROOTFS_TYPE);

    config->rootfs->diff_ids = util_common_calloc_s(sizeof(char *));
    if (config->rootfs->diff_ids == NULL) {
        ERROR("out of memory");
        isulad_try_set_error_message("out of memory");
        ret = -1;
        goto out;
    }
    config->rootfs->diff_ids_len = 1;

    config->history[0] = util_common_calloc_s(sizeof(docker_image_history));
    if (config->history[0] == NULL) {
        ERROR("out of memory");
        isulad_try_set_error_message("out of memory");
        ret = -1;
        goto out;
    }

    if (!get_time_buffer(&desc->now_time, time_str, TIME_BUF_MAX_LEN)) {
        ERROR("get time string from timestamp failed");
        isulad_try_set_error_message("get time string from timestamp failed");
        ret = -1;
        goto out;
    }

    config->history[0]->comment = util_strdup_s(IMPORT_COMMENT);
    config->history[0]->created = util_strdup_s(time_str);

    config->rootfs->diff_ids[0] = util_strdup_s(desc->uncompressed_digest);

    config->comment = util_strdup_s(IMPORT_COMMENT);
    config->created = util_strdup_s(time_str);
    config->os = host_os;
    host_os = NULL;
    config->architecture = host_arch;
    host_arch = NULL;

    desc->config = docker_image_config_v2_generate_json(config, NULL, &err);
    if (desc->config == NULL) {
        ERROR("generate default config for import failed: %s", err);
        isulad_try_set_error_message("generate default config for import failed: %s", err);
        ret = -1;
        goto out;
    }

    desc->config_digest = sha256_full_digest_str(desc->config);
    if (desc->config_digest == NULL) {
        ERROR("calc digest of config for import failed");
        isulad_try_set_error_message("calc digest of config for import failed");
        ret = -1;
        goto out;
    }

out:
    free(err);
    err = NULL;
    free(host_os);
    host_os = NULL;
    free(host_arch);
    host_arch = NULL;
    free(host_variant);
    host_variant = NULL;
    free_docker_image_config_v2(config);
    config = NULL;

    return ret;
}

static int create_manifest(import_desc *desc)
{
    int ret = 0;
    registry_manifest_schema2 *manifest = NULL;
    parser_error err = NULL;

    if (desc == NULL || desc->compressed_digest == NULL || desc->config == NULL || desc->config_digest == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    manifest = util_common_calloc_s(sizeof(registry_manifest_schema2));
    if (manifest == NULL) {
        ERROR("out of memory");
        isulad_try_set_error_message("out of memory");
        ret = -1;
        goto out;
    }

    manifest->config = util_common_calloc_s(sizeof(registry_manifest_schema2_config));
    manifest->layers = util_common_calloc_s(sizeof(registry_manifest_schema2_layers_element *));
    if (manifest->config == NULL || manifest->layers == NULL) {
        ERROR("out of memory");
        isulad_try_set_error_message("out of memory");
        ret = -1;
        goto out;
    }
    manifest->layers_len = 1;

    manifest->layers[0] = util_common_calloc_s(sizeof(registry_manifest_schema2_layers_element *));
    if (manifest->layers[0] == NULL) {
        ERROR("out of memory");
        isulad_try_set_error_message("out of memory");
        ret = -1;
        goto out;
    }

    manifest->config->size = strlen(desc->config);
    manifest->config->media_type = util_strdup_s(DOCKER_IMAGE_V1);
    manifest->config->digest = util_strdup_s(desc->config_digest);

    manifest->layers[0]->media_type = util_strdup_s(DOCKER_IMAGE_LAYER_TAR_GZIP);
    manifest->layers[0]->size = desc->compressed_size;
    manifest->layers[0]->digest = util_strdup_s(desc->compressed_digest);

    manifest->schema_version = 2;
    manifest->media_type = util_strdup_s(DOCKER_MANIFEST_SCHEMA2_JSON);

    desc->manifest = registry_manifest_schema2_generate_json(manifest, NULL, &err);
    if (desc->manifest == NULL) {
        ERROR("generate default manifest for import failed: %s", err);
        isulad_try_set_error_message("generate default manifest for import failed: %s", err);
        ret = -1;
        goto out;
    }

    desc->manifest_digest = sha256_full_digest_str(desc->manifest);
    if (desc->manifest_digest == NULL) {
        ERROR("calc digest of manifest for import failed");
        isulad_try_set_error_message("calc digest of manifest for import failed");
        ret = -1;
        goto out;
    }

out:
    free(err);
    err = NULL;
    free_registry_manifest_schema2(manifest);
    manifest = NULL;

    return ret;
}

static int register_image(import_desc *desc)
{
    int ret = 0;
    char *image_id = NULL;
    char *pre_top_layer = NULL;
    char *top_layer_id = NULL;
    bool image_created = false;
    struct storage_img_create_options opts = { 0 };

    if (desc == NULL || desc->manifest == NULL || desc->manifest_digest == NULL || desc->config == NULL ||
        desc->config_digest == NULL || desc->uncompressed_digest == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    opts.create_time = &desc->now_time;
    opts.digest = desc->manifest_digest;

    image_id = without_sha256_prefix(desc->config_digest);
    top_layer_id = without_sha256_prefix(desc->uncompressed_digest);
    ret = storage_img_create(image_id, top_layer_id, NULL, &opts);
    if (ret != 0) {
        pre_top_layer = storage_get_img_top_layer(image_id);
        if (pre_top_layer == NULL) {
            ERROR("create image %s for %s failed", image_id, desc->tag);
            ret = -1;
            goto out;
        }

        if (strcmp(pre_top_layer, top_layer_id) != 0) {
            ERROR("error committing image, image id %s exist, but top layer doesn't match. local %s, import %s",
                  image_id, pre_top_layer, top_layer_id);
            ret = -1;
            goto out;
        }

        ret = 0;
    }

    image_created = true;

    ret = storage_img_add_name(image_id, desc->tag);
    if (ret != 0) {
        ERROR("add image name %s failed", desc->tag);
        goto out;
    }

    ret = storage_img_set_big_data(image_id, desc->config_digest, desc->config);
    if (ret != 0) {
        ERROR("set config for import %s failed", desc->tag);
        goto out;
    }

    ret = storage_img_set_big_data(image_id, MANIFEST_BIG_DATA_KEY, desc->manifest);
    if (ret != 0) {
        ERROR("set manifest for import %s failed", desc->tag);
        goto out;
    }

    ret = storage_img_set_loaded_time(image_id, &desc->now_time);
    if (ret != 0) {
        ERROR("set loaded time failed");
        goto out;
    }

    ret = storage_img_set_image_size(image_id);
    if (ret != 0) {
        ERROR("set image size failed for %s failed", desc->tag);
        isulad_try_set_error_message("set image size failed");
        goto out;
    }

out:

    if (ret != 0 && image_created) {
        if (storage_img_delete(image_id, true)) {
            ERROR("delete image %s failed", image_id);
        }
    }

    return ret;
}

static char *create_temp_file()
{
    int fd = -1;
    char temp_file[] = TEMP_FILE_TEMPLATE;

    fd = mkstemp(temp_file);
    if (fd < 0) {
        ERROR("make temporary file failed: %s", strerror(errno));
        isulad_try_set_error_message("make temporary file failed: %s", strerror(errno));
        return NULL;
    }
    close(fd);

    return util_strdup_s(temp_file);
}

static import_desc *prepre_import(char *file, char *tag)
{
    int ret = 0;
    import_desc *desc = NULL;
    char *errmsg = NULL;

    desc = util_common_calloc_s(sizeof(import_desc));
    if (desc == NULL) {
        ERROR("out of memory");
        isulad_try_set_error_message("out of memory");
        return NULL;
    }

    desc->compressed_size = util_file_size(file);
    if (desc->compressed_size < 0) {
        ERROR("Calc size of file %s for import failed", file);
        isulad_try_set_error_message("Calc size of file %s for import failed", file);
        ret = -1;
        goto out;
    }

    desc->compressed_digest = sha256_full_file_digest(file);
    if (desc->compressed_digest == NULL) {
        ERROR("Calc compressed digest of file %s failed", file);
        isulad_try_set_error_message("Calc compressed digest of file %s failed", file);
        ret = -1;
        goto out;
    }

    desc->uncompressed_file = create_temp_file();
    if (desc->uncompressed_file == NULL) {
        ERROR("create temporary file for import failed");
        isulad_try_set_error_message("create temporary file for import failed");
        ret = -1;
        goto out;
    }

    ret = archive_uncompress(file, desc->uncompressed_file, &errmsg);
    if (ret != 0) {
        ERROR("uncompress %s for import failed: %s", file, errmsg);
        isulad_try_set_error_message("uncompress %s for import failed: %s", file, errmsg);
        ret = -1;
        goto out;
    }

    desc->uncompressed_digest = sha256_full_file_digest(desc->uncompressed_file);
    if (desc->uncompressed_digest == NULL) {
        ERROR("Calc uncompressed digest of file %s failed", file);
        isulad_try_set_error_message("Calc uncompressed digest of file %s failed", file);
        ret = -1;
        goto out;
    }

    if (!get_now_time_stamp(&desc->now_time)) {
        ERROR("get time stamp for import failed");
        isulad_try_set_error_message("get time stamp for import failed");
        ret = -1;
        goto out;
    }
    desc->tag = util_strdup_s(tag);

out:
    if (ret != 0) {
        free_import_desc(desc);
        desc = NULL;
    }
    free(errmsg);
    errmsg = NULL;

    return desc;
}

static int do_import(char *file, char *tag)
{
    int ret = 0;
    import_desc *desc = NULL;

    if (file == NULL || tag == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    desc = prepre_import(file, tag);
    if (desc == NULL) {
        ERROR("Prepare import %s to be %s failed", file, tag);
        isulad_try_set_error_message("Prepare import failed");
        return -1;
    }

    ret = register_layer(desc);
    if (ret != 0) {
        ERROR("Register layer from file %s for import failed", file);
        isulad_try_set_error_message("Register layer from file %s for import failed", file);
        goto out;
    }

    ret = create_config(desc);
    if (ret != 0) {
        ERROR("Create config for import failed");
        isulad_try_set_error_message("Create config for import failed");
        ret = -1;
        goto out;
    }

    ret = create_manifest(desc);
    if (ret != 0) {
        ERROR("Create manifest for import failed");
        isulad_try_set_error_message("Create manifest for import failed");
        ret = -1;
        goto out;
    }

    ret = register_image(desc);
    if (ret != 0) {
        ERROR("Register image for import failed");
        isulad_try_set_error_message("Register image for import failed");
        goto out;
    }

out:
    if (desc->uncompressed_file != NULL) {
        if (util_path_remove(desc->uncompressed_file)) {
            WARN("failed to remove file %s: %s", desc->uncompressed_file, strerror(errno));
        }
    }
    free_import_desc(desc);
    desc = NULL;

    return ret;
}

int oci_do_import(char *file, char *tag, char **id)
{
    int ret = 0;
    imagetool_image *image = NULL;

    if (file == NULL || tag == NULL || id == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    ret = do_import(file, tag);
    if (ret != 0) {
        ERROR("import %s failed", tag);
        goto out;
    }

    image = storage_img_get(tag);
    if (image == NULL) {
        ERROR("get image %s failed after import", tag);
        isulad_try_set_error_message("get image %s failed after import", tag);
        ret = -1;
        goto out;
    }

    *id = util_strdup_s(image->id);

out:
    free_imagetool_image(image);

    return ret;
}

void oci_import_cleanup()
{
    return;
}
