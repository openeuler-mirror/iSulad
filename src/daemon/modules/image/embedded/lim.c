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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide image list functions
 ******************************************************************************/
#include <malloc.h>
#include <string.h>
#include <limits.h>

#include "error.h"
#include "isula_libutils/log.h"
#include "lim.h"
#include "err_msg.h"
#include "mediatype.h"
#include "snapshot.h"
#include "snapshot_def.h"
#include "isula_libutils/embedded_manifest.h"
#include "db_all.h"
#include "path.h"
#include "image_api.h"
#include "sha256.h"

/* lim init */
int lim_init(const char *rootpath)
{
    int ret = 0;

    if (rootpath == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    if (db_common_init(rootpath)) {
        ERROR("Failed to init database");
        ret = -1;
        goto out;
    }

    /* Param driver_type is reserved for later implement. */
    ret = snapshot_init(DRIVER_TYPE_INVALID);
    if (ret != 0) {
        ERROR("init driver failed");
        ret = -1;
        goto out;
    }

    ret = db_all_init();
    if (ret != 0) {
        ERROR("init database failed");
        ret = -1;
        goto out;
    }

    ret = db_delete_dangling_images();
    if (ret != 0) {
        ERROR("delete dangling images failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/* free image creator */
void free_image_creator(struct image_creator **ic)
{
    if (ic != NULL && *ic != NULL) {
        UTIL_FREE_AND_SET_NULL((*ic)->type);
        UTIL_FREE_AND_SET_NULL((*ic)->name);
        UTIL_FREE_AND_SET_NULL((*ic)->media_type);
        UTIL_FREE_AND_SET_NULL((*ic)->config_digest);
        free(*ic);
        *ic = NULL;
    }
    return;
}

/* lim create image start */
int lim_create_image_start(char *name, char *type, struct image_creator **pic)
{
    struct image_creator *ic = NULL;
    int ret = 0;

    if (type == NULL || pic == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }

    ic = (struct image_creator *)util_common_calloc_s(sizeof(struct image_creator));
    if (ic == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    if (strncmp(type, IMAGE_TYPE_EMBEDDED, strlen(IMAGE_TYPE_EMBEDDED)) == 0) {
        ic->type = util_strdup_s(type);
    } else {
        ERROR("invalid image type %s", type);
        ret = EINVALIDARGS;
        goto out;
    }

    /* assign only when success */
    *pic = ic;

out:
    if (ret != 0) {
        free_image_creator(&ic);
    }

    return ret;
}

/* valid relative path */
static bool valid_relative_path(char *path)
{
    if (path == NULL) {
        ERROR("invalid NULL path");
        return false;
    }

    if (path[0] == 0) {
        ERROR("invalid empty path");
        return false;
    }

    if (path[0] == '/') {
        ERROR("path %s not a relative path", path);
        return false;
    }

    return true;
}

/* valid absolute path */
static bool valid_absolute_path(char *path)
{
    if (path == NULL) {
        ERROR("invalid NULL path");
        return false;
    }

    if (path[0] == 0) {
        ERROR("invalid empty path");
        return false;
    }

    if (path[0] != '/') {
        ERROR("path %s not a absolute path", path);
        return false;
    }

    return true;
}

/* validate layer path in container */
static bool validate_layer_path_in_container(size_t layer_index, char *path)
{
    /* layer 0 does not contains path_in_container and digest, make sure it's empty. */
    if (layer_index == 0) {
        if (path != NULL && path[0] != 0) {
            ERROR("first layer's path in container must be empty, got %s", path);
            isulad_try_set_error_message("Invalid content in manifest: first layer path in container must be empty");
            return false;
        }
        return true;
    }

    if (!valid_absolute_path(path)) {
        ERROR("path in container %s should be absolute path, layer %llu", path, (unsigned long long)layer_index);
        isulad_try_set_error_message("Invalid content in manifest:"
                                     " layer path in container(except first layer) must be absolute path");
        return false;
    }
    return true;
}

/* validate layer path in host real */
static bool validate_layer_path_in_host_real(size_t layer_index, char *path_in_host, char *real_path, uint32_t fmod)
{
    if (!util_file_exists(real_path)) {
        ERROR("file not exist, path in host %s, real path is %s", path_in_host, real_path);
        isulad_try_set_error_message("Invalid content in manifest: layer not exists");
        return false;
    }

    if (!util_valid_file(real_path, fmod)) {
        ERROR("invalid path in host %s, real path is %s, layer %ld", path_in_host, real_path, layer_index);
        if (fmod == (uint32_t)S_IFREG) {
            isulad_try_set_error_message(
                "Invalid content in manifest: layer(except first layer) is not a regular file");
        } else if ((int)fmod == S_IFDIR) {
            isulad_try_set_error_message("Invalid content in manifest: layer(except first layer) is not a directory");
        } else if ((int)fmod == S_IFBLK) {
            isulad_try_set_error_message("Invalid content in manifest: layer is not block device");
        }
        return false;
    }
    return true;
}

/* validate layer path in host */
static bool validate_layer_path_in_host(size_t layer_index, const char *location, char *path_in_host, char *real_path,
                                        uint32_t fmod)
{
    char *abs_path = NULL;
    if (layer_index == 0) {
        /* layer 0 is absolute path of rootfs device  or host / */
        if (!valid_absolute_path(path_in_host)) {
            ERROR("path in host %s not a absolute path, layer %lu", path_in_host, layer_index);
            isulad_try_set_error_message("Invalid content in manifest: first layer path in host must be absolute path");
            return false;
        }

        if ((int)fmod == S_IFDIR && strcmp(path_in_host, "/") != 0) {
            ERROR("expected / as root, got %s, layer %lu", path_in_host, layer_index);
            isulad_try_set_error_message("Invalid content in manifest: first layer path in host must be /");
            return false;
        }
        abs_path = util_strdup_s(path_in_host);
        /* other layers must be relative path of squashfs image file */
    } else {
        char *tmp_path = NULL;
        char parent_location[PATH_MAX] = { 0 };
        int sret = 0;
        if (!valid_relative_path(path_in_host)) {
            ERROR("path in host %s not a relative path, layer %lu", path_in_host, layer_index);
            isulad_try_set_error_message("Invalid content in manifest:"
                                         " layer path in host(except first layer) must be relative path");
            return false;
        }
        abs_path = util_add_path(location, path_in_host);
        sret = snprintf(parent_location, sizeof(parent_location), "%s/..", location);
        if (sret < 0 || (size_t)sret >= sizeof(parent_location)) {
            ERROR("Failed to sprintf parent_location");
            isulad_try_set_error_message("Failed to sprintf parent_location");
            UTIL_FREE_AND_SET_NULL(abs_path);
            UTIL_FREE_AND_SET_NULL(tmp_path);
            return false;
        }
        tmp_path = follow_symlink_in_scope(abs_path, parent_location);
        if (tmp_path == NULL || !strncmp(tmp_path, "..", 2)) {
            ERROR("invalid layer path %s", path_in_host);
            isulad_try_set_error_message("Invalid content in manifest: layer not exists");
            UTIL_FREE_AND_SET_NULL(abs_path);
            UTIL_FREE_AND_SET_NULL(tmp_path);
            return false;
        }
        UTIL_FREE_AND_SET_NULL(tmp_path);
    }

    if (strlen(abs_path) > PATH_MAX || realpath(abs_path, real_path) == NULL) {
        ERROR("invalid layer path %s", abs_path);
        isulad_try_set_error_message("Invalid content in manifest: layer not exists");
        UTIL_FREE_AND_SET_NULL(abs_path);
        return false;
    }
    UTIL_FREE_AND_SET_NULL(abs_path);
    return validate_layer_path_in_host_real(layer_index, path_in_host, real_path, fmod);
}

/* validate layer media type */
static bool validate_layer_media_type(size_t layer_index, char *media_type, uint32_t *fmod)
{
    if (media_type != NULL) {
        if (strcmp(media_type, MediaTypeEmbeddedLayerSquashfs) == 0) {
            // first layer is block device, others are regular files.
            *fmod = layer_index ? S_IFREG : S_IFBLK;
            return true;
        }
        if (strcmp(media_type, MediaTypeEmbeddedLayerDir) == 0) {
            *fmod = S_IFDIR;
            return true;
        }
    }

    isulad_try_set_error_message(
        "Invalid content in manifest: layer's media type must be"
        " application/squashfs.image.rootfs.diff.img or application/bind.image.rootfs.diff.dir");
    ERROR("invalid layer media type %s", media_type);
    return false;
}

/* validate layer digest */
static bool validate_layer_digest(size_t layer_index, char *path, uint32_t fmod, char *digest)
{
    /* If no digest, do not check digest. Digest is optinal. */
    if (digest == NULL) {
        return true;
    }
    if (!digest[0]) {
        return true;
    }

    // first layer's digest must be empty
    if (layer_index == 0) {
        isulad_try_set_error_message("Invalid content in manifest: first layer's digest must be empty");
        ERROR("first layer's digest must be empty, got %s", digest);
    }

    /* If layer is a directory, digest must be empty */
    if ((int)fmod == S_IFDIR) {
        ERROR("Invalid digest %s, digest must be empty if media type is %s", digest, MediaTypeEmbeddedLayerDir);
        isulad_try_set_error_message("Invalid content in manifest: layer digest must be empty if mediaType is %s",
                                     MediaTypeEmbeddedLayerDir);
        return false;
    }

    /* check if digest format is valid */
    if (!util_valid_digest(digest)) {
        ERROR("invalid digest %s for layer", digest);
        isulad_try_set_error_message("Invalid content in manifest: layer(except first layer) has invalid digest");
        return false;
    }

    /* calc and check digest */
    if (!sha256_valid_digest_file(path, digest)) {
        isulad_try_set_error_message("Invalid content in manifest: layer(except first layer) has invalid digest");
        return false;
    }

    return true;
}

/* validate layer host files */
static bool validate_layer_host_files(size_t layer_index, const char *location, embedded_layers *layer)
{
    uint32_t fmod;
    char real_path[PATH_MAX] = { 0 };

    if (layer == NULL) {
        return false;
    }

    if (!validate_layer_media_type(layer_index, layer->media_type, &fmod)) {
        return false;
    }

    if (!validate_layer_path_in_host(layer_index, location, layer->path_in_host, real_path, fmod)) {
        return false;
    }

    return validate_layer_digest(layer_index, real_path, fmod, layer->digest);
}

/* validate layer size */
static bool validate_layer_size(size_t layer_index, embedded_layers *layer)
{
    if (layer == NULL) {
        return false;
    }

    if (layer->size < 0) {
        ERROR("invalid layer size %lld, layer %llu", (long long)layer->size, (unsigned long long)layer_index);
        isulad_try_set_error_message("Invalid content in manifest: layer's size must not be negative number");
        return false;
    }
    return true;
}

/* validate create time */
static bool validate_create_time(char *created)
{
    if (!util_valid_time_tz(created)) {
        ERROR("invalid created time %s, invalid format", created);
        isulad_try_set_error_message("Invalid content in manifest: invalid created time");
        return false;
    }

    return true;
}

/* validate image name */
static bool validate_image_name(char *image_name)
{
    if (image_name == NULL) {
        ERROR("image name not exist");
        isulad_try_set_error_message("Invalid content in manifest: image name not exist");
        return false;
    }

    if (strcmp(image_name, "none") == 0 || strcmp(image_name, "none:latest") == 0) {
        ERROR("image name %s must not be none or none:latest", image_name);
        isulad_try_set_error_message(
            "Image name 'none' or 'none:latest' in manifest is reserved, please use other name");
        return false;
    }

    if (!util_valid_embedded_image_name(image_name)) {
        ERROR("invalid image name %s", image_name);
        isulad_try_set_error_message("Invalid content in manifest: invalid image name");
        return false;
    }
    return true;
}

/* validate image layers number */
static bool validate_image_layers_number(size_t layers_len)
{
    if (layers_len > LAYER_NUM_MAX || layers_len < 1) {
        ERROR("invalid layers number %ld maxium is %d", layers_len, LAYER_NUM_MAX);
        isulad_try_set_error_message("Invalid content in manifest: layer empty or max depth exceeded");
        return false;
    }
    return true;
}

/* valid embedded manifest */
static bool valid_embedded_manifest(embedded_manifest *manifest, const char *path)
{
    size_t i = 0;

    if (manifest == NULL || path == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    if (!validate_image_layers_number(manifest->layers_len)) {
        return false;
    }

    if (manifest->schema_version != 1) {
        ERROR("invalid schema version %u", manifest->schema_version);
        isulad_try_set_error_message("Invalid content in manifest: schema version must be 1");
        return false;
    }

    if (manifest->media_type == NULL || strcmp(manifest->media_type, MediaTypeEmbeddedImageManifest) != 0) {
        ERROR("invalid manifest media type %s", manifest->media_type);
        isulad_try_set_error_message("Invalid content in manifest:"
                                     " manifest's media type must be application/embedded.manifest+json");
        return false;
    }

    if (!validate_image_name(manifest->image_name)) {
        return false;
    }

    if (!validate_create_time(manifest->created)) {
        return false;
    }

    for (i = 0; i < manifest->layers_len; i++) {
        if (!validate_layer_size(i, manifest->layers[i])) {
            return false;
        }
        // valitate path_in_host, media_type and digest
        if (!validate_layer_host_files(i, path, manifest->layers[i])) {
            return false;
        }

        if (!validate_layer_path_in_container(i, manifest->layers[i]->path_in_container)) {
            return false;
        }
    }

    return true;
}

static bool valid_manifest_and_get_size(embedded_manifest *manifest, const char *path, int64_t *image_size)
{
    size_t i = 0;
    int64_t size = 0;
    char real_path[PATH_MAX] = { 0 };
    char *abs_path = NULL;
    bool result = false;

    if (!valid_embedded_manifest(manifest, path)) {
        ERROR("check manifest valid failed");
        return false;
    }

    for (i = 1; i < (int)manifest->layers_len; i++) {
        abs_path = util_add_path(path, manifest->layers[i]->path_in_host);
        if (abs_path == NULL) {
            ERROR("Failed to add path: %s, %s", path, manifest->layers[i]->path_in_host);
            goto out;
        }
        if (strlen(abs_path) > PATH_MAX || !realpath(abs_path, real_path)) {
            ERROR("invalid file path %s", abs_path);
            isulad_try_set_error_message("Invalid content in manifest: layer not exists");
            goto out;
        }
        UTIL_FREE_AND_SET_NULL(abs_path);

        size = util_file_size(real_path);
        if (size < 0) {
            isulad_try_set_error_message("Calculate layer size failed");
            goto out;
        }

        if (INT64_MAX - size < *image_size) {
            ERROR("The layer size is too large!");
            isulad_try_set_error_message("The layer size is too large!");
            goto out;
        }
        *image_size += size;
    }

    result = true;

out:
    free(abs_path);
    return result;
}

/* lim add manifest */
int lim_add_manifest(struct image_creator *ic, char *path, char *digest, bool mv)
{
    int ret = 0;
    char *manifest_digest = NULL;
    embedded_manifest *manifest = NULL;
    parser_error err = NULL;
    int64_t image_size = 0;
    struct db_image imginfo = { 0 };

    if (ic == NULL || path == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }
    if (strcmp(ic->type, IMAGE_TYPE_EMBEDDED) != 0) {
        ERROR("invalid image type %s", ic->type);
        isulad_try_set_error_message("Invalid image type: image type must be embedded");
        return EINVALIDARGS;
    }

    /* calc and check digest */
    manifest_digest = sha256_full_file_digest(path);
    if (manifest_digest == NULL) {
        ERROR("calc full digest of %s failed", path);
        isulad_try_set_error_message("Invalid manifest: invalid digest");
        return -1;
    }

    if (digest != NULL) {
        if (strcmp(manifest_digest, digest) != 0) {
            ERROR("file %s digest %s not match %s", path, manifest_digest, digest);
            ret = EINVALIDARGS;
            isulad_try_set_error_message("Invalid manifest: invalid digest");
            goto out;
        }
    }

    manifest = embedded_manifest_parse_file(path, 0, &err);
    if (manifest == NULL) {
        ERROR("parse embedded manifest file %s failed", path);
        ret = EINVALIDARGS;
        isulad_try_set_error_message("Invalid content in manifest: parse manifest as a json file failed");
        goto out;
    }

    if (valid_manifest_and_get_size(manifest, path, &image_size) != true) {
        ret = EINVALIDARGS;
        goto out;
    }

    imginfo.image_name = manifest->image_name;
    imginfo.image_type = IMAGE_TYPE_EMBEDDED;
    imginfo.size = image_size;
    imginfo.layer_num = manifest->layers_len;
    imginfo.top_chainid = "";
    imginfo.top_cacheid = "";
    /* manifest contains config. We use manifest as config,
     * user should parse it when using config */
    imginfo.config_digest = manifest_digest;
    imginfo.config_cacheid = "";
    imginfo.config_path = path;
    imginfo.created = manifest->created;
    /* layer 0 is used as rootfs in embedded image */
    imginfo.mount_string = manifest->layers[0]->path_in_host;
    imginfo.config = util_read_text_file(path);
    if (imginfo.config == NULL) {
        ERROR("read manifest data failed");
        ret = -1;
        goto out;
    }

    ret = db_save_image(&imginfo);
    if (ret != 0) {
        ERROR("Failed to save the image to DB, ret is %d", ret);
        if (ret == DB_NAME_CONFLICT) {
            isulad_try_set_error_message("Image name is conflicted in the database");
            ret = ENAMECONFLICT;
        } else {
            ret = -1;
        }
        goto out;
    }

    INFO("Load image %s success", manifest->image_name);

out:
    free(imginfo.config);
    free(manifest_digest);
    free(err);
    free_embedded_manifest(manifest);

    return ret;
}

/* lim create image end */
int lim_create_image_end(struct image_creator *ic)
{
    int ret = 0;

    if (ic == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    if (strcmp(ic->type, IMAGE_TYPE_EMBEDDED) != 0) {
        ERROR("invalid image type %s", ic->type);
        return -1;
    }

    free_image_creator(&ic);

    return ret;
}

/* image type to driver type */
uint32_t image_type_to_driver_type(const char *image_type)
{
    if (image_type == NULL) {
        ERROR("invalid NULL param");
        return DRIVER_TYPE_INVALID;
    }

    /* only support embedded currently */
    if (strcmp(image_type, IMAGE_TYPE_EMBEDDED) == 0) {
        return DRIVER_TYPE_EMBEDDED;
    } else {
        return DRIVER_TYPE_INVALID;
    }
}

/* lim delete image */
int lim_delete_image(char *name, bool force)
{
    struct db_image *imginfo = NULL;
    int ret = 0;

    if (name == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }

    ret = db_read_image(name, &imginfo);
    if (ret != 0) {
        ERROR("can't find image %s in database", name);
        isulad_try_set_error_message("No such image:%s", name);
        ret = EIMAGENOTFOUND;
        goto out;
    }

    /* delete image name from database */
    ret = db_delete_image(name, force);
    if (ret < 0) {
        ERROR("delete image %s in database failed", name);
        ret = -1;
        goto out;
    } else if (ret == DB_DEL_NAME_ONLY) { /* no need to delete layers */
        DEBUG("delete image name %s only, no need to delete layers", name);
        ret = 0;
        goto out;
    } else if (ret == DB_INUSE) {
        ERROR("image %s is in use", name);
        isulad_try_set_error_message("Image is in use");
        ret = EIMAGEBUSY;
        goto out;
    } else if (ret == DB_NOT_EXIST) {
        ERROR("image %s not exist", name);
        isulad_try_set_error_message("No such image:%s", name);

        ret = EIMAGENOTFOUND;
        goto out;
    } else {
        INFO("Delete image %s success", name);
    }

out:
    db_image_free(&imginfo);

    return ret;
}

/* lim query images */
int lim_query_images(void *images_info)
{
    struct db_all_images **info = (struct db_all_images **)images_info;
    int ret = 0;

    if (info == NULL) {
        ERROR("invalid NULL param");
        ret = -1;
        goto out;
    }

    ret = db_read_all_images_info(info);
    if (ret == DB_NOT_EXIST) {
        WARN("Failed to find image in database");
        ret = EIMAGENOTFOUND;
    } else if (ret != 0) {
        ERROR("Failed to find image in database");
    }
out:

    return ret;
}

/* lim create rw layer */
int lim_create_rw_layer(char *name, const char *id, char **options, char **mount_string)
{
    int ret = 0;
    struct db_image *imginfo = NULL;
    uint32_t driver_type = DRIVER_TYPE_INVALID;

    if (name == NULL || id == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }

    ret = db_read_image(name, &imginfo);
    if (ret != 0) {
        ERROR("can't find image %s in database", name);
        isulad_try_set_error_message("No such image:%s", name);
        ret = EIMAGENOTFOUND;
        goto out;
    }

    driver_type = image_type_to_driver_type(imginfo->image_type);
    if (driver_type > DRIVER_TYPE_NUM) {
        ERROR("get driver type from image type %s failed", imginfo->image_type);
        ret = EINVALIDARGS;
        goto out;
    }

    if (mount_string != NULL) {
        ret = snapshot_generate_mount_string(driver_type, imginfo, NULL, mount_string);
        if (ret) {
            ERROR("generate mount string failed");
            goto out;
        }
    }

out:
    db_image_free(&imginfo);

    return ret;
}

static bool valid_param(const char *name, const char *type, char **data)
{
    if (name == NULL || type == NULL || data == NULL) {
        return false;
    }

    return true;
}

/* lim query image data */
int lim_query_image_data(const char *name, const char *type, char **data, char **image_type)
{
    struct db_image *imginfo = NULL;
    int ret = 0;

    if (valid_param(name, type, data) != true) {
        ERROR("invalid NULL param");
        return -1;
    }

    ret = db_read_image((char *)name, &imginfo);
    if (ret != 0 || imginfo == NULL) {
        ERROR("can't find image %s in database", name);
        ret = -1;
        isulad_try_set_error_message("No such image:%s", name);
        goto out;
    }

    if (imginfo->image_type == NULL || imginfo->config_path == NULL || imginfo->config == NULL) {
        ERROR("image info NULL");
        ret = -1;
        goto out;
    }

    if (strcmp(type, IMAGE_DATA_TYPE_CONFIG_PATH) == 0) {
        *data = util_strdup_s(imginfo->config_path);
    } else if (strcmp(type, IMAGE_DATA_TYPE_CONFIG) == 0) {
        *data = util_strdup_s(imginfo->config);

        if (image_type != NULL) {
            *image_type = util_strdup_s(imginfo->image_type);
        }
    } else {
        ERROR("unsupported image data type %s", type);
        ret = -1;
        goto out;
    }

out:
    if (imginfo != NULL) {
        db_image_free(&imginfo);
    }

    if (ret != 0) {
        UTIL_FREE_AND_SET_NULL(*data);
        if (image_type != NULL) {
            UTIL_FREE_AND_SET_NULL(*image_type);
        }
    }

    return ret;
}
