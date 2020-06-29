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
 * Explanation: provide image functions
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <ctype.h>

#include "containers_store.h"
#include "specs_extend.h"
#include "isula_libutils/log.h"
#include "embedded_image.h"
#include "lim.h"
#include "embedded_config_merge.h"
#include "db_all.h"
#include "utils.h"

static bool embedded_image_exist(const char *image_name)
{
    bool ret = false;
    int nret = 0;
    struct db_image *imginfo = NULL;

    nret = db_read_image(image_name, &imginfo);
    if (nret != 0) {
        WARN("can't find image %s in database", image_name);
        goto out;
    }

    ret = true;

out:
    db_image_free(&imginfo);
    return ret;
}

bool embedded_detect(const char *image_name)
{
    if (image_name == NULL || !util_valid_embedded_image_name(image_name)) {
        WARN("invalid image name: %s", image_name != NULL ? image_name : "");
        isulad_set_error_message("Invalid image name '%s'", image_name != NULL ? image_name : "");
        return false;
    }

    return embedded_image_exist(image_name);
}

char *embedded_resolve_image_name(const char *image_name)
{
    return util_strdup_s(image_name);
}
int embedded_filesystem_usage(const im_container_fs_usage_request *request, imagetool_fs_info **fs_usage)
{
    return 0;
}

int embedded_prepare_rf(const im_prepare_request *request, char **real_rootfs)
{
    if (request == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    return lim_create_rw_layer(request->image_name, request->container_id, NULL, real_rootfs);
}

int embedded_mount_rf(const im_mount_request *request)
{
    return 0;
}

int embedded_umount_rf(const im_umount_request *request)
{
    return 0;
}

int embedded_delete_rf(const im_delete_rootfs_request *request)
{
    return 0;
}

static int do_merge_embedded_image_conf(const char *image_name, container_config *container_spec)
{
    int ret = 0;
    char *image_config = NULL;
    char *image_type = NULL;

    if (container_spec == NULL || image_name == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    ret = lim_query_image_data(image_name, IMAGE_DATA_TYPE_CONFIG, &image_config, &image_type);
    if (ret != 0 || image_config == NULL || image_type == NULL) {
        ERROR("query image data for image %s failed", image_name);
        goto out;
    }

    if (strcmp(image_type, IMAGE_TYPE_EMBEDDED) == 0) {
        ret = embedded_image_merge_config(image_config, container_spec);
        if (ret != 0) {
            goto out;
        }
    } else {
        ERROR("unsupported image type %s", image_type);
        ret = -1;
        goto out;
    }

out:
    free(image_config);
    free(image_type);

    return ret;
}

int embedded_merge_conf(const char *img_name, container_config *container_spec)
{
    int ret = 0;

    if (img_name == NULL || container_spec == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    ret = do_merge_embedded_image_conf(img_name, container_spec);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

int embedded_get_user_conf(const char *basefs, host_config *hc, const char *userstr, defs_process_user *puser)
{
    if (puser == NULL) {
        ERROR("Empty basefs or puser");
        return -1;
    }
    return get_user("/", hc, userstr, puser);
}

static int embedded_images_to_imagetool_images(struct db_all_images *all_images, imagetool_images_list *list)
{
    int ret = 0;
    size_t images_num = 0;
    size_t i = 0;
    struct db_image *tmp_embedded = NULL;

    images_num = all_images->imagesnum;
    if (images_num == 0) {
        goto out;
    }

    if (images_num >= (SIZE_MAX / sizeof(imagetool_image *))) {
        ERROR("Too many images, out of memory");
        ret = -1;
        isulad_try_set_error_message("Get too many images info, out of memory");
        goto out;
    }
    list->images = util_common_calloc_s(sizeof(imagetool_image *) * images_num);
    if (list->images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < images_num; i++) {
        tmp_embedded = all_images->images_info[i];

        list->images[i] = util_common_calloc_s(sizeof(imagetool_image));
        if (list->images[i] == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        list->images_len++;

        /* NOTE: embedded image do not have id, use config digest as image id,
         * but can not use this id to manage the image or run container.
         */
        if (tmp_embedded->config_digest != NULL) {
            const char *psha = strstr(tmp_embedded->config_digest, SHA256_PREFIX);
            if (psha != NULL) {
                list->images[i]->id = util_strdup_s(psha + strlen(SHA256_PREFIX));
            } else {
                list->images[i]->id = util_strdup_s(tmp_embedded->config_digest);
            }
        }

        list->images[i]->repo_tags = util_common_calloc_s(sizeof(char *));
        if (list->images[i]->repo_tags == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        list->images[i]->repo_tags[0] = util_strdup_s(tmp_embedded->image_name);
        list->images[i]->repo_tags_len++;

        list->images[i]->repo_digests = util_common_calloc_s(sizeof(char *));
        if (list->images[i]->repo_digests == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        list->images[i]->repo_digests[0] = util_strdup_s(tmp_embedded->config_digest);
        list->images[i]->repo_digests_len++;

        list->images[i]->size = (uint64_t)tmp_embedded->size;

        list->images[i]->created = util_strdup_s(tmp_embedded->created);
    }

out:
    return ret;
}

int embedded_list_images(const im_list_request *request, imagetool_images_list **list)
{
    int ret = 0;
    struct db_all_images *all_images = NULL;

    *list = util_common_calloc_s(sizeof(imagetool_images_list));
    if (*list == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    if (request->filter.image.image != NULL || request->image_filters != NULL) {
        INFO("Embedded images do not support filter");
        ret = 0;
        goto out;
    }

    ret = lim_query_images(&all_images);
    /* no images found, success should be returned */
    if (ret == EIMAGENOTFOUND) {
        INFO("No image Found");
        ret = 0;
        goto out;
    } else if (ret != 0 || all_images == NULL || all_images->imagesnum == 0) {
        ERROR("Get image info failed");
        ret = -1;
        isulad_try_set_error_message("Get image info failed");
        goto out;
    }

    ret = embedded_images_to_imagetool_images(all_images, *list);
    if (ret != 0) {
        ERROR("Failed to translate embedded images to imagetool images");
        ret = -1;
        isulad_try_set_error_message("Failed to translate embedded images to imagetool images");
        goto out;
    }

out:
    if (ret != 0) {
        free_imagetool_images_list(*list);
        *list = NULL;
    }
    if (all_images != NULL) {
        db_all_imginfo_free(all_images);
    }

    return ret;
}

int embedded_remove_image(const im_rmi_request *request)
{
    bool force = false;
    char *image_ref = NULL;
    int ret = 0;
    size_t i = 0;
    size_t container_num = 0;
    container_t **conts = NULL;

    force = request->force;
    image_ref = request->image.image;

    if (!force) {
        ret = containers_store_list(&conts, &container_num);
        if (ret != 0) {
            ERROR("query all containers info failed");
            ret = -1;
            goto out;
        }
        /* check if container is using this image */
        for (i = 0; i < container_num; i++) {
            if (ret != 0) {
                goto unref_continue;
            }
            if (conts[i]->common_config->image == NULL) {
                goto unref_continue;
            }

            if (strcmp(conts[i]->common_config->image, image_ref) == 0) {
                ERROR("unable to remove image %s, container %s is using it", image_ref, conts[i]->common_config->id);
                isulad_set_error_message("Image is in use");
                ret = EIMAGEBUSY;
                goto unref_continue;
            }
unref_continue:
            container_unref(conts[i]);
            continue;
        }
        if (ret != 0) {
            ret = -1;
            goto out;
        }
    }

    ret = lim_delete_image(image_ref, force);

out:
    free(conts);
    return ret;
}

int embedded_inspect_image(const im_inspect_request *request, char **inspected_json)
{
    char *image_ref = NULL;

    if (request == NULL || inspected_json == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    image_ref = request->image.image;

    return lim_query_image_data(image_ref, IMAGE_DATA_TYPE_CONFIG, inspected_json, NULL);
}

int embedded_init(const isulad_daemon_configs *args)
{
    if (args == NULL) {
        ERROR("Invalid image configs");
        return -1;
    }

    return lim_init(args->graph);
}

void embedded_exit()
{
    db_common_finish();
}
