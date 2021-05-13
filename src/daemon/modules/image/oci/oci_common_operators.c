/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuhao
 * Create: 2019-07-23
 * Description: provide image common function definition
 ******************************************************************************/
#include "oci_common_operators.h"

#include <stdio.h>
#include <string.h>
#include <isula_libutils/imagetool_image.h>
#include <isula_libutils/imagetool_image_status.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_image_spec.h>
#include <stdint.h>
#include <stdlib.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_images.h"
#include "oci_config_merge.h"
#include "image_rootfs_handler.h"
#include "err_msg.h"
#include "filters.h"
#include "storage.h"
#include "map.h"
#include "utils_timestamp.h"
#include "utils_verify.h"

bool oci_detect(const char *image_name)
{
    if (image_name == NULL) {
        return false;
    }

    return storage_image_exist(image_name);
}

char *oci_resolve_image_name(const char *name)
{
    if (name == NULL) {
        return NULL;
    }

    if (util_valid_short_sha256_id(name) && storage_image_exist(name)) {
        return util_strdup_s(name);
    }

    return oci_normalize_image_name(name);
}

int oci_get_user_conf(const char *basefs, host_config *hc, const char *userstr, defs_process_user *puser)
{
    if (basefs == NULL || puser == NULL) {
        ERROR("Empty basefs or puser");
        return -1;
    }
    return get_user_from_image_roofs(basefs, hc, userstr, puser);
}

static int oci_list_all_images(imagetool_images_list *images_list)
{
    return storage_get_all_images(images_list);
}

static bool image_meet_dangling_filter(const imagetool_image_summary *src, const struct filters_args *filters)
{
    bool ret = false;
    map_t *field_values_map = NULL;
    const char *field = "dangling";
    map_itor *itor = NULL;
    bool dangling_value = false;

    field_values_map = map_search(filters->fields, (void *)field);
    if (field_values_map == NULL) {
        return true;
    }

    itor = map_itor_new(field_values_map);
    if (itor == NULL) {
        ERROR("Out of memory");
        return false;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        if (strcmp(map_itor_key(itor), "true") == 0) {
            dangling_value = true;
            break;
        }
    }

    if (dangling_value) {
        ret = src->repo_tags_len == 0;
    } else {
        ret = src->repo_tags_len != 0;
    }

    map_itor_free(itor);
    return ret;
}

static int do_image_time_filter(map_itor *itor, bool is_before_filter, int64_t *cmp_nanos)
{
    int ret = 0;
    int64_t tmp_nanos = 0;
    imagetool_image_summary *image_summary = NULL;

    char *tmp = oci_resolve_image_name(map_itor_key(itor));
    if (tmp == NULL) {
        ERROR("Failed to resolve image name");
        goto out;
    }

    image_summary = storage_img_get_summary(tmp);
    if (image_summary == NULL) {
        ret = -1;
        goto out;
    }

    if (util_to_unix_nanos_from_str(image_summary->created, &tmp_nanos) != 0) {
        ERROR("Failed to get unix nano from string");
        ret = -1;
        goto out;
    }

    if (is_before_filter) {
        if (*cmp_nanos > tmp_nanos) {
            *cmp_nanos = tmp_nanos;
        }
    } else {
        if (*cmp_nanos < tmp_nanos) {
            *cmp_nanos = tmp_nanos;
        }
    }

out:
    free_imagetool_image_summary(image_summary);
    free(tmp);
    return ret;
}

static bool image_time_filter(const imagetool_image_summary *src, const struct filters_args *filters, const char *field)
{
    bool ret = false;
    map_t *field_values_map = NULL;
    map_itor *itor = NULL;
    bool is_before_filter = true;
    int64_t cmp_nanos;
    int64_t tmp_nanos = 0;

    is_before_filter = (strcmp(field, "before") == 0);
    cmp_nanos = is_before_filter ? INT64_MAX : 0;

    field_values_map = map_search(filters->fields, (void *)field);
    if (field_values_map == NULL) {
        return true;
    }

    itor = map_itor_new(field_values_map);
    if (itor == NULL) {
        ERROR("Out of memory");
        return false;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        if (do_image_time_filter(itor, is_before_filter, &cmp_nanos) != 0) {
            goto out;
        }
    }

    if (util_to_unix_nanos_from_str(src->created, &tmp_nanos) != 0) {
        ERROR("Failed to get unix nano from string");
        goto out;
    }

    if (is_before_filter) {
        if (tmp_nanos < cmp_nanos) {
            ret = true;
        }
    } else {
        if (tmp_nanos > cmp_nanos) {
            ret = true;
        }
    }

out:
    map_itor_free(itor);
    return ret;
}

static bool image_meet_before_filter(const imagetool_image_summary *src, const struct filters_args *filters)
{
    return image_time_filter(src, filters, "before");
}

static bool image_meet_since_filter(const imagetool_image_summary *src, const struct filters_args *filters)
{
    return image_time_filter(src, filters, "since");
}

static bool image_meet_label_filter(const imagetool_image_summary *src, const struct filters_args *filters)
{
    bool ret = false;
    map_t *field_values_map = NULL;
    const char *field = "label";
    map_itor *itor = NULL;
    size_t i;

    field_values_map = map_search(filters->fields, (void *)field);
    if (field_values_map == NULL) {
        return true;
    }

    if (src->labels == NULL) {
        return false;
    }

    itor = map_itor_new(field_values_map);
    if (itor == NULL) {
        ERROR("Out of memory");
        return false;
    }

    for (; map_itor_valid(itor); map_itor_next(itor)) {
        char *tmp_key = map_itor_key(itor);
        if (tmp_key == NULL) {
            ERROR("Invalid labels");
            ret = false;
            goto out;
        }
        for (i = 0; i < src->labels->len; i++) {
            if (strcmp(tmp_key, src->labels->keys[i]) == 0) {
                ret = true;
                goto out;
            }
        }
    }

out:
    map_itor_free(itor);
    return ret;
}

static bool image_meet_reference_filter(const imagetool_image_summary *src, const struct filters_args *filters)
{
    size_t i;
    size_t len = src->repo_tags_len;

    map_t *field_values_map = map_search(filters->fields, (void *)"reference");
    if (field_values_map == NULL) {
        return true;
    }

    for (i = 0; i < len; i++) {
        if (filters_args_match(filters, "reference", src->repo_tags[i])) {
            return true;
        }
    }

    return false;
}

static bool image_meet_filters(const imagetool_image_summary *src, const struct filters_args *filters)
{
    return image_meet_dangling_filter(src, filters) && image_meet_before_filter(src, filters) &&
           image_meet_since_filter(src, filters) && image_meet_label_filter(src, filters) &&
           image_meet_reference_filter(src, filters);
}

static int dup_oci_image_info_by_filters(const imagetool_image_summary *src, const struct filters_args *filters,
                                         imagetool_images_list *images_list)
{
    int ret = 0;
    char *json = NULL;
    parser_error err = NULL;
    imagetool_image_summary **tmp_images = NULL;
    imagetool_image_summary *tmp_image = NULL;
    size_t new_size, old_size;

    if (src == NULL) {
        goto out;
    }

    if (!image_meet_filters(src, filters)) {
        goto out;
    }

    json = imagetool_image_summary_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        ret = -1;
        goto out;
    }

    tmp_image = imagetool_image_summary_parse_data(json, NULL, &err);
    if (tmp_image == NULL) {
        ERROR("Failed to parse json: %s", err);
        ret = -1;
        goto out;
    }

    if (images_list->images_len > SIZE_MAX / sizeof(imagetool_image_summary *) - 1) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    new_size = (images_list->images_len + 1) * sizeof(imagetool_image_summary *);
    old_size = images_list->images_len * sizeof(imagetool_image_summary *);

    ret = util_mem_realloc((void **)(&tmp_images), new_size, images_list->images, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for append images");
        ret = -1;
        goto out;
    }
    images_list->images = tmp_images;
    images_list->images[images_list->images_len] = tmp_image;
    tmp_image = NULL;
    images_list->images_len++;

    ret = 0;

out:
    free(err);
    free(json);
    free_imagetool_image_summary(tmp_image);
    return ret;
}

static int oci_list_images_by_filters(struct filters_args *filters, imagetool_images_list *images_list)
{
    int ret = 0;
    int nret;
    size_t i = 0;
    imagetool_images_list *all_images = NULL;

    all_images = util_common_calloc_s(sizeof(imagetool_images_list));
    if (all_images == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    if (storage_get_all_images(all_images) != 0) {
        ERROR("Failed to get all images info");
        ret = -1;
        goto out;
    }

    for (i = 0; i < all_images->images_len; i++) {
        nret = dup_oci_image_info_by_filters(all_images->images[i], filters, images_list);
        if (nret != 0) {
            WARN("Failed to dup oci image info");
        }
    }

out:
    free_imagetool_images_list(all_images);
    return ret;
}

int oci_list_images(const im_list_request *request, imagetool_images_list **images)
{
    int ret = 0;
    struct filters_args *image_filters = NULL;

    if (request != NULL && request->image_filters != NULL) {
        image_filters = request->image_filters;
    }

    *images = util_common_calloc_s(sizeof(imagetool_images_list));
    if (*images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (image_filters != NULL) {
        ret = oci_list_images_by_filters(image_filters, *images);
    } else {
        ret = oci_list_all_images(*images);
    }

out:
    if (ret != 0) {
        free_imagetool_images_list(*images);
        *images = NULL;
    }
    return ret;
}

size_t oci_get_images_count(void)
{
    return storage_get_img_count();
}

int oci_summary_image(im_summary_request *request, im_summary_response *response)
{
    int ret = 0;
    imagetool_image_summary *image_summary = NULL;
    char *image_ref = NULL;
    char *resolved_name = NULL;

    if (response == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    image_ref = request->image.image;
    if (image_ref == NULL) {
        ERROR("Inspect image requires image ref");
        isulad_set_error_message("Inspect image requires image ref");
        ret = -1;
        goto pack_response;
    }

    resolved_name = oci_resolve_image_name(image_ref);
    if (resolved_name == NULL) {
        ERROR("Failed to resolve image name %s", image_ref);
        isulad_set_error_message("Failed to resolve image name %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    WARN("Event: {Object: %s, Type: statusing image summary}", resolved_name);

    image_summary = storage_img_get_summary(resolved_name);
    if (image_summary == NULL) {
        ERROR("No such image:%s", resolved_name);
        isulad_set_error_message("No such image:%s", resolved_name);
        ret = -1;
        goto pack_response;
    }

    response->image_summary = image_summary;
    image_summary = NULL;

    WARN("Event: {Object: %s, Type: statused image summary}", resolved_name);

pack_response:
    free(resolved_name);
    return ret;
}

int oci_status_image(im_status_request *request, im_status_response *response)
{
    int ret = 0;
    imagetool_image_status *image_status = NULL;
    imagetool_image *image_info = NULL;
    char *image_ref = NULL;
    char *resolved_name = NULL;

    if (response == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    image_status = util_common_calloc_s(sizeof(imagetool_image_status));
    if (image_status == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto pack_response;
    }
    response->image_info = image_status;

    image_ref = request->image.image;
    if (image_ref == NULL) {
        ERROR("Inspect image requires image ref");
        isulad_set_error_message("Inspect image requires image ref");
        ret = -1;
        goto pack_response;
    }

    resolved_name = oci_resolve_image_name(image_ref);
    if (resolved_name == NULL) {
        ERROR("Failed to resolve image name %s", image_ref);
        isulad_set_error_message("Failed to resolve image name %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    WARN("Event: {Object: %s, Type: statusing image}", resolved_name);

    image_info = storage_img_get(resolved_name);
    if (image_info == NULL) {
        ERROR("No such image:%s", resolved_name);
        isulad_set_error_message("No such image:%s", resolved_name);
        ret = -1;
        goto pack_response;
    }

    response->image_info->image = image_info;
    image_info = NULL;

    WARN("Event: {Object: %s, Type: statused image}", resolved_name);

pack_response:
    free(resolved_name);
    return ret;
}

int oci_inspect_image(const im_inspect_request *im_request, char **inspected_json)
{
    int ret = 0;
    im_status_request request;
    im_status_response *response = NULL;
    struct parser_context ctx = { OPT_GEN_SIMPLIFY, 0 };
    parser_error err = NULL;

    if (im_request == NULL || inspected_json == NULL) {
        ERROR("Invalid input arguments");
        return -1;
    }

    (void)memset(&request, 0, sizeof(im_status_request));

    request.image.image = im_request->image.image;

    response = (im_status_response *)util_common_calloc_s(sizeof(im_status_response));
    if (response == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = oci_status_image(&request, response);
    if (ret != 0) {
        goto out;
    }

    *inspected_json = imagetool_image_status_generate_json(response->image_info, &ctx, &err);
    if (*inspected_json == NULL) {
        ERROR("Failed to generate image status request json:%s", err);
        ret = -1;
        goto out;
    }

out:
    free(err);
    free_im_status_response(response);
    return ret;
}

int oci_image_conf_merge_into_spec(const char *image_name, container_config *container_spec)
{
    int ret = 0;
    char *resolved_name = NULL;
    imagetool_image *image_info = NULL;

    if (container_spec == NULL || image_name == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    resolved_name = oci_resolve_image_name(image_name);
    if (resolved_name == NULL) {
        ERROR("Resolve external config image name failed, image name is %s", image_name);
        ret = -1;
        goto out;
    }

    image_info = storage_img_get(resolved_name);
    if (image_info == NULL) {
        ERROR("Get image from image store failed, image name is %s", resolved_name);
        ret = -1;
        goto out;
    }

    ret = oci_image_merge_config(image_info, container_spec);
    if (ret != 0) {
        ERROR("Failed to merge oci config for image %s", resolved_name);
        ret = -1;
        goto out;
    }

out:
    free(resolved_name);
    free_imagetool_image(image_info);
    return ret;
}
