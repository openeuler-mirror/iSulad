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
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <sys/utsname.h>
#include <ctype.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "oci_images_store.h"
#include "specs_extend.h"
#include "oci_config_merge.h"

#include "isula_image_status.h"
#include "isula_images_list.h"
#include "filters.h"

#define DEFAULT_TAG ":latest"
#define DEFAULT_HOSTNAME "docker.io/"
#define DEFAULT_REPO_PREFIX "library/"

static bool oci_image_exist(const char *image_name)
{
    bool ret = false;
    oci_image_t *image_info = NULL;

    image_info = oci_images_store_get(image_name);
    if (image_info != NULL) {
        ret = true;
        oci_image_unref(image_info);
    }

    return ret;
}

bool oci_detect(const char *image_name)
{
    if (image_name == NULL) {
        return false;
    }

    return oci_image_exist(image_name);
}

char *get_last_part(char **parts)
{
    char *last_part = NULL;
    char **p;

    for (p = parts; p != NULL && *p != NULL; p++) {
        last_part = *p;
    }

    return last_part;
}

// normalize the unqualified image to be domain/repo/image...
char *oci_normalize_image_name(const char *name)
{
    char temp[PATH_MAX] = { 0 };
    char **parts = NULL;
    char *last_part = NULL;
    char *add_dockerio = "";
    char *add_library = "";
    char *add_default_tag = "";

    // Add prefix docker.io if necessary
    parts = util_string_split(name, '/');
    if ((parts != NULL && *parts != NULL && !strings_contains_any(*parts, ".:") &&
         strcmp(*parts, "localhost")) || (strstr(name, "/") == NULL)) {
        add_dockerio = DEFAULT_HOSTNAME;
    }

    // Add library if necessary
    if (strlen(add_dockerio) != 0 && strstr(name, "/") == NULL) {
        add_library = DEFAULT_REPO_PREFIX;
    }

    // Add default tag if necessary
    last_part = get_last_part(parts);
    if (last_part != NULL && strrchr(last_part, ':') == NULL) {
        add_default_tag = DEFAULT_TAG;
    }

    util_free_array(parts);

    // Normalize image name
    int nret = snprintf(temp, sizeof(temp), "%s%s%s%s", add_dockerio, add_library, name, add_default_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
        ERROR("sprint temp image name failed");
        return NULL;
    }

    return util_strdup_s(temp);
}

char *oci_resolve_image_name(const char *name)
{
    if (util_valid_short_sha256_id(name) && oci_image_exist(name)) {
        return util_strdup_s(name);
    }

    return oci_normalize_image_name(name);
}

int oci_split_image_name(const char *image_name, char **host, char **name, char **tag)
{
    char *tag_pos = NULL;
    char *name_pos = NULL;
    char *tmp_image_name = NULL;

    if (!util_valid_image_name(image_name)) {
        ERROR("Invalid full image name %s", image_name);
        return -1;
    }

    tmp_image_name = util_strdup_s(image_name);
    tag_pos = util_tag_pos(tmp_image_name);
    if (tag_pos != NULL) {
        *tag_pos = 0;
        tag_pos++;
        if (tag != NULL) {
            *tag = util_strdup_s(tag_pos);
        }
    }

    name_pos = strchr(tmp_image_name, '/');
    if (name_pos != NULL) {
        *name_pos = 0;
        name_pos++;
        if (name != NULL) {
            *name = util_strdup_s(name_pos);
        }
        if (host != NULL) {
            *host = util_strdup_s(tmp_image_name);
        }
    }

    return 0;
}

char *oci_full_image_name(const char *host, const char *name, const char *tag)
{
    char temp[PATH_MAX] = { 0 };
    const char *tmp_host = "";
    const char *tmp_sep = "";
    const char *tmp_prefix = "";
    const char *tmp_colon = "";
    const char *tmp_tag = DEFAULT_TAG;

    if (name == NULL) {
        ERROR("Invalid NULL name found when getting full image name");
        return NULL;
    }

    if (host != NULL) {
        tmp_host = host;
        tmp_sep = "/";
    }
    if (strchr(name, '/') == NULL) {
        tmp_prefix = DEFAULT_REPO_PREFIX;
    }
    if (tag != NULL) {
        tmp_colon = ":";
        tmp_tag = tag;
    }
    int nret = snprintf(temp, sizeof(temp), "%s%s%s%s%s%s", tmp_host, tmp_sep, tmp_prefix, name, tmp_colon, tmp_tag);
    if (nret < 0 || (size_t)nret >= sizeof(temp)) {
        ERROR("sprint temp image name failed, host %s, name %s, tag %s", host, name, tag);
        return NULL;
    }

    if (!util_valid_image_name(temp)) {
        ERROR("Invalid full image name %s, host %s, name %s, tag %s", temp, host, name, tag);
        return NULL;
    }

    return util_strdup_s(temp);
}

static char *oci_strip_dockerio_prefix(const char *name)
{
    char prefix[PATH_MAX] = { 0 };
    size_t size = 0;

    if (name == NULL) {
        ERROR("NULL image name");
        return NULL;
    }

    int nret = snprintf(prefix, sizeof(prefix), "%s%s", DEFAULT_HOSTNAME, DEFAULT_REPO_PREFIX);
    if (nret < 0 || (size_t)nret >= sizeof(prefix)) {
        ERROR("sprint prefix prefix failed");
        return NULL;
    }

    // Strip docker.io/library
    size = strlen(prefix);
    if (strncmp(name, prefix, size) == 0 && strlen(name) > size) {
        return util_strdup_s(name + size);
    }

    // Strip docker.io
    size = strlen(DEFAULT_HOSTNAME);
    if (strncmp(name, DEFAULT_HOSTNAME, size) == 0 && strlen(name) > size) {
        return util_strdup_s(name + size);
    }

    return util_strdup_s(name);
}

static void oci_strip_dockerio(const imagetool_image *image)
{
    char *repo_tag = NULL;
    char *repo_digest = NULL;
    size_t i = 0;

    if (image == NULL) {
        return;
    }

    for (i = 0; i < image->repo_tags_len; i++) {
        repo_tag = image->repo_tags[i];
        image->repo_tags[i] = oci_strip_dockerio_prefix(repo_tag);
        free(repo_tag);
        repo_tag = NULL;
    }

    for (i = 0; i < image->repo_digests_len; i++) {
        repo_digest = image->repo_digests[i];
        image->repo_digests[i] = oci_strip_dockerio_prefix(repo_digest);
        free(repo_digest);
        repo_digest = NULL;
    }

    return;
}

int oci_get_user_conf(const char *basefs, host_config *hc, const char *userstr, defs_process_user *puser)
{
    if (basefs == NULL || puser == NULL) {
        ERROR("Empty basefs or puser");
        return -1;
    }
    return get_user(basefs, hc, userstr, puser);
}

static int dup_oci_image_info(const imagetool_image *src, imagetool_image **dest)
{
    int ret = -1;
    char *json = NULL;
    parser_error err = NULL;

    if (src == NULL) {
        *dest = NULL;
        return 0;
    }

    json = imagetool_image_generate_json(src, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        goto out;
    }
    *dest = imagetool_image_parse_data(json, NULL, &err);
    if (*dest == NULL) {
        ERROR("Failed to parse json: %s", err);
        goto out;
    }
    ret = 0;

out:
    free(err);
    free(json);
    return ret;
}

static int oci_list_all_images(imagetool_images_list *images_list)
{
    int ret = 0;
    size_t i = 0;
    oci_image_t **images_info = NULL;
    size_t images_num = 0;

    ret = oci_images_store_list(&images_info, &images_num);
    if (ret != 0) {
        ERROR("query all oci images info failed");
        return -1;
    }

    if (images_num == 0) {
        ret = 0;
        goto out;
    }

    images_list->images = util_smart_calloc_s(sizeof(imagetool_image *), images_num);
    if (images_list->images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < images_num; i++) {
        ret = dup_oci_image_info(images_info[i]->info, &images_list->images[i]);
        if (ret != 0) {
            ERROR("Failed to dup oci image %s info", images_info[i]->info->id);
            ret = -1;
            goto out;
        }
        oci_image_unref(images_info[i]);
        images_list->images_len++;
    }
out:
    if (ret != 0) {
        for (; i < images_num; i++) {
            oci_image_unref(images_info[i]);
        }
    }

    free(images_info);
    return ret;
}

static bool image_meet_dangling_filter(const imagetool_image *src, const struct filters_args *filters)
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
    oci_image_t *image_info = NULL;
    int64_t tmp_nanos = 0;
    char *tmp = oci_resolve_image_name(map_itor_key(itor));
    if (tmp == NULL) {
        ERROR("Failed to resolve image name");
        goto out;
    }

    image_info = oci_images_store_get(tmp);
    if (image_info == NULL) {
        ret = -1;
        goto out;
    }
    free(tmp);
    tmp = NULL;

    if (to_unix_nanos_from_str(image_info->info->created, &tmp_nanos) != 0) {
        ERROR("Failed to get unix nano from string");
        ret = -1;
        goto out;
    }
    oci_image_unref(image_info);
    image_info = NULL;

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
    oci_image_unref(image_info);
    free(tmp);
    return ret;
}

static bool image_time_filter(const imagetool_image *src, const struct filters_args *filters,
                              const char *field)
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

    if (to_unix_nanos_from_str(src->created, &tmp_nanos) != 0) {
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

static bool image_meet_before_filter(const imagetool_image *src, const struct filters_args *filters)
{
    return image_time_filter(src, filters, "before");
}

static bool image_meet_since_filter(const imagetool_image *src, const struct filters_args *filters)
{
    return image_time_filter(src, filters, "since");
}

static bool image_meet_label_filter(const imagetool_image *src, const struct filters_args *filters)
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

    if (src->spec->config == NULL || src->spec->config->labels == NULL) {
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
        for (i = 0; i < src->spec->config->labels->len; i++) {
            if (strcmp(tmp_key, src->spec->config->labels->keys[i]) == 0) {
                ret = true;
                goto out;
            }
        }
    }

out:
    map_itor_free(itor);
    return ret;
}

static bool image_meet_reference_filter(const imagetool_image *src, const struct filters_args *filters)
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

static bool image_meet_filters(const imagetool_image *src, const struct filters_args *filters)
{
    return image_meet_dangling_filter(src, filters) &&
           image_meet_before_filter(src, filters) &&
           image_meet_since_filter(src, filters) &&
           image_meet_label_filter(src, filters) &&
           image_meet_reference_filter(src, filters);
}

static int dup_oci_image_info_by_filters(oci_image_t *src, const struct filters_args *filters,
                                         imagetool_images_list *images_list)
{
    int ret = 0;
    char *json = NULL;
    parser_error err = NULL;
    imagetool_image **tmp_images = NULL;
    imagetool_image *tmp_image = NULL;
    size_t new_size, old_size;

    if (src == NULL || src->info == NULL) {
        goto out;
    }

    if (!image_meet_filters(src->info, filters)) {
        goto out;
    }

    json = imagetool_image_generate_json(src->info, NULL, &err);
    if (json == NULL) {
        ERROR("Failed to generate json: %s", err);
        ret = -1;
        goto out;
    }

    tmp_image = imagetool_image_parse_data(json, NULL, &err);
    if (tmp_image == NULL) {
        ERROR("Failed to parse json: %s", err);
        ret = -1;
        goto out;
    }

    if (images_list->images_len > SIZE_MAX / sizeof(imagetool_image *) - 1) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    new_size = (images_list->images_len + 1) * sizeof(imagetool_image *);
    old_size = images_list->images_len * sizeof(imagetool_image *);

    ret = mem_realloc((void **)(&tmp_images), new_size, images_list->images, old_size);
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
    free_imagetool_image(tmp_image);
    return ret;
}

static int oci_list_images_by_filters(struct filters_args *filters, imagetool_images_list *images_list)
{
    int ret = 0;
    int nret;
    size_t i = 0;
    oci_image_t **images_info = NULL;
    size_t images_num = 0;

    ret = oci_images_store_list(&images_info, &images_num);
    if (ret != 0) {
        ERROR("query all oci images info failed");
        return -1;
    }

    if (images_num == 0) {
        ret = 0;
        goto out;
    }

    for (i = 0; i < images_num; i++) {
        nret = dup_oci_image_info_by_filters(images_info[i], filters, images_list);
        if (nret != 0) {
            WARN("Failed to dup oci image info");
        }
        oci_image_unref(images_info[i]);
    }

out:
    free(images_info);
    return ret;
}

static void oci_strip_all_dockerios(const imagetool_images_list *images)
{
    size_t i = 0;

    if (images == NULL) {
        return;
    }

    for (i = 0; i < images->images_len; i++) {
        oci_strip_dockerio(images->images[i]);
    }

    return;
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

    oci_strip_all_dockerios(*images);

out:
    if (ret != 0) {
        free_imagetool_images_list(*images);
        *images = NULL;
    }
    return ret;
}

int oci_status_image(im_status_request *request, im_status_response **response)
{
    int ret = 0;
    imagetool_image_status *image = NULL;
    char *image_ref = NULL;
    oci_image_t *image_info = NULL;
    char *resolved_name = NULL;

    if (*response == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }

    image = util_common_calloc_s(sizeof(imagetool_image_status));
    if (image == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto pack_response;
    }
    (*response)->image_info = image;

    image_ref = request->image.image;
    if (image_ref == NULL) {
        ERROR("Inspect image requires image ref");
        isulad_set_error_message("Inspect image requires image ref");
        ret = -1;
        goto pack_response;
    }

    resolved_name = oci_resolve_image_name(image_ref);
    if (resolved_name == NULL) {
        ERROR("Failed to reslove image name %s", image_ref);
        isulad_set_error_message("Failed to reslove image name %s", image_ref);
        ret = -1;
        goto pack_response;
    }

    EVENT("Event: {Object: %s, Type: statusing image}", resolved_name);

    image_info = oci_images_store_get(resolved_name);
    if (image_info == NULL) {
        ERROR("No such image:%s", resolved_name);
        isulad_set_error_message("No such image:%s", resolved_name);
        ret = -1;
        goto pack_response;
    }

    ret = dup_oci_image_info(image_info->info, &((*response)->image_info->image));
    oci_image_unref(image_info);
    if (ret != 0) {
        ERROR("Failed to dup image info:%s", resolved_name);
        isulad_set_error_message("Failed to dup image info:%s", resolved_name);
        ret = -1;
        goto pack_response;
    }

    oci_strip_dockerio((*response)->image_info->image);

    EVENT("Event: {Object: %s, Type: statused image}", resolved_name);

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

    ret = oci_status_image(&request, &response);
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

imagetool_image *oci_get_image_info_by_name(const char *id)
{
    return isula_image_get_image_info_by_name(id);
}

/* call low driver to get images list */
int oci_get_all_images(const im_list_request *request, imagetool_images_list **images)
{
    return isula_list_images(request, images);
}

int oci_image_conf_merge_into_spec(const char *image_name, container_config *container_spec)
{
    int ret = 0;
    oci_image_t *image_info = NULL;
    char *resolved_name = NULL;

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

    image_info = oci_images_store_get(resolved_name);
    if (image_info == NULL) {
        ERROR("Get image from image store failed, image name is %s", resolved_name);
        ret = -1;
        goto out;
    }

    ret = oci_image_merge_config(image_info->info, container_spec);
    if (ret != 0) {
        ERROR("Failed to merge oci config for image %s", resolved_name);
        ret = -1;
        goto out;
    }

out:
    oci_image_unref(image_info);
    free(resolved_name);
    return ret;
}

