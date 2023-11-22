/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide image functions
 *********************************************************************************/
#include "image_cb.h"
#include <stdio.h>
#include <malloc.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/image_delete_image_request.h>
#include <isula_libutils/image_delete_image_response.h>
#include <isula_libutils/image_descriptor.h>
#include <isula_libutils/image_image.h>
#include <isula_libutils/image_import_request.h>
#include <isula_libutils/image_import_response.h>
#include <isula_libutils/image_inspect_request.h>
#include <isula_libutils/image_inspect_response.h>
#include <isula_libutils/image_load_image_request.h>
#include <isula_libutils/image_load_image_response.h>
#include <isula_libutils/image_login_request.h>
#include <isula_libutils/image_login_response.h>
#include <isula_libutils/image_logout_request.h>
#include <isula_libutils/image_logout_response.h>
#include <isula_libutils/image_tag_image_request.h>
#include <isula_libutils/image_tag_image_response.h>
#include <isula_libutils/image_pull_image_request.h>
#include <isula_libutils/image_pull_image_response.h>
#ifdef ENABLE_IMAGE_SEARCH
#include <isula_libutils/image_search_image.h>
#include <isula_libutils/image_search_images_request.h>
#include <isula_libutils/image_search_images_response.h>
#endif
#include <isula_libutils/imagetool_image.h>
#include <isula_libutils/imagetool_images_list.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/timestamp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "error.h"
#include "err_msg.h"
#include "isula_libutils/log.h"
#include "image_api.h"
#include "filters.h"
#include "events_sender_api.h"
#include "service_image_api.h"
#include "event_type.h"
#include "utils_regex.h"
#include "utils_timestamp.h"
#include "utils_verify.h"
#include "path.h"

static int do_import_image(const char *file, const char *tag, char **id)
{
    int ret = 0;
    im_import_request *request = NULL;
    char cleanpath[PATH_MAX] = { 0 };

    if (file == NULL || tag == NULL || id == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    if (util_clean_path(file, cleanpath, sizeof(cleanpath)) == NULL) {
        ERROR("clean path for %s failed", file);
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(im_import_request));
    if (request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    request->tag = util_strdup_s(tag);
    request->file = util_strdup_s(cleanpath);

    ret = im_import_image(request, id);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    free_im_import_request(request);
    return ret;
}

/* import cb */
static int import_cb(const image_import_request *request, image_import_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;
    char *id = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(image_import_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    if (request->file == NULL || request->tag == NULL) {
        ERROR("input arguments error");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Importing}", request->file);

    ret = do_import_image(request->file, request->tag, &id);
    if (ret != 0) {
        ERROR("Failed to import docker image %s with tag %s", request->file, request->tag);
        cc = EINVALIDARGS;
        goto out;
    }

    (*response)->id = id;
    id = NULL;

    EVENT("Image Event: {Object: %s, Type: Imported}", request->file);

    (void)isulad_monitor_send_image_event(request->file, IM_IMPORT);
out:

    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}

static int do_load_image(const char *file, const char *tag, const char *type)
{
    int ret = 0;
    im_load_request *request = NULL;
    im_load_response *response = NULL;
    char cleanpath[PATH_MAX] = { 0 };

    if (file == NULL || type == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    if (util_clean_path(file, cleanpath, sizeof(cleanpath)) == NULL) {
        ERROR("clean path for %s failed", file);
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(im_load_request));
    if (request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (tag != NULL) {
        request->tag = util_strdup_s(tag);
    }
    request->file = util_strdup_s(cleanpath);
    request->type = util_strdup_s(type);

    ret = im_load_image(request, &response);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    free_im_load_request(request);
    free_im_load_response(response);
    return ret;
}

/* image load cb */
static int image_load_cb(const image_load_image_request *request, image_load_image_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(image_load_image_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    if (request->file == NULL || request->type == NULL) {
        ERROR("input arguments error");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Loading}", request->file);

    ret = do_load_image(request->file, request->tag, request->type);
    if (ret != 0) {
        ERROR("Failed to load docker image %s with tag %s and type %s", request->file, request->tag, request->type);
        cc = EINVALIDARGS;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Loaded}", request->file);

    (void)isulad_monitor_send_image_event(request->file, IM_LOAD);
out:

    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}

static int do_login(const char *username, const char *password, const char *server, const char *type)
{
    int ret = 0;
    im_login_request *request = NULL;
    im_login_response *response = NULL;

    request = util_common_calloc_s(sizeof(im_login_request));
    if (request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    request->username = util_strdup_s(username);
    request->password = util_strdup_s(password);
    request->server = util_strdup_s(server);
    request->type = util_strdup_s(type);

    ret = im_login(request, &response);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    free_im_login_request(request);
    free_im_login_response(response);
    return ret;
}

/* login cb */
static int login_cb(const image_login_request *request, image_login_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(image_login_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    if (request->username == NULL || request->password == NULL || request->type == NULL || request->server == NULL) {
        ERROR("input arguments error");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Logining}", request->server);

    ret = do_login(request->username, request->password, request->server, request->type);
    if (ret != 0) {
        ERROR("Failed to login %s", request->server);
        cc = EINVALIDARGS;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Logined}", request->server);
    (void)isulad_monitor_send_image_event(request->server, IM_LOGIN);

out:

    if (response != NULL && *response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}

static int do_logout(const char *server, const char *type)
{
    int ret = 0;
    im_logout_request *request = NULL;
    im_logout_response *response = NULL;

    request = util_common_calloc_s(sizeof(im_logout_request));
    if (request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    request->server = util_strdup_s(server);
    request->type = util_strdup_s(type);

    ret = im_logout(request, &response);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

out:
    free_im_logout_request(request);
    free_im_logout_response(response);
    return ret;
}

/* logout cb */
static int logout_cb(const image_logout_request *request, image_logout_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    DAEMON_CLEAR_ERRMSG();
    *response = util_common_calloc_s(sizeof(image_logout_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    if (request->type == NULL || request->server == NULL) {
        ERROR("input arguments error");
        cc = ISULAD_ERR_INPUT;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Logouting}", request->server);

    ret = do_logout(request->server, request->type);
    if (ret != 0) {
        ERROR("Failed to logout %s", request->server);
        cc = EINVALIDARGS;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Logouted}", request->server);
    (void)isulad_monitor_send_image_event(request->server, IM_LOGOUT);

out:

    if (response != NULL && *response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}

/* image remove cb */
static int image_remove_cb(const image_delete_image_request *request, image_delete_image_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || request->image_name == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    *response = util_common_calloc_s(sizeof(image_delete_image_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Deleting}", request->image_name);

    ret = delete_image(request->image_name, request->force);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Deleted}", request->image_name);

out:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}

/* tag image */
static int do_tag_image(const char *src_name, const char *dest_name)
{
    int ret = 0;
    im_tag_request *im_request = NULL;
    im_tag_response *im_response = NULL;

    if (src_name == NULL || dest_name == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }

    im_request = util_common_calloc_s(sizeof(im_tag_request));
    if (im_request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    im_request->src_name.image = util_strdup_s(src_name);
    im_request->dest_name.image = util_strdup_s(dest_name);

    ret = im_tag_image(im_request, &im_response);
    if (ret != 0) {
        if (im_response != NULL && im_response->errmsg != NULL) {
            ERROR("Tag image %s to %s failed:%s", src_name, dest_name, im_response->errmsg);
            isulad_try_set_error_message("Tag image %s to %s failed:%s", src_name, dest_name, im_response->errmsg);
        } else {
            ERROR("Tag image %s to %s failed", src_name, dest_name);
            isulad_try_set_error_message("Tag image %s to %s failed", src_name, dest_name);
        }
        ret = -1;
        goto out;
    }

out:
    free_im_tag_request(im_request);
    free_im_tag_response(im_response);

    return ret;
}

/* image tag cb */
static int image_tag_cb(const image_tag_image_request *request, image_tag_image_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || request->src_name == NULL || response == NULL || request->dest_name == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    *response = util_common_calloc_s(sizeof(image_delete_image_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Tagging}", request->src_name);

    ret = do_tag_image(request->src_name, request->dest_name);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Tagged}", request->src_name);

out:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}

static bool valid_repo_tags(char * const * const repo_tags, size_t repo_index)
{
    if (repo_tags != NULL && repo_tags[repo_index] != NULL) {
        return true;
    }

    return false;
}

static int trans_one_image(image_list_images_response *response, size_t image_index,
                           const imagetool_image_summary *im_image, size_t repo_index)
{
    int ret = 0;
    image_image *out_image = NULL;

    out_image = util_common_calloc_s(sizeof(image_image));
    if (out_image == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    response->images[image_index] = out_image;
    response->images_len++;

    if (valid_repo_tags(im_image->repo_tags, repo_index)) {
        out_image->name = util_strdup_s(im_image->repo_tags[repo_index]);
    }

    if (out_image->name == NULL && im_image->repo_digests != NULL && im_image->repo_digests_len > 0) {
        // repo digest must valid, so just get lastest @
        char *pod = strrchr(im_image->repo_digests[0], '@');
        if (pod != NULL) {
            out_image->name = util_sub_string(im_image->repo_digests[0], 0, (size_t)(pod - im_image->repo_digests[0]));
        }
    }

    out_image->target = util_common_calloc_s(sizeof(image_descriptor));
    if (out_image->target == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    /* This digest is image id. */
    out_image->target->digest = util_full_digest(im_image->id);
    out_image->target->size = (int64_t)im_image->size;

    out_image->created_at = util_common_calloc_s(sizeof(timestamp));
    if (out_image->created_at == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    if (im_image->created != NULL) {
        int64_t created_nanos = 0;
        types_timestamp_t timestamp;

        if (util_to_unix_nanos_from_str(im_image->created, &created_nanos) != 0) {
            ERROR("Failed to translate created time to nanos");
            ret = -1;
            goto out;
        }

        if (!unix_nanos_to_timestamp(created_nanos, &timestamp)) {
            ERROR("Failed to translate nanos to timestamp");
            ret = -1;
            goto out;
        }

        out_image->created_at->seconds = timestamp.seconds;
        out_image->created_at->nanos = timestamp.nanos;
    }

out:

    return ret;
}

static size_t calc_images_display_num(const imagetool_images_list *images)
{
    size_t images_num = 0;
    size_t i = 0;
    const imagetool_image_summary *im_image = NULL;

    for (i = 0; i < images->images_len; i++) {
        size_t j = 0;
        im_image = images->images[i];
        for (j = 0; j < im_image->repo_tags_len || (j == 0 && im_image->repo_tags_len == 0); j++) {
            images_num++;
        }
    }

    return images_num;
}

static int trans_im_list_images(const im_list_response *im_list, image_list_images_response *response)
{
    int ret = 0;
    size_t i = 0;
    size_t j = 0;
    size_t images_num = 0;
    size_t images_display_num = 0;
    size_t image_index = 0;
    imagetool_image_summary *im_image = NULL;

    if (im_list == NULL || im_list->images == NULL) {
        return -1;
    }

    images_num = im_list->images->images_len;
    if (images_num == 0) {
        return 0;
    }

    // If one image have several repo tags, display them all. Image with no
    // repo will also be displayed
    images_display_num = calc_images_display_num(im_list->images);
    response->images = util_smart_calloc_s(sizeof(image_image *), images_display_num);
    if (response->images == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    for (i = 0; i < images_num; i++) {
        im_image = im_list->images->images[i];
        for (j = 0; j < im_image->repo_tags_len || (j == 0 && im_image->repo_tags_len == 0); j++) {
            ret = trans_one_image(response, image_index, im_image, j);
            if (ret < 0) {
                goto out;
            }
            image_index++;
        }
    }

out:
    return ret;
}

#ifdef ENABLE_OCI_IMAGE
struct image_list_context {
    struct filters_args *image_filters;
};

static char *pre_processe_wildcard(const char *wildcard)
{
    char *ret = NULL;
    if (util_wildcard_to_regex(wildcard, &ret) != 0) {
        ERROR("Failed to convert wildcard to regex: %s", wildcard);
        isulad_set_error_message("Failed to convert wildcard to regex: %s", wildcard);
        return NULL;
    }
    return ret;
}

static const struct filter_opt g_image_list_filter[] = {
    {.name = "dangling", .valid = util_valid_bool_string, .pre = NULL},
    {.name = "label", .valid = NULL, .pre = NULL},
    {.name = "before", .valid = im_oci_image_exist, .pre = NULL},
    {.name = "since", .valid = im_oci_image_exist, .pre = NULL},
    {.name = "reference", .valid = NULL, .pre = pre_processe_wildcard},
};

static int do_add_image_list_filters(const char *filter_key, const json_map_string_bool *filter_value,
                                     im_list_request *ctx)
{
    size_t i, len;

    len = sizeof(g_image_list_filter) / sizeof(struct filter_opt);
    for (i = 0; i < len; i++) {
        if (strcmp(filter_key,  g_image_list_filter[i].name) != 0) {
            continue;
        }
        return do_add_filters(filter_key, filter_value, ctx->image_filters,  g_image_list_filter[i].valid,
                              g_image_list_filter[i].pre);
    }
    return -1;
}
#endif

static im_list_request *fold_filter(const image_list_images_request *request)
{
    im_list_request *ctx = NULL;

    ctx = (im_list_request *)util_common_calloc_s(sizeof(im_list_request));
    if (ctx == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

#ifdef ENABLE_OCI_IMAGE
    size_t i;
    if (request->filters == NULL) {
        return ctx;
    }

    ctx->image_filters = filters_args_new();
    if (ctx->image_filters == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    for (i = 0; i < request->filters->len; i++) {
        if (do_add_image_list_filters(request->filters->keys[i], request->filters->values[i], ctx) != 0) {
            ERROR("Invalid filter '%s'", request->filters->keys[i]);
            isulad_set_error_message("Invalid filter '%s'", request->filters->keys[i]);
            goto error_out;
        }
    }
#endif
    return ctx;

error_out:
    free_im_list_request(ctx);
    return NULL;
}

/* image list cb */
int image_list_cb(const image_list_images_request *request, image_list_images_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;
    im_list_request *im_request = NULL;
    im_list_response *im_response = NULL;

    if (request == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();

    *response = util_common_calloc_s(sizeof(image_list_images_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    im_request = fold_filter(request);
    if (im_request == NULL) {
        ERROR("Failed to fold filters");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    ret = im_list_images(im_request, &im_response);
    if (ret) {
        if (im_response != NULL && im_response->errmsg != NULL) {
            ERROR("List images failed:%s", im_response->errmsg);
            isulad_try_set_error_message("List images failed:%s", im_response->errmsg);
        } else {
            ERROR("List images failed");
            isulad_try_set_error_message("List images failed");
        }
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    ret = trans_im_list_images(im_response, *response);
    if (ret) {
        ERROR("Failed to translate list images info");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

out:

    free_im_list_request(im_request);
    free_im_list_response(im_response);

    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}

static int inspect_image_with_valid_name(const char *image_ref, char **inspected_json)
{
    int ret = 0;
    im_inspect_request *im_request = NULL;
    im_inspect_response *im_response = NULL;

    if (image_ref == NULL) {
        ERROR("invalid NULL param");
        return EINVALIDARGS;
    }

    im_request = util_common_calloc_s(sizeof(im_inspect_request));
    if (im_request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    im_request->image.image = util_strdup_s(image_ref);

    ret = im_inspect_image(im_request, &im_response);
    if (ret != 0) {
        if (im_response != NULL && im_response->errmsg != NULL) {
            ERROR("Inspect image %s failed:%s", image_ref, im_response->errmsg);
            isulad_try_set_error_message("Inspect image %s failed:%s", image_ref, im_response->errmsg);
        } else {
            ERROR("Inspect image %s failed", image_ref);
            isulad_try_set_error_message("Inspect image %s failed", image_ref);
        }
        ret = -1;
        goto out;
    }

    *inspected_json = im_response->im_inspect_json ? util_strdup_s(im_response->im_inspect_json) : NULL;

out:
    free_im_inspect_request(im_request);
    free_im_inspect_response(im_response);

    return ret;
}

/* When inspect none image, we respond following string according hasen's request. */
#define INSPECT_NONE_IMAGE_RESP \
    "{                                                                            \
    \"ContainerConfig\": {                                                        \
        \"Env\": [                                                                \
            \"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\" \
        ],                                                                        \
        \"Entrypoint\": null                                                      \
    }                                                                             \
}"

/*
 * RETURN VALUE:
 * 0: inspect success
 * -1: no such image with "id"
*/
static int inspect_image_helper(const char *image_ref, char **inspected_json)
{
    int ret = 0;

    if (strcmp(image_ref, "none") == 0 || strcmp(image_ref, "none:latest") == 0) {
        *inspected_json = util_strdup_s(INSPECT_NONE_IMAGE_RESP);
        INFO("Inspect image %s success", image_ref);
        goto out;
    }

    if (inspect_image_with_valid_name(image_ref, inspected_json) != 0) {
        ERROR("No such image or container or accelerator:%s", image_ref);
        isulad_set_error_message("No such image or container or accelerator:%s", image_ref);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int image_inspect_cb(const image_inspect_request *request, image_inspect_response **response)
{
    char *name = NULL;
    char *image_json = NULL;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || response == NULL) {
        ERROR("Invalid NULL input");
        return -1;
    }

    *response = util_common_calloc_s(sizeof(image_inspect_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto pack_response;
    }

    name = request->id;

    if (name == NULL) {
        ERROR("receive NULL Request id");
        cc = ISULAD_ERR_INPUT;
        goto pack_response;
    }

    isula_libutils_set_log_prefix(name);

    INFO("Inspect :%s", name);

    if (inspect_image_helper(name, &image_json) != 0) {
        cc = ISULAD_ERR_EXEC;
    }

pack_response:
    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
        (*response)->image_json = image_json;
    }

    isula_libutils_free_log_prefix();
    malloc_trim(0);
    return (cc == ISULAD_SUCCESS) ? 0 : -1;
}

int pull_request_from_rest(const image_pull_image_request *request, im_pull_request **im_req)
{
    *im_req = util_common_calloc_s(sizeof(im_pull_request));
    if (*im_req == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    (*im_req)->image = util_strdup_s(request->image_name);
    (*im_req)->is_progress_visible = request->is_progress_visible;

    return 0;
}

/* image pull cb */
static int image_pull_cb(const image_pull_image_request *request, stream_func_wrapper *stream,
                         image_pull_image_response **response)
{
    int ret = -1;
    im_pull_request *im_req = NULL;
    im_pull_response *im_rsp = NULL;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || request->image_name == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    *response = util_common_calloc_s(sizeof(image_pull_image_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        return ISULAD_ERR_MEMOUT;
    }

    EVENT("Image Event: {Object: %s, Type: Pulling}", request->image_name);
    ret = pull_request_from_rest(request, &im_req);
    if (ret != 0) {
        goto out;
    }

    // current only oci image support pull
    im_req->type = util_strdup_s(IMAGE_TYPE_OCI);
    ret = im_pull_image(im_req, stream, &im_rsp);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Pulled}", request->image_name);

out:
    (*response)->cc = cc;
    if (im_rsp != NULL) {
        (*response)->errmsg = util_strdup_s(im_rsp->errmsg);
        (*response)->image_ref = util_strdup_s(im_rsp->image_ref);
    }
    free_im_pull_request(im_req);
    free_im_pull_response(im_rsp);

    return (ret < 0) ? ECOMMON : ret;
}

#ifdef ENABLE_IMAGE_SEARCH
bool valid_uint_filter_value(const char *value)
{
    int num = 0;

    if (util_safe_int(value, &num) != 0 || num < 0) {
        return false;
    }

    return true;
}

static const struct filter_opt g_search_filter[] = {
    {.name = "stars", .valid = valid_uint_filter_value, .pre = NULL},
    {.name = "is-automated", .valid = util_valid_bool_string, .pre = NULL},
    {.name = "is-official", .valid = util_valid_bool_string, .pre = NULL},
};

static int do_add_search_filters(const char *filter_key, const json_map_string_bool *filter_value,
                                 im_search_request *ctx)
{
    size_t i, len;

    len = sizeof(g_search_filter) / sizeof(struct filter_opt);
    for (i = 0; i < len; i++) {
        if (strcmp(filter_key,  g_search_filter[i].name) != 0) {
            continue;
        }
        return do_add_filters(filter_key, filter_value, ctx->filter,  g_search_filter[i].valid,  g_search_filter[i].pre);
    }
    return -1;
}

static im_search_request *trans_im_search_request(const image_search_images_request *request)
{
    im_search_request *req = NULL;

    req = util_common_calloc_s(sizeof(im_search_request));
    if (req == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    req->search_name = util_strdup_s(request->search_name);
    req->limit = request->limit;

    size_t i;
    if (request->filters == NULL) {
        return req;
    }

    req->filter = filters_args_new();
    if (req->filter == NULL) {
        ERROR("Out of memory");
        goto error_out;
    }

    for (i = 0; i < request->filters->len; i++) {
        if (do_add_search_filters(request->filters->keys[i], request->filters->values[i], req) != 0) {
            ERROR("Invalid filter '%s'", request->filters->keys[i]);
            isulad_set_error_message("Invalid filter '%s'", request->filters->keys[i]);
            goto error_out;
        }
    }
    return req;

error_out:
    free_im_search_request(req);
    return NULL;
}

static int trans_im_search_images(const im_search_response *im_search, image_search_images_response *response)
{
    size_t i = 0;

    if (im_search == NULL || im_search->result == NULL) {
        return -1;
    }

    response->search_result =
        (image_search_image **)util_smart_calloc_s(sizeof(image_search_image *), im_search->result->results_len);
    if (response->search_result == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (im_search->result->results_len == 0) {
        return 0;
    }

    for (i = 0; i < im_search->result->results_len; i++) {
        response->search_result[i] = (image_search_image *)util_common_calloc_s(sizeof(image_search_image));
        if (response->search_result[i] == NULL) {
            ERROR("Out of memory");
            return -1;
        }
        response->search_result[i]->name = util_strdup_s(im_search->result->results[i]->name);
        response->search_result[i]->description = util_strdup_s(im_search->result->results[i]->description);
        response->search_result[i]->is_automated = im_search->result->results[i]->is_automated;
        response->search_result[i]->is_official = im_search->result->results[i]->is_official;
        response->search_result[i]->star_count = im_search->result->results[i]->star_count;
        response->search_result_len++;
    }

    return 0;
}

static int image_search_cb(const image_search_images_request *request, image_search_images_response **response)
{
    int ret = -1;
    uint32_t cc = ISULAD_SUCCESS;
    im_search_request *im_request = NULL;
    im_search_response *im_response = NULL;

    if (request == NULL || request->search_name == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    DAEMON_CLEAR_ERRMSG();

    *response = util_common_calloc_s(sizeof(image_search_images_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    im_request = trans_im_search_request(request);
    if (im_request == NULL) {
        ERROR("Failed to trans im_search_request");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    // current only oci image support search
    im_request->type = util_strdup_s(IMAGE_TYPE_OCI);

    ret = im_search_images(im_request, &im_response);
    if (ret != 0) {
        if (im_response != NULL && im_response->errmsg != NULL) {
            ERROR("Search images failed:%s", im_response->errmsg);
            isulad_try_set_error_message("Search images failed:%s", im_response->errmsg);
        } else {
            ERROR("Search images failed");
            isulad_try_set_error_message("Search images failed");
        }
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    ret = trans_im_search_images(im_response, *response);
    if (ret) {
        ERROR("Failed to translate search result");
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

out:

    free_im_search_request(im_request);
    free_im_search_response(im_response);

    if (*response != NULL) {
        (*response)->cc = cc;
        if (g_isulad_errmsg != NULL) {
            (*response)->errmsg = util_strdup_s(g_isulad_errmsg);
            DAEMON_CLEAR_ERRMSG();
        }
    }

    return (ret < 0) ? ECOMMON : ret;
}
#endif

/* image callback init */
void image_callback_init(service_image_callback_t *cb)
{
    if (cb == NULL) {
        ERROR("Invalid input arguments");
        return;
    }

    cb->load = image_load_cb;
    cb->remove = image_remove_cb;
    cb->list = image_list_cb;
    cb->inspect = image_inspect_cb;
    cb->import = import_cb;
    cb->login = login_cb;
    cb->logout = logout_cb;
    cb->tag = image_tag_cb;
    cb->pull = image_pull_cb;
#ifdef ENABLE_IMAGE_SEARCH
    cb->search = image_search_cb;
#endif
}
