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
 * Create: 2018-11-1
 * Description: provide image functions
 *********************************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include <malloc.h>

#include "image_cb.h"
#include "utils.h"
#include "error.h"
#include "libisulad.h"
#include "isula_libutils/log.h"
#include "image_api.h"
#include "isulad_config.h"
#include "mediatype.h"
#include "filters.h"
#include "events_sender_api.h"
#include "service_image_api.h"
#ifdef ENABLE_OCI_IMAGE
#include "oci_common_operators.h"
#endif

static int isula_import_image(const char *file, const char *tag, char **id)
{
    int ret = 0;
    im_import_request *request = NULL;

    if (file == NULL || tag == NULL || id == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(im_import_request));
    if (request == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }

    request->tag = util_strdup_s(tag);
    request->file = util_strdup_s(file);

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

    ret = isula_import_image(request->file, request->tag, &id);
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

static int docker_load_image(const char *file, const char *tag, const char *type)
{
    int ret = 0;
    im_load_request *request = NULL;
    im_load_response *response = NULL;

    if (file == NULL || type == NULL) {
        ERROR("Invalid input arguments");
        ret = -1;
        goto out;
    }

    request = util_common_calloc_s(sizeof(im_load_request));
    if (request == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
    if (tag != NULL) {
        request->tag = util_strdup_s(tag);
    }
    request->file = util_strdup_s(file);
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

    if (request->tag != NULL && !util_valid_image_name(request->tag)) {
        ERROR("Invalid image name %s", request->tag);
        cc = ISULAD_ERR_INPUT;
        isulad_try_set_error_message("Invalid image name:%s", request->tag);
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Loading}", request->file);

    ret = docker_load_image(request->file, request->tag, request->type);
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

static int docker_login(const char *username, const char *password, const char *server, const char *type)
{
    int ret = 0;
    im_login_request *request = NULL;
    im_login_response *response = NULL;

    request = util_common_calloc_s(sizeof(im_login_request));
    if (request == NULL) {
        ERROR("Memory out");
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

    ret = docker_login(request->username, request->password, request->server, request->type);
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

static int docker_logout(const char *server, const char *type)
{
    int ret = 0;
    im_logout_request *request = NULL;
    im_logout_response *response = NULL;

    request = util_common_calloc_s(sizeof(im_logout_request));
    if (request == NULL) {
        ERROR("Memory out");
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

    ret = docker_logout(request->server, request->type);
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
    char *image_ref = NULL;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || request->image_name == NULL || response == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    image_ref = request->image_name;

    *response = util_common_calloc_s(sizeof(image_delete_image_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    if (!util_valid_image_name(image_ref)) {
        ERROR("Invalid image name %s", image_ref);
        cc = ISULAD_ERR_INPUT;
        isulad_try_set_error_message("Invalid image name:%s", image_ref);
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Deleting}", image_ref);

    ret = delete_image(image_ref, request->force);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Deleted}", image_ref);

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
static int tag_image(const char *src_name, const char *dest_name)
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
            isulad_try_set_error_message("Tag image %s to %s failed");
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
    char *src_name = NULL;
    char *dest_name = NULL;
    uint32_t cc = ISULAD_SUCCESS;

    DAEMON_CLEAR_ERRMSG();

    if (request == NULL || request->src_name == NULL || response == NULL || request->dest_name == NULL) {
        ERROR("Invalid input arguments");
        return EINVALIDARGS;
    }

    src_name = request->src_name;
    dest_name = request->dest_name;

    *response = util_common_calloc_s(sizeof(image_delete_image_response));
    if (*response == NULL) {
        ERROR("Out of memory");
        cc = ISULAD_ERR_MEMOUT;
        goto out;
    }

    if (!util_valid_image_name(src_name)) {
        ERROR("Invalid image name %s", src_name);
        cc = ISULAD_ERR_INPUT;
        isulad_try_set_error_message("Invalid image name:%s", src_name);
        goto out;
    }

    if (!util_valid_image_name(dest_name)) {
        ERROR("Invalid image name %s", dest_name);
        cc = ISULAD_ERR_INPUT;
        isulad_try_set_error_message("Invalid image name:%s", dest_name);
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Tagging}", src_name);

    ret = tag_image(src_name, dest_name);
    if (ret != 0) {
        cc = ISULAD_ERR_EXEC;
        goto out;
    }

    EVENT("Image Event: {Object: %s, Type: Tagged}", src_name);

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

static bool valid_repo_tags(char *const *const repo_tags, size_t repo_index)
{
    if (repo_tags != NULL && repo_tags[repo_index] != NULL) {
        return true;
    }

    return false;
}

static int trans_one_image(image_list_images_response *response, size_t image_index, const imagetool_image *im_image,
                           size_t repo_index)
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

        if (to_unix_nanos_from_str(im_image->created, &created_nanos) != 0) {
            ERROR("Failed to translate created time to nanos");
            ret = -1;
            goto out;
        }

        if (!unix_nanos_to_timestamp(created_nanos, &timestamp) != 0) {
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
    const imagetool_image *im_image = NULL;

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
    imagetool_image *im_image = NULL;

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
    if (images_display_num >= (SIZE_MAX / sizeof(image_image *))) {
        INFO("Too many images, out of memory");
        ret = -1;
        isulad_try_set_error_message("Get too many images info, out of memory");
        goto out;
    }

    response->images = util_common_calloc_s(sizeof(image_image *) * images_display_num);
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

static im_list_request *image_list_context_new(const image_list_images_request *request)
{
    im_list_request *ctx = NULL;

    ctx = util_common_calloc_s(sizeof(im_list_request));
    if (ctx == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    return ctx;
}

#ifdef ENABLE_OCI_IMAGE
struct image_list_context {
    struct filters_args *image_filters;
};

static const char *g_accepted_image_filter_tags[] = { "dangling", "label", "before", "since", "reference", NULL };

static bool is_valid_dangling_string(const char *val)
{
    return strcmp(val, "true") == 0 || strcmp(val, "false") == 0;
}

static bool is_valid_image(const char *val)
{
    bool ret = true;
    char *resolved_name = NULL;
    int nret = im_resolv_image_name(IMAGE_TYPE_OCI, val, &resolved_name);
    if (nret != 0) {
        ERROR("Failed to resolve image name");
        ret = false;
        goto out;
    }
    if (!im_oci_image_exist(resolved_name)) {
        ERROR("No such image: %s", val);
        ret = false;
        goto out;
    }

out:
    free(resolved_name);
    return ret;
}

static int do_add_filters(const char *filter_key, const json_map_string_bool *filter_value, im_list_request *ctx)
{
    int ret = 0;
    size_t j;
    bool bret = false;
    char *value = NULL;

    for (j = 0; j < filter_value->len; j++) {
        if (strcmp(filter_key, "reference") == 0) {
            if (util_wildcard_to_regex(filter_value->keys[j], &value) != 0) {
                ERROR("Failed to convert wildcard to regex: %s", filter_value->keys[j]);
                isulad_set_error_message("Failed to convert wildcard to regex: %s", filter_value->keys[j]);
                ret = -1;
                goto out;
            }
        } else if (strcmp(filter_key, "dangling") == 0) {
            if (!is_valid_dangling_string(filter_value->keys[j])) {
                ERROR("Unrecognised filter value for status: %s", filter_value->keys[j]);
                isulad_set_error_message("Unrecognised filter value for status: %s", filter_value->keys[j]);
                ret = -1;
                goto out;
            }
            value = util_strdup_s(filter_value->keys[j]);
        } else if (strcmp(filter_key, "before") == 0 || strcmp(filter_key, "since") == 0) {
            if (!is_valid_image(filter_value->keys[j])) {
                ERROR("No such image: %s", filter_value->keys[j]);
                isulad_set_error_message("No such image: %s", filter_value->keys[j]);
                ret = -1;
                goto out;
            }
            value = util_strdup_s(filter_value->keys[j]);
        } else {
            value = util_strdup_s(filter_value->keys[j]);
        }

        bret = filters_args_add(ctx->image_filters, filter_key, value);
        if (!bret) {
            ERROR("Add filter args failed");
            ret = -1;
            goto out;
        }
        free(value);
        value = NULL;
    }

out:
    free(value);
    return ret;
}
#endif

static im_list_request *fold_filter(const image_list_images_request *request)
{
    im_list_request *ctx = NULL;

    ctx = image_list_context_new(request);
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
        if (!filters_args_valid_key(g_accepted_image_filter_tags, sizeof(g_accepted_image_filter_tags) / sizeof(char *),
                                    request->filters->keys[i])) {
            ERROR("Invalid filter '%s'", request->filters->keys[i]);
            isulad_set_error_message("Invalid filter '%s'", request->filters->keys[i]);
            goto error_out;
        }

        if (do_add_filters(request->filters->keys[i], request->filters->values[i], ctx) != 0) {
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

/* When inspect none image, we respone following string according hasen's request. */
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

    if (!util_valid_image_name(image_ref)) {
        ERROR("Inspect invalid name %s", image_ref);
        isulad_set_error_message("Inspect invalid name %s", image_ref);
        ret = -1;
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
}
