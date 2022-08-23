/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container supervisor functions
 ******************************************************************************/
#define _GNU_SOURCE
#include <isula_libutils/container_config_v2.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "service_image_api.h"
#include "isula_libutils/log.h"
#include "image_api.h"
#include "utils.h"
#include "container_api.h"
#include "events_sender_api.h"
#include "err_msg.h"
#include "event_type.h"
#include "path.h"

static bool embeded_image_check(const char *image_ref, container_t *cont)
{
    return strcmp(cont->common_config->image, image_ref) == 0;
}

static bool external_image_check(const char *image_ref, container_t *cont)
{
    char cleanend_base_fs[PATH_MAX + 1] = { 0 };
    char cleaned_img_ref[PATH_MAX + 1] = { 0 };

    if (util_clean_path(image_ref, cleaned_img_ref, PATH_MAX) == NULL) {
        WARN("Remove invalid image: %s, just ignore it.", image_ref);
        return true;
    }

    if (util_clean_path(cont->common_config->base_fs, cleanend_base_fs, PATH_MAX) == NULL) {
        WARN("Container: %s base fs: %s maybe invalid.", cont->common_config->name, cont->common_config->base_fs);
        return false;
    }

    return strcmp(cleanend_base_fs, cleaned_img_ref) == 0;
}

static inline bool do_check_ignore(const container_t *cont, const char *img_type)
{
    if (cont->common_config->image == NULL) {
        return true;
    }

    if (cont->common_config->image_type == NULL) {
        return true;
    }

    // just check same type image of required
    return strcmp(img_type, cont->common_config->image_type) != 0;
}

static bool check_image_in_used(const char *image_ref)
{
    char *img_type = NULL;
    bool in_used = false;
    int ret = 0;
    size_t i = 0;
    size_t container_num = 0;
    container_t **conts = NULL;

    img_type = im_get_image_type(image_ref, NULL);
    if (img_type == NULL) {
        ERROR("Do not found image type of %s", image_ref);
        return true;
    }

    ret = containers_store_list(&conts, &container_num);
    if (ret != 0) {
        ERROR("Query all containers info failed");
        in_used = true;
        goto out;
    }
    /* check if container is using this image */
    for (i = 0; i < container_num; i++) {
        if (in_used) {
            goto unref_continue;
        }
        if (do_check_ignore(conts[i], img_type)) {
            goto unref_continue;
        }

        if (strcmp(IMAGE_TYPE_EMBEDDED, img_type) == 0) {
            if (embeded_image_check(image_ref, conts[i])) {
                isulad_set_error_message("Embeded image used by %s", conts[i]->common_config->id);
                in_used = true;
                goto unref_continue;
            }
        } else if (strcmp(IMAGE_TYPE_EXTERNAL, img_type) == 0) {
            if (external_image_check(image_ref, conts[i])) {
                isulad_set_error_message("External rootfs used by %s", conts[i]->common_config->id);
                in_used = true;
                goto unref_continue;
            }
        }

unref_continue:
        container_unref(conts[i]);
    }

out:
    free(conts);
    free(img_type);
    return in_used;
}

/* delete image info */
int delete_image(const char *image_ref, bool force)
{
    int ret = 0;
    im_rmi_request *im_request = NULL;
    im_remove_response *im_response = NULL;

    if (image_ref == NULL) {
        ERROR("Invalid NULL param");
        ret = -1;
        goto out;
    }

    if (check_image_in_used(image_ref)) {
        ERROR("Failed to remove in used image %s", image_ref);
        ret = -1;
        goto out;
    }

    im_request = util_common_calloc_s(sizeof(im_rmi_request));
    if (im_request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    im_request->image.image = util_strdup_s(image_ref);
    im_request->force = force;

    ret = im_rm_image(im_request, &im_response);
    if (ret != 0) {
        if (im_response != NULL && im_response->errmsg != NULL) {
            ERROR("Remove image %s failed:%s", image_ref, im_response->errmsg);
            isulad_try_set_error_message("Remove image %s failed:%s", image_ref, im_response->errmsg);
        } else {
            ERROR("Remove image %s failed", image_ref);
            isulad_try_set_error_message("Remove image %s failed", image_ref);
        }
        ret = -1;
        goto out;
    }
    (void)isulad_monitor_send_image_event(im_request->image.image, IM_REMOVE);

out:
    free_im_remove_request(im_request);
    free_im_remove_response(im_response);

    return ret;
}
