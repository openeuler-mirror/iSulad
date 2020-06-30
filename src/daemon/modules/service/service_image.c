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
#include "service_image_api.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>

#include "isula_libutils/log.h"
#include "image_api.h"
#include "utils.h"
#include "container_api.h"
#include "events_sender_api.h"

static bool check_image_in_used(const char *image_ref)
{
    bool in_used = false;
    int ret = 0;
    size_t i = 0;
    size_t container_num = 0;
    container_t **conts = NULL;

    ret = containers_store_list(&conts, &container_num);
    if (ret != 0) {
        ERROR("query all containers info failed");
        in_used = true;
        goto out;
    }
    /* check if container is using this image */
    for (i = 0; i < container_num; i++) {
        if (in_used) {
            goto unref_continue;
        }
        if (conts[i]->common_config->image == NULL) {
            goto unref_continue;
        }

        if (strcmp(conts[i]->common_config->image, image_ref) == 0) {
            isulad_set_error_message("Image used by %s", conts[i]->common_config->id);
            ERROR("Image used by %s", conts[i]->common_config->id);
            in_used = true;
            goto unref_continue;
        }
unref_continue:
        container_unref(conts[i]);
        continue;
    }

out:
    free(conts);
    return in_used;
}

/* delete image info */
int delete_image(const char *image_ref, bool force)
{
    int ret = 0;
    im_rmi_request *im_request = NULL;
    im_remove_response *im_response = NULL;

    if (image_ref == NULL) {
        ERROR("invalid NULL param");
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
