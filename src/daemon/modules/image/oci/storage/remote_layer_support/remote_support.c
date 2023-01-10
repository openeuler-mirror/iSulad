/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2023-03-03
 * Description: provide image store functions
 ******************************************************************************/

#include "remote_support.h"

#include "layer_store.h"
#include "image_store.h"
#include "isula_libutils/log.h"
#include "driver_overlay2.h"
#include "utils.h"

remote_supporter *create_layer_supporter(const char *remote_home, const char *remote_ro)
{
    remote_support *handlers = layer_store_impl_remote_support();
    if (handlers == NULL || handlers->create == NULL) {
        return NULL;
    }

    remote_supporter *supporter = (remote_supporter *)util_common_calloc_s(sizeof(remote_supporter));
    if (supporter == NULL) {
        goto err_out;
    }

    supporter->handlers = handlers;
    supporter->data = handlers->create(remote_home, remote_ro);

    return supporter;

err_out:
    free(handlers);
    free(supporter);
    return NULL;
}

remote_supporter *create_image_supporter(const char *remote_home, const char *remote_ro)
{
    remote_support *handlers = image_store_impl_remote_support();
    if (handlers == NULL || handlers->create == NULL) {
        return NULL;
    }

    remote_supporter *supporter = (remote_supporter *)util_common_calloc_s(sizeof(remote_supporter));
    if (supporter == NULL) {
        goto err_out;
    }

    supporter->handlers = handlers;
    supporter->data = handlers->create(remote_home, remote_ro);

    return supporter;

err_out:
    free(handlers);
    free(supporter);
    return NULL;
}

remote_supporter *create_overlay_supporter(const char *remote_home, const char *remote_ro)
{
    remote_support *handlers = overlay_driver_impl_remote_support();
    if (handlers == NULL || handlers->create == NULL) {
        return NULL;
    }

    remote_supporter *supporter = (remote_supporter *)util_common_calloc_s(sizeof(remote_supporter));
    if (supporter == NULL) {
        goto err_out;
    }

    supporter->handlers = handlers;
    supporter->data = handlers->create(remote_home, remote_ro);

    return supporter;

err_out:
    free(handlers);
    free(supporter);
    return NULL;

}

void destroy_suppoter(remote_supporter *supporter)
{
    if (supporter->handlers->destroy == NULL) {
        ERROR("destroy_supporter operation not supported");
        return;
    }

    supporter->handlers->destroy(supporter->data);
    free(supporter->handlers);
    free(supporter);
}

int scan_remote_dir(remote_supporter *supporter)
{
    if (supporter->handlers->scan_remote_dir == NULL) {
        ERROR("scan_remote_dir operation not supported");
        return -1;
    }
    return supporter->handlers->scan_remote_dir(supporter->data);
}

int load_item(remote_supporter *supporter)
{
    if (supporter->handlers->scan_remote_dir == NULL) {
        ERROR("load_item operation not supported");
        return -1;
    }
    return supporter->handlers->load_item(supporter->data);
}
