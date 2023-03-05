/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2023. All rights reserved.
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
 * Description: provide remote support functions
 ******************************************************************************/

#ifndef DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_REMOTE_LAYER_SUPPORT_REMOTE_SUPPORT_H
#define DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_REMOTE_LAYER_SUPPORT_REMOTE_SUPPORT_H

#include "linked_list.h"
#define REMOTE_RO_LAYER_DIR "RO"
#define OVERLAY_RO_DIR "RO"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *(*create)(const char *remote_home, const char *remote_ro);
    void (*destroy)(void *data);
    // populate the list contains all dirs
    int (*scan_remote_dir)(void *data);
    // consume the list contains all dirs
    int (*load_item)(void *data);
} remote_support;

typedef struct {
    void *data;
    remote_support *handlers;
} remote_supporter;

// RemoteSupport *impl_remote_support();
remote_supporter *create_image_supporter(const char *remote_home, const char *remote_ro);

remote_supporter *create_layer_supporter(const char *remote_home, const char *remote_ro);

remote_supporter *create_overlay_supporter(const char *remote_home, const char *remote_ro);

void destroy_suppoter(remote_supporter *supporter);

int scan_remote_dir(remote_supporter *supporter);

int load_item(remote_supporter *supporter);

#ifdef __cplusplus
}
#endif

#endif
