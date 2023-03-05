/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2023-01-12
 * Description: provide remote symlink maintain functions
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_REMOTE_LAYER_SUPPORT_RO_SYMLINK_MAINTAIN_H
#define DAEMON_MODULES_IMAGE_OCI_STORAGE_LAYER_STORE_REMOTE_LAYER_SUPPORT_RO_SYMLINK_MAINTAIN_H

#include "map.h"

#ifdef __cplusplus
extern "C" {
#endif

int remote_image_init(const char *root_dir);

int remote_layer_init(const char *root_dir);

int remote_overlay_init(const char *driver_home);

void remote_maintain_cleanup(void);

int start_refresh_thread(void);

int remote_layer_build_ro_dir(const char *id);

int remote_overlay_build_ro_dir(const char *id);

int remote_layer_remove_ro_dir(const char *id);

int remote_overlay_remove_ro_dir(const char *id);

char **deleted_layers(map_t *old, map_t *new);

char **added_layers(map_t *old, map_t *new);

int empty_map(map_t *mp);

#ifdef __cplusplus
}
#endif

#endif
