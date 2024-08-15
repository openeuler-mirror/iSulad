/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-07-17
 * Description: provide nri utils functions
 *********************************************************************************/
#ifndef DAEMON_COMMON_NRI_NRI_UTILS_H
#define DAEMON_COMMON_NRI_NRI_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#include <isula_libutils/nri_create_container_request.h>
#include <isula_libutils/nri_create_container_response.h>
#include <isula_libutils/nri_update_container_request.h>
#include <isula_libutils/nri_update_container_response.h>
#include <isula_libutils/nri_container_update.h>
#include <isula_libutils/nri_mount.h>

#include <isula_libutils/container_config.h>
#include <isula_libutils/host_config.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UNKNOWN = 0,
    RUN_POD_SANDBOX = 1,
    STOP_POD_SANDBOX = 2,
    REMOVE_POD_SANDBOX = 3,
    CREATE_CONTAINER = 4,
    POST_CREATE_CONTAINER = 5,
    START_CONTAINER = 6,
    POST_START_CONTAINER = 7,
    UPDATE_CONTAINER = 8,
    POST_UPDATE_CONTAINER = 9,
    STOP_CONTAINER = 10,
    REMOVE_CONTAINER = 11,
    LAST = 12,
} NRI_Event;

nri_mount *copy_nri_mount(const nri_mount *src);
nri_posix_rlimit *copy_nri_posix_rlimit(const nri_posix_rlimit *src);
nri_linux_resources *copy_nri_linux_resources(const nri_linux_resources *src);
nri_key_value *copy_nri_key_value(const nri_key_value *src);
nri_linux_device *copy_nri_device(const nri_linux_device *src);

bool is_marked_for_removal(const char* key, char **out);

bool merge_nri_hooks(nri_hook **targetHooks, size_t targetSize, const nri_hook **sourceHooks,
                     size_t sourceLen);

nri_container_update *init_nri_container_update(const char *id, const uint8_t ignore_failure);
nri_linux_resources *init_nri_linux_resources(void);

#ifdef __cplusplus
}
#endif

#endif // DAEMON_COMMON_NRI_NRI_UTILS_H