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
 * Author: wangrunze
 * Create: 2022-12-7
 * Description: provide cleanup functions
 *********************************************************************************/
#ifndef DAEMON_MODULES_API_LEFTOVER_CLEANUP_API_H
#define DAEMON_MODULES_API_LEFTOVER_CLEANUP_API_H

#include <isula_libutils/isulad_daemon_configs.h>

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef enum {
    BROKEN_ROOTFS = 1
} cleanup_ctx_data_t;

int clean_module_init(const isulad_daemon_configs *args);

void clean_module_fill_ctx(cleanup_ctx_data_t data_type, void *data);

void clean_module_do_clean();

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif
