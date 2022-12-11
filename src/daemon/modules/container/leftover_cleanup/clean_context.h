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
 * Create: 2022-10-31
 * Description: provide cleanup definition
 *********************************************************************************/
#ifndef DAEMON_MODULES_CONTAINER_LEFTOVER_CLEANUP_CLEAN_CONTEXT_H
#define DAEMON_MODULES_CONTAINER_LEFTOVER_CLEANUP_CLEAN_CONTEXT_H

#include "linked_list.h"
#include "utils.h"
#include "isula_libutils/log.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

struct clean_ctx {
    bool inited;
    struct linked_list broken_rootfs_list;
};

struct clean_ctx *clean_ctx_init();

void clean_ctx_destroy(struct clean_ctx *ctx);

void clean_ctx_fill_broken_rootfs(struct clean_ctx *ctx, const char *id);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif