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
#include "clean_context.h"
#include "linked_list.h"
#include "utils.h"
#include "isula_libutils/log.h"

struct clean_ctx *clean_ctx_init(void)
{
    struct clean_ctx *ctx = util_common_calloc_s(sizeof(struct clean_ctx));
    if (ctx == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    linked_list_init(&(ctx->broken_rootfs_list));
    ctx->inited = true;

    return ctx;
}

void clean_ctx_destroy(struct clean_ctx *ctx)
{
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    char *id = NULL;

    if (ctx == NULL) {
        return;
    }

    if (!ctx->inited) {
        free(ctx);
        return;
    }

    linked_list_for_each_safe(it, &(ctx->broken_rootfs_list), next) {
        id = (char *)it->elem;
        linked_list_del(it);
        free(id);
        free(it);
        it = NULL;
    }

    free(ctx);
}

void clean_ctx_fill_broken_rootfs(struct clean_ctx *ctx, const char *id)
{
    struct linked_list *new_node = NULL;
    char *broken_id = NULL;

    if (ctx == NULL || !ctx->inited) {
        return;
    }

    new_node = util_common_calloc_s(sizeof(struct linked_list));
    if (new_node == NULL) {
        ERROR("Out of memory, broken rootfs %s not added", id);
        return;
    }

    broken_id = util_strdup_s(id);
    linked_list_add_elem(new_node, broken_id);
    linked_list_add_tail(&ctx->broken_rootfs_list, new_node);
}