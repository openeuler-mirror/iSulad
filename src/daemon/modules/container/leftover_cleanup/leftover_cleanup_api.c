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
 * Description: provide cleanup functions
 *********************************************************************************/
#include "utils.h"
#include "leftover_cleanup_api.h"
#include "cleanup.h"
#include "clean_context.h"

struct clean_ctx *g_clean_ctx = NULL;
struct cleaners *g_clns = NULL;

int clean_module_init(const isulad_daemon_configs *args)
{
    if (args->storage_enable_remote_layer) {
        // need to disable cleanup
        // cause cleanup may cleanup local broken RO layer
        // while this RO layer is valid for remote 
        return 0;
    }

    // create cleaners and clean_ctx
    g_clns = cleaners_init();
    if (g_clns == NULL) {
        ERROR("Failed to init clean module");
        return -1;
    }

    g_clean_ctx = clean_ctx_init();
    if (g_clean_ctx == NULL) {
        ERROR("Failed to init clean module");
        destroy_cleaners(g_clns);
        return -1;
    }

    return 0;
}

void clean_module_fill_ctx(cleanup_ctx_data_t data_type, void *data)
{
    switch (data_type) {
        case BROKEN_ROOTFS:
            clean_ctx_fill_broken_rootfs(g_clean_ctx, data);
            break;
    }
}

void clean_module_do_clean()
{
    if (g_clns == NULL || g_clean_ctx == NULL) {
        return;
    }

    cleaners_do_clean(g_clns, g_clean_ctx);

    if (g_clns->count == g_clns->done_clean) {
        DEBUG("all clean up success");
    } else {
        ERROR("Aim to do %d clean, %d clean sucess\n", g_clns->count, g_clns->done_clean);
    }

    destroy_cleaners(g_clns);
    clean_ctx_destroy(g_clean_ctx);

    g_clns = NULL;
    g_clean_ctx = NULL;
}

