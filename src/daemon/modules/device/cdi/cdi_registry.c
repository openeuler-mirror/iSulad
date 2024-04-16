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
 * Author: liuxu
 * Create: 2024-03-06
 * Description: provide cdi registry function
 ******************************************************************************/
#include "cdi_registry.h"

#include <util_atomic.h>
#include <isula_libutils/auto_cleanup.h>

static struct cdi_registry g_cdi_reg = { 0 };

int cdi_registry_init(string_array *spec_dirs)
{
    // isulad will use default dirs when spec_dirs == NULL
    g_cdi_reg.cdi_cache = cdi_new_cache(spec_dirs);
    if (g_cdi_reg.cdi_cache == NULL) {
        ERROR("Failed to init registry");
        return -1;
    }
    g_cdi_reg.ops = cdi_get_cache_ops();
    return 0;
}

struct cdi_registry *cdi_get_registry(void)
{
    return &g_cdi_reg;
}
