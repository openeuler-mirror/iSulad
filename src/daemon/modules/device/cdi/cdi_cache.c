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
 * Description: provide cdi cache function
 ******************************************************************************/
#include "cdi_cache.h"

void free_cdi_cache(struct cdi_cache *c)
{
    (void)c;
}

struct cdi_cache *cdi_new_cache(string_array *spec_dirs)
{
    return NULL;
}

static int cdi_inject_devices(struct cdi_cache *c, oci_runtime_spec *oci_spec, string_array *devices)
{
    return 0;
}

static int cdi_configure(struct cdi_cache *c, string_array *spec_dirs)
{
    return 0;
}

static int cdi_refresh(struct cdi_cache *c)
{
    return 0;
}

static map_t *cdi_get_errors(struct cdi_cache *c)
{
    return NULL;
}

static string_array *cdi_get_spec_directories(struct cdi_cache *c)
{
    return NULL;
}

static map_t *cdi_get_spec_dir_errors(struct cdi_cache *c)
{
    return NULL;
}

static struct cdi_cache_ops g_cdi_cache_ops = {
    .inject_devices = cdi_inject_devices,
    .configure = cdi_configure,
    .refresh = cdi_refresh,
    .get_errors = cdi_get_errors,
    .get_spec_directories = cdi_get_spec_directories,
    .get_spec_dir_errors = cdi_get_spec_dir_errors
};

struct cdi_cache_ops *cdi_get_cache_ops(void)
{
    return &g_cdi_cache_ops;
}