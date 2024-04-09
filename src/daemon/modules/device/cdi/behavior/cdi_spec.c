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
 * Description: provide cdi spec function
 ******************************************************************************/
#include "cdi_spec.h"

void free_cdi_cache_spec(struct cdi_cache_spec *s)
{
    (void)s;
}

struct cdi_cache_spec *cdi_spec_read_spec(const char *path, int priority, char **error)
{
    return NULL;
}

struct cdi_cache_spec *cdi_spec_new_spec(cdi_spec *raw, const char *path, int priority, char **error)
{
    return NULL;
}

const char *cdi_spec_get_vendor(struct cdi_cache_spec *s)
{
    return NULL;
}

const char *cdi_spec_get_class(struct cdi_cache_spec *s)
{
    return NULL;
}

struct cdi_cache_device *cdi_spec_get_cache_device(struct cdi_cache_spec *s, const char *name)
{
    return NULL;
}

const char *cdi_spec_get_path(struct cdi_cache_spec *s)
{
    return NULL;
}

int cdi_spec_get_priority(struct cdi_cache_spec *s)
{
    return 0;
}

cdi_container_edits *cdi_spec_edits(struct cdi_cache_spec *s)
{
    return NULL;
}
