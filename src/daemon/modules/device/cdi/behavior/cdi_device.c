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
 * Description: provide cdi device function
 ******************************************************************************/
#include "cdi_device.h"

void free_cdi_cache_device(struct cdi_cache_device *d)
{
    (void)d;
}

struct cdi_cache_device *cdi_device_new_device(struct cdi_cache_spec *spec, cdi_device *d, char **error)
{
    return NULL;
}

struct cdi_cache_spec *cdi_device_get_spec(struct cdi_cache_device *d)
{
    return NULL;
}

char *cdi_device_get_qualified_name(struct cdi_cache_device *d)
{
    return NULL;
}

cdi_container_edits *cdi_device_get_edits(struct cdi_cache_device *d)
{
    return NULL;
}
