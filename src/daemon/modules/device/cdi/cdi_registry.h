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
 * Description: provide cdi registry function definition
 ******************************************************************************/
#ifndef CDI_REGISTRY_H
#define CDI_REGISTRY_H

#include "cdi_cache.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cdi_registry {
    struct cdi_cache *cdi_cache;
    struct cdi_cache_ops *ops;
};

int cdi_registry_init(string_array *spec_dirs);
struct cdi_registry *cdi_get_registry(void);

#ifdef __cplusplus
}
#endif

#endif