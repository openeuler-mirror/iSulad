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
 * Description: provide cdi device function definition
 ******************************************************************************/
#ifndef CDI_DEVICE_H
#define CDI_DEVICE_H

#include <stdbool.h>
#include <isula_libutils/cdi_device.h>
#include <isula_libutils/oci_runtime_spec.h>

#include "cdi_container_edits.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cdi_cache_spec;

struct cdi_cache_device {
    const cdi_device *raw_device;
    const struct cdi_cache_spec *cache_spec;
};

void free_cdi_cache_device(struct cdi_cache_device *d);

struct cdi_cache_device *cdi_device_new_device(struct cdi_cache_spec *spec, cdi_device *d);
const struct cdi_cache_spec *cdi_device_get_spec(const struct cdi_cache_device *d);
char *cdi_device_get_qualified_name(const struct cdi_cache_device *d);
cdi_container_edits *cdi_device_get_edits(const struct cdi_cache_device *d);

#ifdef __cplusplus
}
#endif

#endif