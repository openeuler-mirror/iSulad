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
 * Description: provide cdi spec dirs function definition
 ******************************************************************************/
#ifndef CDI_SPEC_DIRS_H
#define CDI_SPEC_DIRS_H

#include "cdi_cache.h"
#include "utils_array.h"
#include "map.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CDI_DEFAULT_STATIC_DIR "/etc/cdi"
#define CDI_DEFAULT_DYNAMIC_DIR "/var/run/cdi"

extern string_array g_default_spec_dirs;
 
struct cdi_scan_fn_maps {
    map_t *specs;
    map_t *devices;
    map_t *conflicts;
    bool *refresh_error_flag;
};
typedef void(*cdi_scan_spec_func)(struct cdi_scan_fn_maps *scan_fn_maps, const char *path, int priority,
                                  struct cdi_cache_spec *spec);

int cdi_scan_spec_dirs(string_array *dirs, struct cdi_scan_fn_maps *scan_fn_maps, cdi_scan_spec_func scan_fn);

#ifdef __cplusplus
}
#endif

#endif