/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2020-09-28
 * Description: cached for cni
 *********************************************************************************/
#ifndef CLIBCNI_CACHED_H
#define CLIBCNI_CACHED_H

#include <isula_libutils/cni_cached_info.h>

#include "libcni_api.h"

#ifdef __cplusplus
extern "C" {
#endif

int copy_cni_port_mapping(const struct cni_port_mapping *src, cni_inner_port_mapping *dst);

int cni_cache_add(const char *cache_dir, const struct result *res, const char *config, const char *net_name,
                  const struct runtime_conf *rc);

int cni_cache_delete(const char *cache_dir, const char *net_name, const struct runtime_conf *rc);

int cni_cache_read(const char *cache_dir, const char *net_name, const struct runtime_conf *rc,
                   cni_cached_info **p_info);

int cni_get_cached_config(const char *cache_dir, const char *net_name, struct runtime_conf *rc, char **config);

int cni_get_cached_result(const char *cache_dir, const char *net_name, const char *hope_version,
                          const struct runtime_conf *rc, struct result **cached_res);

#ifdef __cplusplus
}
#endif

#endif
