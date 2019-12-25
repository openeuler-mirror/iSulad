/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-16
* Description: provide isula image operator definition
*******************************************************************************/
#ifndef __IMAGE_GLOBAL_CONFIG_H
#define __IMAGE_GLOBAL_CONFIG_H

#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PARAM_NUM 100

enum {
    GB_OPTION_GRAPH_ROOT = 0,
    GB_OPTION_RUN_ROOT,
    GB_OPTION_DRIVER_NAME,
    GB_OPTION_DRIVER_OPTIONS,
    GB_OPTION_STORAGE_OPTIONS,
    GB_OPTION_REGISTRY,
    GB_OPTION_INSEC_REGISTRY,
    GB_OPTION_OPT_TIMEOUT,
    GB_OPTION_LOG_LEVEL,
    GB_OPTION_GRPC_SERVER_ADDR, // image server socket addr
    GB_OPTION_MAX, // should not be used
};


static inline void add_array_elem(char **array, size_t total, size_t *pos, const char *elem)
{
    if (*pos + 1 >= total - 1) {
        return;
    }
    array[*pos] = util_strdup_s(elem);
    *pos += 1;
}

static inline void add_array_kv(char **array, size_t total, size_t *pos, const char *k, const char *v)
{
    if (k == NULL || v == NULL) {
        return;
    }
    add_array_elem(array, total, pos, k);
    add_array_elem(array, total, pos, v);
}

int pack_global_options(const char * const *options, char *params[], size_t *count, bool ignore_storage_opt_size);

#ifdef __cplusplus
}
#endif

#endif /* __IMAGE_GLOBAL_CONFIG_H */
