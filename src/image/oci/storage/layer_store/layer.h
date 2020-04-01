
/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: liuhao
 * Create: 2020-03-24
 * Description: provide layer store function definition
 ******************************************************************************/
#ifndef __OCI_STORAGE_LAYER_H
#define __OCI_STORAGE_LAYER_H

#include <stdint.h>

#include "defs.h"

#ifdef __cplusplus
extern "C" {
#endif

struct layer_config {
    /*configs for graph driver */
    char *driver_name;
    char *driver_root;
    char **driver_opts;
    size_t driver_opts_len;

    defs_id_mapping *uid_map;
    size_t uid_map_len;
    defs_id_mapping *gid_map;
    size_t gid_map_len;

};

struct layer_store_ops {
    int (*init)(const struct layer_config *conf);
};

#ifdef __cplusplus
}
#endif

#endif
