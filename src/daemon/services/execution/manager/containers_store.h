/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide containers store definition
 ******************************************************************************/
#ifndef __ISULAD_MEMORY_STORE_H__
#define __ISULAD_MEMORY_STORE_H__

#include "container_unix.h"
#include "map.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

int containers_store_init(void);

bool containers_store_add(const char *id, container_t *cont);

container_t *containers_store_get(const char *id_or_name);

container_t *containers_store_get_by_prefix(const char *prefix);

bool containers_store_remove(const char *id);

int containers_store_list(container_t ***out, size_t *size);

char **containers_store_list_ids(void);

/* name indexs */
int name_index_init(void);

bool name_index_remove(const char *name);

char *name_index_get(const char *name);

bool name_index_add(const char *name, const char *id);

map_t *name_index_get_all(void);

bool name_index_rename(const char *new_name, const char *old_name, const char *id);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_MEMORY_STORE_H__ */

