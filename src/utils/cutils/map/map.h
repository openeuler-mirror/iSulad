/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container map definition
 ******************************************************************************/
#ifndef UTILS_CUTILS_MAP_MAP_H
#define UTILS_CUTILS_MAP_MAP_H

#include <stdbool.h>
#include <stddef.h>

#include "rb_tree.h"

struct _map_t;

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef struct _map_t map_t;
typedef struct rb_iterator map_itor;

#define MAP_DEFAULT_CMP_FUNC NULL
#define MAP_DEFAULT_FREE_FUNC NULL

/* function to free key and value */
typedef key_value_freer map_kvfree_func;

/* function to compare key */
typedef key_comparator map_cmp_func;

/* function to remove element by key */
bool map_remove(map_t *map, void *key);

/* function to search key */
void *map_search(const map_t *map, void *key);

/* function to get size of map */
size_t map_size(const map_t *map);

/* function to replace key value */
bool map_replace(const map_t *map, void *key, void *value);

/* function to insert key value */
bool map_insert(map_t *map, void *key, void *value);

/* function to return map itor */
map_itor *map_itor_new(const map_t *map);

/* function to free map itor */
void map_itor_free(map_itor *itor);

/* function to locate first map itor */
bool map_itor_first(map_itor *itor);

/* function to locate last map itor */
bool map_itor_last(map_itor *itor);

/* function to locate next itor */
bool map_itor_next(map_itor *itor);

/* function to locate prev itor */
bool map_itor_prev(map_itor *itor);

/* function to check itor is valid */
bool map_itor_valid(const map_itor *itor);

/* function to check itor is valid */
void *map_itor_key(map_itor *itor);

/* function to check itor is valid */
void *map_itor_value(map_itor *itor);

typedef enum {
    MAP_INT_INT = 0,
    MAP_INT_BOOL,
    MAP_INT_STR,
    MAP_INT_PTR,
    MAP_STR_BOOL,
    MAP_STR_INT,
    MAP_STR_PTR,
    MAP_STR_STR,
    MAP_PTR_INT,
    MAP_PTR_STR,
    MAP_PTR_PTR
} map_type_t;

struct _map_t {
    map_type_t type;
    rb_tree_t *store;
};

map_t *map_new(map_type_t kvtype, map_cmp_func comparator, map_kvfree_func kvfree);

void map_free(map_t *map);

void map_clear(map_t *map);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif // UTILS_CUTILS_MAP_MAP_H

