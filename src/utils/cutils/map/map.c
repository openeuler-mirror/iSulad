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
 * Description: provide container map functions
 ******************************************************************************/
#include <stdlib.h>
#include <string.h>

#include "map.h"
#include "isula_libutils/log.h"
#include "utils.h"

static void map_free_key_value(void *key, void *val)
{
    free(key);
    free(val);
}

/* function to remove element by key */
bool map_remove(map_t *map, void *key)
{
    if (map == NULL || key == NULL) {
        return false;
    }

    return rbtree_remove(map->store, key);
}

/* function to search key */
void *map_search(const map_t *map, void *key)
{
    if (map == NULL || key == NULL) {
        return NULL;
    }

    return rbtree_search(map->store, key);
}

/* function to return map itor */
map_itor *map_itor_new(const map_t *map)
{
    if (map == NULL) {
        return NULL;
    }

    return rbtree_iterator_new(map->store);
}

/* function to free map itor */
void map_itor_free(map_itor *itor)
{
    if (itor == NULL) {
        return;
    }

    rbtree_iterator_free(itor);
}

/* function to locate first map itor */
bool map_itor_first(map_itor *itor)
{
    if (itor == NULL) {
        return false;
    }

    return rbtree_iterator_first(itor);
}

/* function to locate last map itor */
bool map_itor_last(map_itor *itor)
{
    if (itor == NULL) {
        return false;
    }

    return rbtree_iterator_last(itor);
}

/* function to locate next itor */
bool map_itor_next(map_itor *itor)
{
    if (itor == NULL) {
        return false;
    }

    return rbtree_iterator_next(itor);
}

/* function to locate prev itor */
bool map_itor_prev(map_itor *itor)
{
    if (itor == NULL) {
        return false;
    }

    return rbtree_iterator_prev(itor);
}

/* function to check itor is valid */
bool map_itor_valid(const map_itor *itor)
{
    if (itor == NULL) {
        return false;
    }

    return rbtree_iterator_valid(itor);
}

/* function to check itor is valid */
void *map_itor_key(map_itor *itor)
{
    if (itor == NULL) {
        return NULL;
    }

    return rbtree_iterator_key(itor);
}

/* function to check itor is valid */
void *map_itor_value(map_itor *itor)
{
    if (itor == NULL) {
        return NULL;
    }

    return rbtree_iterator_value(itor);
}

/* function to get size of map */
size_t map_size(const map_t *map)
{
    if (map == NULL) {
        return 0;
    }

    return rbtree_size(map->store);
}

/* is key int */
static bool is_key_int(map_type_t type)
{
    return (type == MAP_INT_INT || type == MAP_INT_STR || type == MAP_INT_PTR || type == MAP_INT_BOOL);
}

/* is key str */
static bool is_key_str(map_type_t type)
{
    return (type == MAP_STR_INT || type == MAP_STR_STR || type == MAP_STR_PTR || type == MAP_STR_BOOL);
}

/* is key ptr */
static bool is_key_ptr(map_type_t type)
{
    return (type == MAP_PTR_INT || type == MAP_PTR_STR || type == MAP_PTR_PTR);
}

/* is val bool */
static bool is_val_bool(map_type_t type)
{
    return (type == MAP_STR_BOOL || type == MAP_INT_BOOL);
}

/* is val int */
static bool is_val_int(map_type_t type)
{
    return (type == MAP_INT_INT || type == MAP_STR_INT || type == MAP_PTR_INT);
}

/* is val str */
static bool is_val_str(map_type_t type)
{
    return (type == MAP_INT_STR || type == MAP_STR_STR || type == MAP_PTR_STR);
}

/* is val ptr */
static bool is_val_ptr(map_type_t type)
{
    return (type == MAP_INT_PTR || type == MAP_STR_PTR || type == MAP_PTR_PTR);
}

static void *map_convert_key(const map_t *map, void *key)
{
    void *insert_key = NULL;
    int *ikey = NULL;
    char *skey = NULL;
    if (is_key_ptr(map->type)) {
        insert_key = key;
    } else if (is_key_int(map->type)) {
        ikey = util_common_calloc_s(sizeof(int));
        if (ikey == NULL) {
            ERROR("out of memory");
            return NULL;
        }
        *ikey = *(int *)key;
        insert_key = (void *)ikey;
    } else if (is_key_str(map->type)) {
        skey = util_strdup_s((const char *)key);
        if (skey == NULL) {
            ERROR("out of memory");
            return NULL;
        }
        insert_key = (void *)skey;
    } else {
        return NULL;
    }
    return insert_key;
}

static void *map_convert_value(const map_t *map, void *value)
{
    void *insert_value = NULL;
    bool *bvalue = NULL;
    int *ivalue = NULL;
    char *svalue = NULL;
    if (is_val_ptr(map->type)) {
        insert_value = value;
    } else if (is_val_bool(map->type)) {
        bvalue = util_common_calloc_s(sizeof(bool));
        if (bvalue == NULL) {
            return NULL;
        }
        *bvalue = *(bool *)value;
        insert_value = (void *)bvalue;
    } else if (is_val_int(map->type)) {
        ivalue = util_common_calloc_s(sizeof(int));
        if (ivalue == NULL) {
            return NULL;
        }
        *ivalue = *(int *)value;
        insert_value = (void *)ivalue;
    } else if (is_val_str(map->type)) {
        svalue = util_strdup_s((const char *)value);
        insert_value = (void *)svalue;
    } else {
        return NULL;
    }
    return insert_value;
}

/* function to replace key value */
bool map_replace(const map_t *map, void *key, void *value)
{
    void *tmp = NULL;
    void *tmp_value = NULL;

    if (map == NULL || key == NULL || value == NULL) {
        ERROR("invalid parameter");
        return false;
    }

    tmp = map_convert_key(map, key);
    if (tmp == NULL) {
        ERROR("failed to convert key, out of memory or invalid k-v type");
        return false;
    }

    tmp_value = map_convert_value(map, value);
    if (tmp_value == NULL) {
        ERROR("failed to convert value, out of memory or invalid k-v type");
        if (!is_key_ptr(map->type)) {
            free(tmp);
        }
        return false;
    }

    bool ret = rbtree_replace(map->store, tmp, tmp_value);
    if (!ret) {
        ERROR("failed to replace node in rbtree");
        if (!is_key_ptr(map->type)) {
            free(tmp);
        }
        if (!is_val_ptr(map->type)) {
            free(tmp_value);
        }
    }

    return ret;
}

/* function to insert key value */
bool map_insert(map_t *map, void *key, void *value)
{
    void *tmp = NULL;
    void *tmp_value = NULL;

    if (map == NULL || key == NULL || value == NULL) {
        ERROR("invalid parameter");
        return false;
    }

    tmp = map_convert_key(map, key);
    if (tmp == NULL) {
        ERROR("failed to convert key, out of memory or invalid k-v type");
        return false;
    }
    tmp_value = map_convert_value(map, value);
    if (tmp_value == NULL) {
        ERROR("failed to convert value, out of memory or invalid k-v type");
        if (!is_key_ptr(map->type)) {
            free(tmp);
        }
        return false;
    }

    bool ret = rbtree_insert(map->store, tmp, tmp_value);
    if (!ret) {
        ERROR("failed to insert node to rbtree");
        if (!is_key_ptr(map->type)) {
            free(tmp);
        }
        if (!is_val_ptr(map->type)) {
            free(tmp_value);
        }
    }
    return ret;
}

// malloc a new map by type
map_t *map_new(map_type_t kvtype, map_cmp_func comparator, map_kvfree_func kvfree)
{
    map_t *map = NULL;
    key_comparator cmpor = NULL;
    key_value_freer freer = NULL;

    map = util_common_calloc_s(sizeof(map_t));
    if (map == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    if (kvfree == MAP_DEFAULT_FREE_FUNC) {
        freer = map_free_key_value;
    } else {
        freer = kvfree;
    }
    cmpor = comparator;
    if (is_key_ptr(kvtype) && (comparator == MAP_DEFAULT_CMP_FUNC)) {
        cmpor = rbtree_ptr_cmp;
    } else if (is_key_int(kvtype) && (comparator == MAP_DEFAULT_CMP_FUNC)) {
        cmpor = rbtree_int_cmp;
    } else if (is_key_str(kvtype) && (comparator == MAP_DEFAULT_CMP_FUNC)) {
        cmpor = rbtree_str_cmp;
    } else {
        ERROR("invalid comparator!");
        free(map);
        return NULL;
    }
    map->type = kvtype;
    map->store = rbtree_new(cmpor, freer);
    if (map->store == NULL) {
        map_free(map);
        return NULL;
    }
    return map;
}

/* just clear all nodes */
void map_clear(map_t *map)
{
    if (map != NULL && map->store != NULL) {
        rbtree_clear(map->store);
    }
}

/* map free */
void map_free(map_t *map)
{
    if (map == NULL) {
        return;
    }

    if (map->store != NULL) {
        rbtree_free(map->store);
        map->store = NULL;
    }
    free(map);
}

