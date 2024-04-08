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
 * Create: 2018-11-1
 * Description: provide container utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_array.h"

#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"

void util_free_array_by_len(char **array, size_t len)
{
    size_t i = 0;

    if (array == NULL) {
        return;
    }

    for (; i < len; i++) {
        UTIL_FREE_AND_SET_NULL(array[i]);
    }

    free(array);
}

void util_free_sensitive_array_by_len(char **array, size_t len)
{
    size_t i = 0;

    if (array == NULL) {
        return;
    }

    for (; i < len; i++) {
        util_free_sensitive_string(array[i]);
        array[i] = NULL;
    }

    free(array);
}

size_t util_array_len(const char **array)
{
    const char **pos;
    size_t len = 0;

    for (pos = array; pos != NULL && *pos != NULL; pos++) {
        len++;
    }

    return len;
}

void util_free_array(char **array)
{
    char **p;

    for (p = array; p != NULL && *p != NULL; p++) {
        UTIL_FREE_AND_SET_NULL(*p);
    }
    free(array);
}

void util_free_sensitive_array(char **array)
{
    char **p;

    for (p = array; p != NULL && *p != NULL; p++) {
        util_free_sensitive_string(*p);
        *p = NULL;
    }
    free(array);
}

char **util_copy_array_by_len(char **array, size_t len)
{
    char **new_array = NULL;
    size_t i;
 
    if (array == NULL || len == 0) {
        return NULL;
    }
 
    new_array = util_smart_calloc_s(sizeof(char *), len);
    if (new_array == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
 
    for (i = 0; i < len; i++) {
        new_array[i] = util_strdup_s(array[i]);
    }
    return new_array;
}

int util_array_append(char ***array, const char *element)
{
    size_t len;
    char **new_array = NULL;

    if (array == NULL || element == NULL) {
        return -1;
    }

    // let new len to len + 2 for element and null
    len = util_array_len((const char **)(*array));

    new_array = util_smart_calloc_s(sizeof(char *), (len + 2));
    if (new_array == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    if (*array != NULL) {
        (void)memcpy(new_array, *array, len * sizeof(char *));
        UTIL_FREE_AND_SET_NULL(*array);
    }
    *array = new_array;

    new_array[len] = util_strdup_s(element);

    return 0;
}

int util_grow_array(char ***orig_array, size_t *orig_capacity, size_t size, size_t increment)
{
    size_t add_capacity;
    char **add_array = NULL;

    if (orig_array == NULL || orig_capacity == NULL || increment == 0) {
        return -1;
    }

    if (((*orig_array) == NULL) || ((*orig_capacity) == 0)) {
        UTIL_FREE_AND_SET_NULL(*orig_array);
        *orig_capacity = 0;
    }

    add_capacity = *orig_capacity;
    while (size + 1 > add_capacity) {
        add_capacity += increment;
    }
    if (add_capacity != *orig_capacity) {
        add_array = util_smart_calloc_s(sizeof(void *), add_capacity);
        if (add_array == NULL) {
            return -1;
        }
        if (*orig_array != NULL) {
            (void)memcpy(add_array, *orig_array, *orig_capacity * sizeof(void *));
            UTIL_FREE_AND_SET_NULL(*orig_array);
        }

        *orig_array = add_array;
        *orig_capacity = add_capacity;
    }

    return 0;
}

bool util_array_contain(const char **array, const char *element)
{
    const char **pos;

    if (array == NULL || element == NULL) {
        return false;
    }

    for (pos = array; *pos != NULL; pos++) {
        if (strcmp(*pos, element) == 0) {
            return true;
        }
    }

    return false;
}

static size_t get_array_scale_size(size_t old_size)
{
#define DOUBLE_THRESHOLD 1024
    const size_t max_threshold = MAX_MEMORY_SIZE / sizeof(char *);
    if (old_size == 0) {
        return 1;
    }

    if (old_size < DOUBLE_THRESHOLD) {
        return old_size << 1;
    }

    // new_size = old_size + old_size / 4
    if (old_size > max_threshold - (old_size >> 2)) {
        return max_threshold;
    }

    return old_size + (old_size >> 2);
}

static bool do_expand_array(string_array *array)
{
    size_t new_size = get_array_scale_size(array->cap);
    char **new_items = NULL;

    // array capability sure less than MAX_MEMORY_SIZE
    // so we need to check Overflow:
    if (new_size == array->cap) {
        ERROR("Too large string array, overflow memory");
        return false;
    }

    // new_size * sizeof(*new_items) and list->len * sizeof(*list->items)
    if (util_mem_realloc((void **)&new_items, new_size * sizeof(char *), (void *)array->items,
                         array->len * sizeof(char *)) != 0) {
        ERROR("Out of memory");
        return false;
    }
    array->items = new_items;
    array->cap = new_size;

    return true;
}

int util_append_string_array(string_array *sarr, const char *val)
{
    if (sarr == NULL) {
        ERROR("invalid string array");
        return -1;
    }

    if (val == NULL) {
        DEBUG("empty new item, just ignore it");
        return 0;
    }

    if (sarr->len < sarr->cap) {
        goto out;
    }

    // expand string array
    if (!do_expand_array(sarr)) {
        return -1;
    }

out:
    sarr->items[sarr->len] = util_strdup_s(val);
    sarr->len += 1;
    return 0;
}

string_array *util_copy_string_array(string_array *sarr)
{
    string_array *ptr = NULL;
    size_t i;
 
    if (sarr == NULL) {
        ERROR("Invalid string array");
        return NULL;
    }
 
    ptr = util_string_array_new(sarr->cap);
    if (ptr == NULL) {
        ERROR("Out of memory");
        return NULL;
    }
    for (i = 0; i < sarr->len; i++) {
        ptr->items[i] = util_strdup_s(sarr->items[i]);
        ptr->len += 1;
    }
 
    return ptr;
}

bool util_string_array_contain(const string_array *sarr, const char *elem)
{
    size_t i;

    if (elem == NULL || sarr == NULL) {
        return false;
    }

    for (i = 0; i < sarr->len; i++) {
        if (strcmp(sarr->items[i], elem) == 0) {
            return true;
        }
    }

    return false;
}

void util_free_string_array(string_array *ptr)
{
    size_t i;

    if (ptr == NULL) {
        return;
    }

    for (i = 0; i < ptr->len; i++) {
        free(ptr->items[i]);
        ptr->items[i] = NULL;
    }
    free(ptr->items);
    ptr->items = NULL;
    ptr->len = 0;
    ptr->cap = 0;

    free(ptr);
}

string_array *util_string_array_new(size_t len)
{
    string_array *ptr = NULL;

    if (len == 0) {
        return NULL;
    }

    ptr = (string_array *)util_common_calloc_s(sizeof(string_array));
    if (ptr == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ptr->items = (char **)util_smart_calloc_s(sizeof(char *), len);
    if (ptr->items == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }

    ptr->len = 0;
    ptr->cap = len;

    return ptr;

err_out:
    util_free_string_array(ptr);
    return NULL;
}

int util_common_array_append_pointer(void ***array, void *element)
{
    size_t len = 0;
    void **p = NULL;
    void **new_array = NULL;

    if (array == NULL || element == NULL) {
        return -1;
    }

    for (p = *array; p != NULL && *p != NULL; p++) {
        len++;
    }

    if (len > SIZE_MAX - 2) {
        ERROR("Out of range");
        return -1;
    }

    new_array = util_smart_calloc_s(sizeof(void *), (len + 2));
    if (new_array == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (*array != NULL) {
        (void)memcpy(new_array, *array, len * sizeof(void *));
        UTIL_FREE_AND_SET_NULL(*array);
    }

    new_array[len] = element;
    *array = new_array;

    return 0;
}

void *util_clone_ptr(void *item)
{
    return item;
}

common_array *util_common_array_new(size_t len, free_common_array_item_cb free_item_cb,
                                    clone_common_array_item_cb clone_item_cb)
{
    common_array *ptr = NULL;

    if (len == 0 || free_item_cb == NULL || clone_item_cb == NULL) {
        return NULL;
    }

    ptr = (common_array *)util_common_calloc_s(sizeof(common_array));
    if (ptr == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ptr->items = (void **)util_smart_calloc_s(sizeof(void *), len);
    if (ptr->items == NULL) {
        ERROR("Out of memory");
        free(ptr);
        return NULL;
    }

    ptr->len = 0;
    ptr->cap = len;
    ptr->free_item_cb = free_item_cb;
    ptr->clone_item_cb = clone_item_cb;

    return ptr;
}

void util_free_common_array(common_array *ptr)
{
    size_t i;

    if (ptr == NULL || ptr->free_item_cb == NULL) {
        return;
    }

    for (i = 0; i < ptr->len; i++) {
        ptr->free_item_cb(ptr->items[i]);
        ptr->items[i] = NULL;
    }
    free(ptr->items);
    ptr->items = NULL;
    ptr->len = 0;
    ptr->cap = 0;
    ptr->free_item_cb = NULL;
    ptr->clone_item_cb = NULL;

    free(ptr);
}

static bool do_expand_common_array(common_array *array)
{
    size_t new_size = get_array_scale_size(array->cap);
    void **new_items = NULL;

    // array capability sure less than MAX_MEMORY_SIZE
    // so we need to check Overflow:
    if (new_size == array->cap) {
        ERROR("Too large common array, overflow memory");
        return false;
    }

    // new_size * sizeof(*new_items) and list->len * sizeof(*list->items)
    if (util_mem_realloc((void **)&new_items, new_size * sizeof(void *), (void *)array->items,
                         array->len * sizeof(void *)) != 0) {
        ERROR("Out of memory");
        return false;
    }
    array->items = new_items;
    array->cap = new_size;

    return true;
}

int util_append_common_array(common_array *arr, void *val)
{
    if (arr == NULL || arr->clone_item_cb == NULL) {
        ERROR("Invalid common array");
        return -1;
    }

    if (val == NULL) {
        DEBUG("Empty new item, just ignore it");
        return 0;
    }

    if (arr->len < arr->cap) {
        goto out;
    }

    // expand common array
    if (!do_expand_common_array(arr)) {
        return -1;
    }

out:
    arr->items[arr->len] = arr->clone_item_cb(val);
    arr->len += 1;
    return 0;
}

int util_merge_common_array(common_array *dest_arr, common_array *src_arr)
{
    size_t i;

    if (dest_arr == NULL || dest_arr->clone_item_cb == NULL ||
        src_arr == NULL || src_arr->clone_item_cb == NULL) {
        ERROR("Invalid common array");
        return -1;
    }

    for (i = 0; i < src_arr->len; i++) {
        if (util_append_common_array(dest_arr, src_arr->items[i]) != 0) {
            ERROR("Failed to append element");
            return -1;
        }
    }
    return 0;
}
