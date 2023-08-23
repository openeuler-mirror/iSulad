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
#include <stdint.h>

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

