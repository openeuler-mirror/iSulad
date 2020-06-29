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
 * Description: provide container buffer functions
 ******************************************************************************/
#define _GNU_SOURCE
#include "buffer.h"

#include <string.h>
#include "isula_libutils/log.h"
#include "utils.h"

/* buffer alloc */
Buffer *buffer_alloc(size_t initial_size)
{
    Buffer *buf = NULL;
    char *tmp = NULL;

    if (initial_size == 0) {
        return NULL;
    }

    buf = util_common_calloc_s(sizeof(Buffer));
    if (buf == NULL) {
        return NULL;
    }

    if (initial_size > SIZE_MAX / sizeof(char)) {
        free(buf);
        return NULL;
    }
    tmp = calloc(1, initial_size * sizeof(char));
    if (tmp == NULL) {
        free(buf);
        return NULL;
    }

    buf->contents = tmp;
    buf->bytes_used = 0;
    buf->total_size = initial_size;

    return buf;
}

/* buffer strlen */
size_t buffer_strlen(const Buffer *buf)
{
    return buf == NULL ? 0 : buf->bytes_used;
}

/* buffer free */
void buffer_free(Buffer *buf)
{
    if (buf == NULL) {
        return;
    }
    free(buf->contents);
    buf->contents = NULL;
    free(buf);
}

/* buffer empty */
void buffer_empty(Buffer *buf)
{
    if (buf == NULL) {
        return;
    }
    (void)memset(buf->contents, 0, buf->total_size);

    buf->bytes_used = 0;
}

/* buffer grow */
int buffer_grow(Buffer *buffer, size_t min_size)
{
    size_t factor = 0;
    size_t new_size = 0;
    char *tmp = NULL;

    if (buffer == NULL) {
        return -1;
    }

    factor = buffer->total_size;
    if (factor < min_size) {
        factor = min_size;
    }
    if (factor > SIZE_MAX / 2) {
        return -1;
    }
    new_size = factor * 2;
    if (new_size == 0) {
        return -1;
    }

    tmp = util_common_calloc_s(new_size);
    if (tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    (void)memcpy(tmp, buffer->contents, buffer->total_size);

    (void)memset(buffer->contents, 0, buffer->total_size);

    free(buffer->contents);
    buffer->contents = tmp;
    buffer->total_size = new_size;

    return 0;
}

/* buffer append */
int buffer_append(Buffer *buf, const char *append, size_t len)
{
    size_t desired_length = 0;
    size_t i = 0;
    size_t bytes_copy = 0;

    if (buf == NULL) {
        return -1;
    }

    desired_length = len + 1;
    if ((buf->total_size - buf->bytes_used) < desired_length) {
        int status = buffer_grow(buf, desired_length);
        if (status != 0) {
            return -1;
        }
    }

    for (i = 0; i < len; i++) {
        if (append[i] == '\0') {
            break;
        }

        size_t pos = buf->bytes_used + i;
        *(buf->contents + pos) = append[i];

        bytes_copy++;
    }

    buf->bytes_used += bytes_copy;
    /* string end */
    *(buf->contents + buf->bytes_used) = '\0';

    return 0;
}

