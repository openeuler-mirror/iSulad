/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-06-15
 * Description: provide container isulad functions
 ******************************************************************************/
#include "events_format.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>

#include "isula_libutils/log.h"
#include "utils.h"

/* events copy */
int event_copy(const struct isulad_events_format *src, struct isulad_events_format *dest)
{
    size_t i;
    if (src == NULL || dest == NULL) {
        return 0;
    }

    dest->timestamp.has_seconds = src->timestamp.has_seconds;
    dest->timestamp.seconds = src->timestamp.seconds;
    dest->timestamp.has_nanos = src->timestamp.has_nanos;
    dest->timestamp.nanos = src->timestamp.nanos;

    if (src->id != NULL) {
        free(dest->id);
        dest->id = util_strdup_s(src->id);
    }

    if (src->opt != NULL) {
        free(dest->opt);
        dest->opt = util_strdup_s(src->opt);
    }

    if (src->annotations_len != 0) {
        util_free_array_by_len(dest->annotations, dest->annotations_len);
        dest->annotations = (char **)util_common_calloc_s(src->annotations_len * sizeof(char *));
        if (dest->annotations == NULL) {
            ERROR("Out of memory");
            return -1;
        }

        for (i = 0; i < src->annotations_len; i++) {
            dest->annotations[i] = util_strdup_s(src->annotations[i]);
        }

        dest->annotations_len = src->annotations_len;
    }

    dest->has_type = src->has_type;
    dest->type = src->type;

    dest->has_pid = src->has_pid;
    dest->pid = src->pid;
    dest->has_exit_status = src->has_exit_status;
    dest->exit_status = src->exit_status;

    return 0;
}

struct isulad_events_format *dup_event(const struct isulad_events_format *event)
{
    struct isulad_events_format *out = NULL;

    if (event == NULL || event->id == NULL) {
        return NULL;
    }

    out = util_common_calloc_s(sizeof(struct isulad_events_format));
    if (out == NULL) {
        return NULL;
    }

    event_copy(event, out);

    return out;
}

void isulad_events_format_free(struct isulad_events_format *value)
{
    size_t i;

    if (value == NULL) {
        return;
    }
    free(value->id);
    value->id = NULL;

    free(value->opt);
    value->opt = NULL;

    for (i = 0; i < value->annotations_len; i++) {
        free(value->annotations[i]);
        value->annotations[i] = NULL;
    }
    free(value->annotations);
    value->annotations = NULL;

    free(value);
}
