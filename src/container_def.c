/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container definition
 ******************************************************************************/
#include <string.h>
#include <stdlib.h>

#include "container_def.h"

/* container cgroup resources free */
void container_cgroup_resources_free(container_cgroup_resources_t *cr)
{
    if (cr == NULL) {
        return;
    }
    free(cr->cpuset_cpus);
    cr->cpuset_cpus = NULL;

    free(cr->cpuset_mems);
    cr->cpuset_mems = NULL;

    free(cr);
}

void container_events_format_free(container_events_format_t *value)
{
    size_t i;

    if (value == NULL) {
        return;
    }

    free(value->opt);
    value->opt = NULL;

    free(value->id);
    value->id = NULL;

    for (i = 0; i < value->annotations_len; i++) {
        free(value->annotations[i]);
        value->annotations[i] = NULL;
    }

    free(value->annotations);
    value->annotations = NULL;

    free(value);
}