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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container gc definition
 ******************************************************************************/
#ifndef __ISULAD_CONTAINER_GC_H__
#define __ISULAD_CONTAINER_GC_H__

#include <pthread.h>

#include "libisulad.h"
#include "linked_list.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef struct _containers_gc_t_ {
    pthread_mutex_t mutex;
    struct linked_list containers_list;
} containers_gc_t;

int new_gchandler();

int gc_add_container(const char *id, const char *runtime, const container_pid_t *pid_info);

int gc_restore();

int start_gchandler();

bool gc_is_gc_progress(const char *id);


#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_CONTAINER_GC_H__ */

