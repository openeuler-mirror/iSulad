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
 * Author: WuJing
 * Create: 2020-05-12
 * Description: provide containers function definition
 ******************************************************************************/
#ifndef __OCI_STORAGE_CONTAINER_H
#define __OCI_STORAGE_CONTAINER_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include "storage_container.h"
#include "log.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct _cntr_t_ {
    storage_container *scontainer;
    uint64_t refcnt;
} cntr_t;

cntr_t *new_container(storage_container *scntr);
void container_ref_inc(cntr_t *cntr);
void container_ref_dec(cntr_t *cntr);
void free_container_t(cntr_t *ptr);

#ifdef __cplusplus
}
#endif

#endif // __OCI_STORAGE_CONTAINER_H
