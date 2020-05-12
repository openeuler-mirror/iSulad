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
 * Description: provide container function definition
 ******************************************************************************/
#include "container.h"
#include "storage_container.h"
#include "constants.h"
#include "util_atomic.h"
#include "utils.h"
#include "log.h"

static cntr_t *create_empty_cntr()
{
    cntr_t *result = NULL;

    result = (cntr_t *)util_smart_calloc_s(sizeof(cntr_t), 1);
    if (result == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    atomic_int_set(&result->refcnt, 1);

    return result;

err_out:
    free_container_t(result);
    return NULL;
}

cntr_t *new_container(storage_container *scntr)
{
    cntr_t *c = NULL;

    if (scntr == NULL) {
        ERROR("Empty storage cntr");
        return NULL;
    }

    c = create_empty_cntr();
    if (c == NULL) {
        return NULL;
    }

    c->scontainer = scntr;

    return c;

}

void container_ref_inc(cntr_t *c)
{
    if (c == NULL) {
        return;
    }
    atomic_int_inc(&c->refcnt);
}

void container_ref_dec(cntr_t *c)
{
    bool is_zero = false;

    if (c == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&c->refcnt);
    if (!is_zero) {
        return;
    }

    free_container_t(c);
}

void free_container_t(cntr_t *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_storage_container(ptr->scontainer);
    ptr->scontainer = NULL;

    free(ptr);
}

