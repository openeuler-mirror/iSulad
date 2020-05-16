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
 * Author: WuJing
 * Create: 2020-05-12
 * Description: provide container function definition
 ******************************************************************************/
#include "rootfs.h"
#include "storage_rootfs.h"
#include "constants.h"
#include "util_atomic.h"
#include "utils.h"
#include "log.h"

static cntrootfs_t *create_empty_cntr()
{
    cntrootfs_t *result = NULL;

    result = (cntrootfs_t *)util_smart_calloc_s(sizeof(cntrootfs_t), 1);
    if (result == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    atomic_int_set(&result->refcnt, 1);

    return result;

err_out:
    free_rootfs_t(result);
    return NULL;
}

cntrootfs_t *new_rootfs(storage_rootfs *scntr)
{
    cntrootfs_t *c = NULL;

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

void rootfs_ref_inc(cntrootfs_t *c)
{
    if (c == NULL) {
        return;
    }
    atomic_int_inc(&c->refcnt);
}

void rootfs_ref_dec(cntrootfs_t *c)
{
    bool is_zero = false;

    if (c == NULL) {
        return;
    }

    is_zero = atomic_int_dec_test(&c->refcnt);
    if (!is_zero) {
        return;
    }

    free_rootfs_t(c);
}

void free_rootfs_t(cntrootfs_t *ptr)
{
    if (ptr == NULL) {
        return;
    }
    free_storage_rootfs(ptr->scontainer);
    ptr->scontainer = NULL;

    free(ptr);
}

