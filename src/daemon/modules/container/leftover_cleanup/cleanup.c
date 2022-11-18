/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangrunze
 * Create: 2022-10-31
 * Description: provide cleanup functions
 *********************************************************************************/
#include "utils.h"
#include "cleanup.h"
#include "oci_rootfs_clean.h"

static struct cleaners *create_cleaners()
{
    struct cleaners *ret = NULL;

    ret = util_common_calloc_s(sizeof(struct cleaners));
    if (ret == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    linked_list_init(&(ret->cleaner_list));

    return ret;
}

static void destroy_cleaners(struct cleaners *clns)
{
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    struct clean_node *c_node = NULL;

    linked_list_for_each_safe(it, &(clns->cleaner_list), next) {
        c_node = (struct clean_node *)it->elem;
        linked_list_del(it);
        free(c_node);
        free(it);
        it = NULL;
    }

    free(clns);
}

static int add_clean_node(struct cleaners *clns, clean_func_t f, const char *desc)
{
    struct linked_list *new_node = NULL;
    struct clean_node *c_node = NULL;

    new_node = util_common_calloc_s(sizeof(struct linked_list));
    if (new_node == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    c_node = util_common_calloc_s(sizeof(struct clean_node));
    if (c_node == NULL) {
        ERROR("Out of memory");
        free(new_node);
        return -1;
    }
    c_node->cleaner = f;
    c_node->desc = desc;

    linked_list_add_elem(new_node, c_node);
    linked_list_add_tail(&(clns->cleaner_list), new_node);
    clns->count++;

    return 0;
}

static int default_cleaner()
{
    return 0;
}

static struct cleaners *cleaner_init()
{
    int ret = 0;
    struct cleaners *clns = create_cleaners();
    
    if (clns == NULL) {
        return NULL;
    }

    ret = add_clean_node(clns, default_cleaner, "default clean");
    if (ret != 0) {
        ERROR("add default_cleaner error");
        return clns;
    }

#ifdef ENABLE_OCI_IMAGE
    ret = add_clean_node(clns, oci_rootfs_cleaner, "clean rootfs");
    if (ret != 0) {
        ERROR("add oci_rootfs_cleaner error");
        return clns;
    }
#endif

    return clns;
}

static void do_clean(struct cleaners * clns)
{
    struct linked_list *it = NULL;
    struct linked_list *next = NULL;
    struct clean_node *c_node = NULL;

    linked_list_for_each_safe(it, &(clns->cleaner_list), next) {
        c_node = (struct clean_node *)it->elem;
        if (c_node->cleaner() != 0) {
            ERROR("failed to clean for: %s", c_node->desc);
        } else {
            DEBUG("do clean success for: %s", c_node->desc);
            clns->done_clean++;
        }
    }
}

void clean_leftover()
{
    struct cleaners *clns = cleaner_init();

    if (clns == NULL) {
        ERROR("failed to clean leftovers, because cleaner init error");
        return;
    }

    do_clean(clns);

    if (clns->count == clns->done_clean) {
        DEBUG("all clean up success");
    } else {
        ERROR("Aim to do %d clean, %d clean sucess\n", clns->count, clns->done_clean);
    }

    destroy_cleaners(clns);
}