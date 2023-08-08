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
 * Description: provide cleanup definition
 *********************************************************************************/
#ifndef DAEMON_MODULES_CONTAINER_LEFTOVER_CLEANUP_CLEANERS_H
#define DAEMON_MODULES_CONTAINER_LEFTOVER_CLEANUP_CLEANERS_H

#include <stdlib.h>

#include "linked_list.h"
#include "isula_libutils/log.h"
#include "clean_context.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef int clean_func_t(struct clean_ctx *ctx);

struct clean_node {
    const char *desc;
    clean_func_t *cleaner;
    int error_code;
};

struct cleaners {
    int count;
    int done_clean;
    struct linked_list cleaner_list;
};

struct cleaners *cleaners_init();

void destroy_cleaners(struct cleaners *clns);

void cleaners_do_clean(struct cleaners *clns, struct clean_ctx *ctx);

void do_isulad_tmpdir_cleaner(void);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif