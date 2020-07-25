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
 * Author: maoweiyong
 * Create: 2017-11-22
 * Description: provide monitord definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_EVENTS_MONITORD_H
#define DAEMON_MODULES_EVENTS_MONITORD_H
#include <pthread.h>
#include <semaphore.h>
#include <limits.h>

#include "utils.h"

struct monitord_sync_data {
    sem_t *monitord_sem;
    int *exit_code;
};

int new_monitord(struct monitord_sync_data *msync);

#endif
