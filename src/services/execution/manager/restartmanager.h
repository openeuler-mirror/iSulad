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
 * Description: provide container restart manager definition
 ******************************************************************************/
#ifndef __RESTARTMANAGER_H
#define __RESTARTMANAGER_H

#include <stdint.h>
#include <pthread.h>
#include "engine.h"
#include "isula_libutils/host_config.h"

struct restart_policy {
    char *name;
    uint64_t max_retry_count;
};

typedef struct _restart_manager_t {
    pthread_mutex_t mutex;
    bool init_mutex;
    pthread_cond_t wait_cancel_con;
    bool init_wait_cancel_con;
    uint64_t refcnt;
    host_config_restart_policy *policy;
    int failure_count;
    int64_t timeout;
    bool active;
    bool canceled;
} restart_manager_t;

void restart_policy_free(host_config_restart_policy *policy);

restart_manager_t *restart_manager_new(const host_config_restart_policy *policy, int failure_count);

void restart_manager_refinc(restart_manager_t *rm);

void restart_manager_unref(restart_manager_t *rm);

void restart_manager_free(restart_manager_t *rm);

int restart_manager_set_policy(restart_manager_t *rm, const host_config_restart_policy *policy);

bool restart_manager_should_restart(const char *id, uint32_t exit_code, bool has_been_manually_stopped,
                                    int64_t exec_duration, uint64_t *timeout);

int restart_manager_cancel(restart_manager_t *rm);

int restart_manager_wait_cancel(restart_manager_t *rm, uint64_t timeout);

int container_restart_in_thread(const char *id, uint64_t timeout, int exit_code);


#endif /* __RESTARTMANAGER_H */

