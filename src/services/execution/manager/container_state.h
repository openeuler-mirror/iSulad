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
 * Description: provide container state definition
 ******************************************************************************/
#ifndef __ISULAD_CONTAINER_STATE_H__
#define __ISULAD_CONTAINER_STATE_H__

#include <pthread.h>

#include "libisulad.h"
#include "isula_libutils/container_config_v2.h"
#include "engine.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef struct _container_state_t_ {
    pthread_mutex_t mutex;
    container_config_v2_state *state;
} container_state_t;


container_state_t *container_state_new(void);

void container_state_free(container_state_t *state);

container_config_v2_state *state_get_info(container_state_t *s);

void container_state_lock(container_state_t *state);

void container_state_unlock(container_state_t *state);

void update_start_and_finish_time(container_state_t *s, const char *finish_at);

void state_set_starting(container_state_t *s);

void state_reset_starting(container_state_t *s);

void state_set_running(container_state_t *s, const container_pid_t *pid_info, bool initial);

void state_set_stopped(container_state_t *s, int exit_code);

void state_set_restarting(container_state_t *s, int exit_code);

void state_set_paused(container_state_t *s);
void state_reset_paused(container_state_t *s);

void state_set_dead(container_state_t *s);

// state_set_removal_in_progress sets the container state as being removed.
// It returns true if the container was already in that state
bool state_set_removal_in_progress(container_state_t *s);

void state_reset_removal_in_progress(container_state_t *s);

const char *state_to_string(Container_Status cs);

Container_Status state_judge_status(const container_config_v2_state *state);

Container_Status state_get_status(container_state_t *s);

bool is_running(container_state_t *s);

bool is_restarting(container_state_t *s);

bool is_removal_in_progress(container_state_t *s);

bool is_paused(container_state_t *s);

uint32_t state_get_exitcode(container_state_t *s);

int state_get_pid(container_state_t *s);

bool is_dead(container_state_t *s);

void container_state_set_error(container_state_t *s, const char *err);

char *state_get_started_at(container_state_t *s);

bool is_valid_state_string(const char *state);

int dup_health_check_status(defs_health **dst, const defs_health *src);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_CONTAINER_STATE_H__ */

