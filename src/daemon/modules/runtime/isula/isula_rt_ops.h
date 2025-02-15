/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: jingrui
 * Create: 2020-1-20
 * Description: runtime ops
 ******************************************************************************/

#ifndef DAEMON_MODULES_RUNTIME_ISULA_ISULA_RT_OPS_H
#define DAEMON_MODULES_RUNTIME_ISULA_ISULA_RT_OPS_H /* ISULA_RT_OPS_H */

#include <stdbool.h>

#include "runtime_api.h"
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

bool rt_isula_detect(const char *runtime);
int rt_isula_create(const char *name, const char *runtime, const rt_create_params_t *params);
int rt_isula_start(const char *name, const char *runtime, const rt_start_params_t *params, pid_ppid_info_t *pid_info);
int rt_isula_restart(const char *name, const char *runtime, const rt_restart_params_t *params);
int rt_isula_clean_resource(const char *name, const char *runtime, const rt_clean_params_t *params);
int rt_isula_rm(const char *name, const char *runtime, const rt_rm_params_t *params);
int rt_isula_exec(const char *id, const char *runtime, const rt_exec_params_t *params, int *exit_code);

int rt_isula_status(const char *name, const char *runtime, const rt_status_params_t *params,
                    struct runtime_container_status_info *status);
int rt_isula_attach(const char *id, const char *runtime, const rt_attach_params_t *params);
int rt_isula_update(const char *id, const char *runtime, const rt_update_params_t *params);
int rt_isula_pause(const char *id, const char *runtime, const rt_pause_params_t *params);
int rt_isula_resume(const char *id, const char *runtime, const rt_resume_params_t *params);
int rt_isula_listpids(const char *id, const char *runtime, const rt_listpids_params_t *params,
                      rt_listpids_out_t *out);
int rt_isula_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                             struct runtime_container_resources_stats_info *rs_stats);
int rt_isula_resize(const char *id, const char *runtime, const rt_resize_params_t *params);
int rt_isula_exec_resize(const char *id, const char *runtime, const rt_exec_resize_params_t *params);
int rt_isula_kill(const char *id, const char *runtime, const rt_kill_params_t *params);
int rt_isula_rebuild_config(const char *name, const char *runtime, const rt_rebuild_config_params_t *params);

int rt_isula_read_pid_ppid_info(const char *name, const char *runtime, const rt_read_pid_ppid_info_params_t *params,
                                pid_ppid_info_t *pid_info);
int rt_isula_detect_process(const char *name, const char *runtime, const rt_detect_process_params_t *params);
#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_RUNTIME_ISULA_ISULA_RT_OPS_H
