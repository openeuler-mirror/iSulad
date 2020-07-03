/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2019-11-22
 * Description: provide container list callback function definition
 *******************************************************************************/

#ifndef __RUNTIME_LCR_OPS_INTERFACE_H_
#define __RUNTIME_LCR_OPS_INTERFACE_H_

#include "runtime_api.h"

#ifdef __cplusplus
extern "C" {
#endif

bool rt_lcr_detect(const char *runtime);
int rt_lcr_create(const char *name, const char *runtime, const rt_create_params_t *params);
int rt_lcr_start(const char *name, const char *runtime, const rt_start_params_t *params, pid_ppid_info_t *pid_info);
int rt_lcr_restart(const char *name, const char *runtime, const rt_restart_params_t *params);
int rt_lcr_clean_resource(const char *name, const char *runtime, const rt_clean_params_t *params);
int rt_lcr_rm(const char *name, const char *runtime, const rt_rm_params_t *params);
int rt_lcr_status(const char *name, const char *runtime, const rt_status_params_t *params,
                  struct runtime_container_status_info *status);
int rt_lcr_exec(const char *id, const char *runtime, const rt_exec_params_t *params, int *exit_code);
int rt_lcr_pause(const char *name, const char *runtime, const rt_pause_params_t *params);
int rt_lcr_resume(const char *name, const char *runtime, const rt_resume_params_t *params);

int rt_lcr_attach(const char *name, const char *runtime, const rt_attach_params_t *params);

int rt_lcr_update(const char *id, const char *runtime, const rt_update_params_t *params);

int rt_lcr_listpids(const char *name, const char *runtime, const rt_listpids_params_t *params, rt_listpids_out_t *out);
int rt_lcr_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                           struct runtime_container_resources_stats_info *rs_stats);
int rt_lcr_resize(const char *id, const char *runtime, const rt_resize_params_t *params);
int rt_lcr_exec_resize(const char *id, const char *runtime, const rt_exec_resize_params_t *params);
#ifdef __cplusplus
}
#endif

#endif
