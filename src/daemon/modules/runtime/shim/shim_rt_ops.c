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
 * Author: gaohuatao
 * Create: 2020-1-20
 * Description: runtime ops
 ******************************************************************************/

#define _GNU_SOURCE


#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <limits.h>
#include "shim_rt_ops.h"
#include "isula_libutils/log.h"
#include "error.h"
#include "err_msg.h"
#include "engine.h"
#include "constants.h"
#include "isula_libutils/shim_client_process_state.h"
#include "utils_string.h"
#include "shim_v2.h"

bool rt_shim_detect(const char *runtime)
{
    if (runtime != NULL && (convert_v2_runtime(runtime, NULL) == 0)) {
        return true;
    }
    return false;
}

int rt_shim_create(const char *name, const char *runtime, const rt_create_params_t *params)
{
    return 0;
}

int rt_shim_start(const char *name, const char *runtime, const rt_start_params_t *params, pid_ppid_info_t *pid_info)
{
    return 0;
}

int rt_shim_restart(const char *name, const char *runtime, const rt_restart_params_t *params)
{
    return 0;
}

int rt_shim_clean_resource(const char *name, const char *runtime, const rt_clean_params_t *params)
{
    return 0;
}

int rt_shim_rm(const char *name, const char *runtime, const rt_rm_params_t *params)
{
    return 0;
}

int rt_shim_exec(const char *id, const char *runtime, const rt_exec_params_t *params, int *exit_code)
{
    return 0;
}


int rt_shim_status(const char *name, const char *runtime, const rt_status_params_t *params,
                   struct runtime_container_status_info *status)
{
    return 0;
}


int rt_shim_attach(const char *id, const char *runtime, const rt_attach_params_t *params)
{
    return 0;
}

int rt_shim_update(const char *id, const char *runtime, const rt_update_params_t *params)
{
    return 0;
}

int rt_shim_pause(const char *id, const char *runtime, const rt_pause_params_t *params)
{
    return 0;
}

int rt_shim_resume(const char *id, const char *runtime, const rt_resume_params_t *params)
{
    return 0;
}

int rt_shim_listpids(const char *name, const char *runtime, const rt_listpids_params_t *params,
                     rt_listpids_out_t *out)
{
    return 0;
}

int rt_shim_resources_stats(const char *name, const char *runtime, const rt_stats_params_t *params,
                            struct runtime_container_resources_stats_info *rs_stats)
{
    return 0;
}

int rt_shim_resize(const char *id, const char *runtime, const rt_resize_params_t *params)
{
    return 0;
}

int rt_shim_exec_resize(const char *id, const char *runtime, const rt_exec_resize_params_t *params)
{
    return 0;
}

int rt_shim_kill(const char *id, const char *runtime, const rt_kill_params_t *params)
{
    return 0;
}