/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-02-22
 * Description: sandbox shim controller implementation
 ******************************************************************************/

#include <stdlib.h>
#include "shim_ctrl_ops.h"
#include "map.h"
#include "utils.h"
#include "isulad_config.h"

bool ctrl_shim_init()
{
    ERROR("Shim controller is unimplemented");
    return true;
}

bool ctrl_shim_detect(const char *sandboxer)
{
    return false;
}


int ctrl_shim_create(const char *sandboxer, const char *sandbox_id,
                     const ctrl_create_params_t *params)
{
    ERROR("Shim Sandbox controller create is unimplemented");
    return -1;
}

int ctrl_shim_start(const char *sandboxer, const char *sandbox_id)
{
    ERROR("Shim Sandbox controller start is unimplemented");
    return -1;
}

int ctrl_shim_platform(const char *sandboxer, const char *sandbox_id,
                        ctrl_platform_response_t *response)
{
    ERROR("Shim Sandbox controller platform is unimplemented");
    return -1;
}

int ctrl_shim_prepare(const char *sandboxer, const char *sandbox_id,
                      const ctrl_prepare_params_t *params,
                      ctrl_prepare_response_t *response)
{
    ERROR("Shim Sandbox controller prepare is unimplemented");
    return -1;
}

int ctrl_shim_purge(const char *sandboxer, const char *sandbox_id,
                    const ctrl_purge_params_t *params)
{
    ERROR("Shim Sandbox controller purge is unimplemented");
    return -1;
}

int ctrl_shim_update_resources(const char *sandboxer, const char *sandbox_id,
                               const ctrl_update_resources_params_t *params)
{
    ERROR("Shim Sandbox controller update-resources is unimplemented");
    return -1;
}

int ctrl_shim_stop(const char *sandboxer, const char *sandbox_id, uint32_t timeout)
{
    ERROR("Shim Sandbox controller stop is unimplemented");
    return -1;
}

int ctrl_shim_wait(const char *sandboxer, const char *sandbox_id,
                   uint32_t *exit_status, uint64_t *exited_at)
{
    ERROR("Shim Sandbox controller wait is unimplemented");
    return -1;
}

int ctrl_shim_status(const char *sandboxer, const char *sandbox_id,
                     bool verbose, ctrl_status_response_t *response)
{
    ERROR("Shim Sandbox controller status is unimplemented");
    return -1;
}

int ctrl_shim_shutdown(const char *sandboxer, const char *sandbox_id)
{
    ERROR("Shim Sandbox controller shutdown is unimplemented");
    return -1;
}
