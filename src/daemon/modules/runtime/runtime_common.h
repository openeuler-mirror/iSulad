/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: liuxu
 * Create: 2024-11-28
 * Description: runtime common definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_RUNTIME_COMMON_H
#define DAEMON_MODULES_RUNTIME_COMMON_H

#include "runtime_api.h"


#ifdef __cplusplus
extern "C" {
#endif

#define SECOND_TO_NANOS 1000000000ULL

static inline bool rt_fg_exec(const rt_exec_params_t *params)
{
    return params->console_fifos[0] != NULL || params->console_fifos[1] != NULL || params->console_fifos[2] != NULL;
}


#ifdef __cplusplus
}
#endif

#endif // DAEMON_MODULES_RUNTIME_COMMON_H
