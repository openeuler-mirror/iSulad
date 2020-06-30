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
 * Author: wujing
 * Create: 2018-11-1
 * Description: provide health check definition
 *********************************************************************************/
#ifndef __ISULAD_HEALTH_CHECK_H_
#define __ISULAD_HEALTH_CHECK_H_

#include "utils_timestamp.h"
#include "container_api.h"
#include "isula_libutils/container_config_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { CMD, CMD_SHELL, HEALTH_NONE, HEALTH_UNKNOWN } health_probe_t;

void health_check_manager_free(health_check_manager_t *health_check);

#ifdef __cplusplus
}
#endif

#endif /* __ISULAD_HEALTH_CHECK_H_ */
