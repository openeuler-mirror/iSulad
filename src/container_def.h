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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container definition
 ******************************************************************************/
#ifndef __CONTAINER_DEF_H_
#define __CONTAINER_DEF_H_

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CONTAINER_STATUS_UNKNOWN = 0,
    CONTAINER_STATUS_CREATED = 1,
    CONTAINER_STATUS_STARTING = 2,
    CONTAINER_STATUS_RUNNING = 3,
    CONTAINER_STATUS_STOPPED = 4,
    CONTAINER_STATUS_PAUSED = 5,
    CONTAINER_STATUS_RESTARTING = 6,
    CONTAINER_STATUS_MAX_STATE = 7
} Container_Status;

typedef enum {
    HEALTH_SERVING_STATUS_UNKNOWN = 0,
    HEALTH_SERVING_STATUS_SERVING = 1,
    HEALTH_SERVING_STATUS_NOT_SERVING = 2,
    HEALTH_SERVING_STATUS_MAX = 3
} Health_Serving_Status;

typedef enum { WAIT_CONDITION_STOPPED = 0, WAIT_CONDITION_REMOVED = 1 } wait_condition_t;

#ifdef __cplusplus
}
#endif

#endif
