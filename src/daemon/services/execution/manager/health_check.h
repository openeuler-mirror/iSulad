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
#include "isula_libutils/container_config_v2.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_OUTPUT_LEN 4096
#define DEFAULT_PROBE_INTERVAL (30 * Time_Second)
#define DEFAULT_PROBE_TIMEOUT (30 * Time_Second)
#define DEFAULT_START_PERIOD (0 * Time_Second)
#define DEFAULT_PROBE_RETRIES 3
#define MAX_LOG_ENTRIES 5
#define EXIT_STATUS_HEALTHY 0

#define NO_HEALTH_CHECK "none"
#define HEALTH_STARTING "starting"
#define HEALTHY "healthy"
#define UNHEALTHY "unhealthy"

typedef enum { CMD, CMD_SHELL, HEALTH_NONE, HEALTH_UNKNOWN } health_probe_t;

typedef enum { MONITOR_IDLE = 0, MONITOR_INTERVAL = 1, MONITOR_STOP = 2 } health_check_monitor_status_t;

typedef struct health_check_manager {
    pthread_mutex_t mutex;
    bool init_mutex;
    health_check_monitor_status_t monitor_status;
} health_check_manager_t;

void init_health_monitor(const char *id);
void stop_health_checks(const char *container_id);
void update_health_monitor(const char *container_id);
void health_check_manager_free(health_check_manager_t *health_check);
int64_t timeout_with_default(int64_t configured_value, int64_t default_value);

#ifdef __cplusplus
}
#endif

#endif /* __ISULAD_HEALTH_CHECK_H_ */
