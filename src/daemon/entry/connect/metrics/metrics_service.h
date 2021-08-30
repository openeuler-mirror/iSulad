/******************************************************************************
 * Copyright (c) KylinSoft  Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.

 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xiapin
 * Create: 2021-08-17
 * Description: provide metric service definition
 ******************************************************************************/
#ifndef DAEMON_ENTRY_CONNECT_METRICS_METRICS_SERVICE_H
#define DAEMON_ENTRY_CONNECT_METRICS_METRICS_SERVICE_H

#include <evhtp.h>

#ifdef __cplusplus
extern "C" {
#endif

#define METRIC_GET_BY_TYPE      "/metrics/type"

void metrics_get_by_type_cb(evhtp_request_t *req, void *arg);

int metrics_service_init(int port);

void metrics_service_shutdown();

#ifdef __cplusplus
}
#endif

#endif