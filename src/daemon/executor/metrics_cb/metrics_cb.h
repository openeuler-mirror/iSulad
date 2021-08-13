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
 * Description: provide metric callback function definition
 ******************************************************************************/
#ifndef DAEMON_EXECUTOR_METRICS_CB_METRICS_CB_H
#define DAEMON_EXECUTOR_METRICS_CB_METRICS_CB_H

#include "callback.h"

#ifdef __cplusplus
extern "C" {
#endif

void metrics_callback_init(service_metrics_callback_t *cb);

#ifdef __cplusplus
}
#endif

#endif