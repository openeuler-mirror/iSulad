/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container list callback function definition
 *********************************************************************************/


#ifndef DAEMON_EXECUTOR_CONTAINER_CB_EXECUTION_EXTEND_H
#define DAEMON_EXECUTOR_CONTAINER_CB_EXECUTION_EXTEND_H

#include "callback.h"

#ifdef __cplusplus
extern "C" {
#endif

void container_extend_callback_init(service_container_callback_t *cb);

#ifdef __cplusplus
}
#endif

#endif

