/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-06-22
 * Description: provide container events handler definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_CONTAINER_CONTAINER_EVENTS_HANDLER_H
#define DAEMON_MODULES_CONTAINER_CONTAINER_EVENTS_HANDLER_H

#include <stdint.h>
#include <pthread.h>

#include "linked_list.h"
#include "container_api.h"
#include "events_format.h"

container_events_handler_t *container_events_handler_new();

void container_events_handler_free(container_events_handler_t *handler);

int container_events_handler_post_events(const struct isulad_events_format *event);

#endif // DAEMON_MODULES_CONTAINER_CONTAINER_EVENTS_HANDLER_H
