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
 * Description: provide container state definition
 ******************************************************************************/
#ifndef __ISULAD_CONTAINER_STATE_H__
#define __ISULAD_CONTAINER_STATE_H__

#include <pthread.h>

#include "container_api.h"

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

container_state_t *container_state_new(void);

void container_state_free(container_state_t *state);

void container_state_lock(container_state_t *state);

void container_state_unlock(container_state_t *state);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __ISULAD_CONTAINER_STATE_H__ */
