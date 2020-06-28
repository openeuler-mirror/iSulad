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
 * Description: provide container callback functions
 ******************************************************************************/
#include "callback.h"

#include "image_cb.h"
#include "execution.h"

service_executor_t g_isulad_service_executor;

/* service callback */
int service_callback_init(void)
{
    container_callback_init(&g_isulad_service_executor.container);
    image_callback_init(&g_isulad_service_executor.image);
    return 0;
}

/* get service callback */
service_executor_t *get_service_executor(void)
{
    return &g_isulad_service_executor;
}
