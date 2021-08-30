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

#include <stdlib.h>

#include "image_cb.h"
#include "execution.h"
#include "volume_cb.h"
#ifdef ENABLE_METRICS
#include "metrics_cb.h"
#endif

service_executor_t g_isulad_service_executor;

/* isulad events request free */
void isulad_events_request_free(struct isulad_events_request *request)
{
    if (request == NULL) {
        return;
    }
    if (request->id != NULL) {
        free(request->id);
        request->id = NULL;
    }
    free(request);
}

void isulad_copy_from_container_request_free(struct isulad_copy_from_container_request *request)
{
    if (request == NULL) {
        return;
    }
    free(request->id);
    request->id = NULL;
    free(request->runtime);
    request->runtime = NULL;
    free(request->srcpath);
    request->srcpath = NULL;

    free(request);
}

void isulad_copy_from_container_response_free(struct isulad_copy_from_container_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->data);
    response->data = NULL;
    response->data_len = 0;

    free(response);
}

/* isulad container rename request free */
void isulad_container_rename_request_free(struct isulad_container_rename_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->old_name);
    request->old_name = NULL;
    free(request->new_name);
    request->new_name = NULL;

    free(request);
}

/* isulad container rename response free */
void isulad_container_rename_response_free(struct isulad_container_rename_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->id);
    response->id = NULL;
    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

/* isulad container rename request free */
void isulad_container_resize_request_free(struct isulad_container_resize_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;

    free(request->suffix);
    request->suffix = NULL;

    free(request);
}

/* isulad container rename response free */
void isulad_container_resize_response_free(struct isulad_container_resize_response *response)
{
    if (response == NULL) {
        return;
    }

    free(response->id);
    response->id = NULL;
    free(response->errmsg);
    response->errmsg = NULL;

    free(response);
}

void isulad_logs_request_free(struct isulad_logs_request *request)
{
    if (request == NULL) {
        return;
    }

    free(request->id);
    request->id = NULL;
    free(request->runtime);
    request->runtime = NULL;
    free(request->since);
    request->since = NULL;
    free(request->until);
    request->until = NULL;
    free(request);
}

void isulad_logs_response_free(struct isulad_logs_response *response)
{
    if (response == NULL) {
        return;
    }
    free(response->errmsg);
    response->errmsg = NULL;
    free(response);
}

/* service callback */
int service_callback_init(void)
{
    container_callback_init(&g_isulad_service_executor.container);
    image_callback_init(&g_isulad_service_executor.image);
    volume_callback_init(&g_isulad_service_executor.volume);
#ifdef ENABLE_METRICS
    metrics_callback_init(&g_isulad_service_executor.metrics);
#endif
    return 0;
}

/* get service callback */
service_executor_t *get_service_executor(void)
{
    return &g_isulad_service_executor;
}
