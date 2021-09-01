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
 * Description: provide metric service functions.
 ******************************************************************************/
#include "metrics_service.h"
#include <sys/types.h>
#include <pthread.h>

#include "utils.h"
#include "isula_libutils/log.h"
#include "callback.h"

#define METRIC_RESPONSE_OK      200
#define METRIC_RESPONSE_FAIL    401
#define METRIC_NOT_IMPL         501
#define METRIC_DEFAULT_IP       "127.0.0.1"
#define METRIC_DEFAULT_PORT     9090
#define BACK_LOG_SIZE           1024

#if (defined GRPC_CONNECTOR) && (defined ENABLE_METRICS)
typedef struct metrics_server_param {
    int32_t port;
    evbase_t *ev_base;
    evhtp_t *ev_http;
} metrics_server_param_t;

static struct metrics_server_param *g_metrics_htp_param = NULL;
#endif

void metrics_get_by_type_cb(evhtp_request_t *req, void *arg)
{
    char *metrics = NULL;
    int ret_code = METRIC_RESPONSE_OK;
    int len = 0;
    const char *req_type = NULL;
    service_executor_t *cb = NULL;

    cb = get_service_executor();
    if (cb == NULL || cb->metrics.export_metrics_by_type == NULL) {
        ret_code = METRIC_NOT_IMPL;
        goto out;
    }

    req_type = req->uri->path->full + strlen(req->uri->path->path); /* full path include request url */
    (void)cb->metrics.export_metrics_by_type(req_type, &metrics, &len);
    if (metrics == NULL || len == 0) {
        ret_code = METRIC_RESPONSE_FAIL;
        goto out;
    }

    evhtp_headers_add_header(req->headers_out,
                             evhtp_header_new("Content-Type", "text/plain; verion:0.0.4; charset=utf-8", 0, 0));
    evbuffer_add(req->buffer_out, metrics, len);
    free(metrics);
    metrics = NULL;

out:
    evhtp_send_reply(req, ret_code);
}

#if (defined GRPC_CONNECTOR) && (defined ENABLE_METRICS)
void *metrics_server_thrd(void *args)
{
    int def_port = 0;

    prctl(PR_SET_NAME, __func__);
    pthread_detach(pthread_self());

    g_metrics_htp_param->ev_base = event_base_new();
    if (g_metrics_htp_param->ev_base == NULL) {
        ERROR("failed to new event base!\n");
        goto success;
    }

    g_metrics_htp_param->ev_http = evhtp_new(g_metrics_htp_param->ev_base, NULL);
    if (g_metrics_htp_param->ev_http == NULL) {
        ERROR("failed to new ev http!\n");
        goto clean_evbase;
    }

    evhtp_set_cb(g_metrics_htp_param->ev_http, METRIC_GET_BY_TYPE, metrics_get_by_type_cb, NULL);
    evhtp_use_dynamic_threads(g_metrics_htp_param->ev_http, NULL, NULL, 0, 0, 0, NULL);

    def_port = g_metrics_htp_param->port != 0 ? g_metrics_htp_param->port : METRIC_DEFAULT_PORT;
    /* if no default port config, we will use 9090 as default metrics port */
    if (evhtp_bind_socket(g_metrics_htp_param->ev_http, METRIC_DEFAULT_IP, def_port, BACK_LOG_SIZE) < 0) {
        ERROR("evhtp_bind_socket failed");
        goto clean_evhtp;
    }

    event_base_loop(g_metrics_htp_param->ev_base, 0);

    goto success;

clean_evhtp:
    evhtp_free(g_metrics_htp_param->ev_http);
    g_metrics_htp_param->ev_http = NULL;
clean_evbase:
    event_base_free(g_metrics_htp_param->ev_base);
    g_metrics_htp_param->ev_base = NULL;
success:
    return NULL;
}

int metrics_service_init(int port)
{
    pthread_t metric_thrd_t = -1;
    if (g_metrics_htp_param != NULL) {
        return -1;
    }

    g_metrics_htp_param = (metrics_server_param_t *)util_common_calloc_s(sizeof(metrics_server_param_t));
    if (g_metrics_htp_param == NULL) {
        ERROR("out of memory!");
        return -1;
    }

    g_metrics_htp_param->port = port;

    /* When gRPC is used by default server, the evhtp can't rcv event(Multiplexing of network),
       therefore, an additional thread is used to create the service */
    if (pthread_create(&metric_thrd_t, NULL, metrics_server_thrd, NULL) != 0) {
        ERROR("pthread create failed");
        free(g_metrics_htp_param);
        g_metrics_htp_param = NULL;
        return -1;
    }

    return 0;
}

void metrics_service_shutdown()
{
    if (g_metrics_htp_param == NULL) {
        return;
    }

    if (g_metrics_htp_param->ev_http != NULL) {
        evhtp_unbind_socket(g_metrics_htp_param->ev_http);
        evhtp_free(g_metrics_htp_param->ev_http);
        g_metrics_htp_param->ev_http = NULL;
    }

    if (g_metrics_htp_param->ev_base != NULL) {
        /* Abort the active event_base_loop() immediately */
        event_base_loopbreak(g_metrics_htp_param->ev_base);
        event_base_free(g_metrics_htp_param->ev_base);
        g_metrics_htp_param->ev_base = NULL;
    }

    free(g_metrics_htp_param);
    g_metrics_htp_param = NULL;

    DEBUG("metrics service shutdown ok.\n");
}
#endif
