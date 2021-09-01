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
 * Author: maoweiyong
 * Create: 2018-11-08
 * Description: provide common service definition
 ******************************************************************************/

#include "service_common.h"

#include <stddef.h>

#include "daemon_arguments.h"
#ifdef GRPC_CONNECTOR
#include "grpc_service.h"
#ifdef ENABLE_METRICS
#include "metrics_service.h"
#endif
#else
#include "rest_service.h"
#include "isula_libutils/log.h"
#endif

/* server common init */
int server_common_init(const struct service_arguments *args, daemon_shutdown_cb_t shutdown_cb)
{
    if (args == NULL || args->hosts == NULL) {
        return -1;
    }

#ifdef GRPC_CONNECTOR
#ifdef ENABLE_METRICS
    metrics_service_init(args->json_confs->metrics_port);
#endif
    return grpc_server_init(args);
#else
    if (args->hosts_len > 1) {
        ERROR("Rest server dest not support multiple hosts");
        return -1;
    }
    return rest_server_init(args->hosts[0], shutdown_cb);
#endif
}

/* server common start */
void server_common_start(void)
{
#ifdef GRPC_CONNECTOR
    grpc_server_wait();
#else
    rest_server_wait();
#endif
}

/* server common shutdown */
void server_common_shutdown(void)
{
#ifdef GRPC_CONNECTOR
    grpc_server_shutdown();
#ifdef ENABLE_METRICS
    metrics_service_shutdown();
#endif
#else
    rest_server_shutdown();
#endif
}

