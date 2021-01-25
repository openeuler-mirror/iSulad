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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container update functions
 ******************************************************************************/
#include "update.h"

#include <stdio.h>
#include <stdlib.h>

#include "client_arguments.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "connect.h"

#include "isula_host_spec.h"

const char g_cmd_update_desc[] = "Update configuration of one or more containers";
const char g_cmd_update_usage[] = "update [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_update_args = {
    .restart = NULL,
};

static isula_host_config_t *pack_update_request(const struct client_arguments *args)
{
    isula_host_config_t *host_config = NULL;

    host_config = util_common_calloc_s(sizeof(isula_host_config_t));
    if (host_config == NULL) {
        COMMAND_ERROR("Memeory out");
        goto error_out;
    }
    host_config->restart_policy = util_strdup_s(args->restart);

    host_config->cr = util_common_calloc_s(sizeof(container_cgroup_resources_t));
    if (host_config->cr == NULL) {
        COMMAND_ERROR("Memeory out");
        goto error_out;
    }

    host_config->cr->blkio_weight = args->cr.blkio_weight;

    host_config->cr->nano_cpus = args->cr.nano_cpus;

    host_config->cr->cpu_shares = args->cr.cpu_shares;

    host_config->cr->cpu_period = args->cr.cpu_period;

    host_config->cr->cpu_quota = args->cr.cpu_quota;

    host_config->cr->cpu_realtime_period = args->cr.cpu_rt_period;

    host_config->cr->cpu_realtime_runtime = args->cr.cpu_rt_runtime;

    host_config->cr->cpuset_cpus = util_strdup_s(args->cr.cpuset_cpus);

    host_config->cr->cpuset_mems = util_strdup_s(args->cr.cpuset_mems);

    host_config->cr->memory = args->cr.memory_limit;

    host_config->cr->memory_swap = args->cr.memory_swap;

    host_config->cr->memory_reservation = args->cr.memory_reservation;

    host_config->cr->kernel_memory = args->cr.kernel_memory_limit;

    // make sure swappiness have default value -1 if not configed, so it
    // will not fail even if kernel does not support swappiness.
    host_config->cr->swappiness = args->cr.swappiness;

    return host_config;

error_out:
    isula_host_config_free(host_config);
    return NULL;
}

static int client_update(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    isula_host_config_t *host_spec = NULL;
    struct isula_update_request *request = NULL;
    struct isula_update_response *response = NULL;
    client_connect_config_t config = { 0 };

    request = util_common_calloc_s(sizeof(struct isula_update_request));
    if (request == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    response = util_common_calloc_s(sizeof(struct isula_update_response));
    if (response == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    request->name = util_strdup_s(args->name);

    host_spec = pack_update_request(args);
    if (host_spec == NULL) {
        ret = -1;
        goto out;
    }

    if (generate_hostconfig(host_spec, &request->host_spec_json) != 0) {
        ret = -1;
        goto out;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.update) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.update(request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

out:
    isula_host_config_free(host_spec);
    isula_update_request_free(request);
    isula_update_response_free(response);
    return ret;
}

int cmd_update_main(int argc, const char **argv)
{
    int ret = 0;
    int i = 0;
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf) UPDATE_OPTIONS(g_cmd_update_args)
        COMMON_OPTIONS(g_cmd_update_args)
    };

    if (client_arguments_init(&g_cmd_update_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        exit(ECOMMON);
    }
    g_cmd_update_args.progname = argv[0];
    isula_libutils_default_log_config(argv[0], &lconf);
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_update_desc,
                 g_cmd_update_usage);
    if (command_parse_args(&cmd, &g_cmd_update_args.argc, &g_cmd_update_args.argv) ||
        update_checker(&g_cmd_update_args)) {
        exit(EINVALIDARGS);
    }
    if (argc <= 3) {
        COMMAND_ERROR("You must provide one or more udpate flags when using this command\n");
        exit(ECOMMON);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Update: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_update_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to update.");
        exit(ECOMMON);
    }

    for (i = 0; i < g_cmd_update_args.argc; i++) {
        g_cmd_update_args.name = g_cmd_update_args.argv[i];
        if (client_update(&g_cmd_update_args)) {
            ERROR("Update container \"%s\" failed\n", g_cmd_update_args.name);
            ret = ECOMMON;
            continue;
        }
        printf("%s\n", g_cmd_update_args.name);
    }

    return ret;
}

int update_checker(const struct client_arguments *args)
{
    int ret = 0;

    if (args->argc == 0) {
        COMMAND_ERROR("Update requires at least 1 container names");
        return EINVALIDARGS;
    }

    return ret;
}
