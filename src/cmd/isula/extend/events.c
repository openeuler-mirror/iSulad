/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container events functions
 ******************************************************************************/
#include "error.h"
#include "events.h"
#include "arguments.h"
#include "log.h"
#include "isula_connect.h"

const char g_cmd_events_desc[] = "Get real time events from the server";
const char g_cmd_events_usage[] = "events [command options]";

struct client_arguments g_cmd_events_args = {
    .since = NULL,
    .until = NULL,
};

static const char * const g_strtype[] = {
    "EXIT",   "STOPPED", "STARTING", "RUNNING", "STOPPING", "ABORTING",   "FREEZING",
    "FROZEN", "THAWED",  "OOM",      "CREATE",  "START",    "EXEC_ADDED", "PAUSED1",
};

static const char *lcrsta2str(container_events_type_t sta)
{
    if (sta > EVENTS_TYPE_PAUSED1) {
        return NULL;
    }
    return g_strtype[sta];
}

static void print_events_callback(const container_events_format_t *event)
{
    char timebuffer[512] = { 0 };

    if (event == NULL) {
        return;
    }

    printf("--------------------------------------------------\n");
    printf("%-15s %s\n", "Name:", event->id);

    if (get_time_buffer(&(event->timestamp), timebuffer, sizeof(timebuffer))) {
        printf("%-15s %s\n", "Time:", timebuffer);
    } else {
        printf("%-15s %s\n", "Time:", "-");
    }

    if (event->has_type) {
        printf("%-15s %s\n", "EventType:", lcrsta2str(event->type));
    } else {
        printf("%-15s %s\n", "EventType:", "-");
    }

    if (event->has_pid) {
        printf("%-15s %u\n", "Pid:", event->pid);
    } else {
        printf("%-15s %s\n", "Pid:", "-");
    }

    if (event->has_exit_status) {
        printf("%-15s %u\n", "Exit_Status:", event->exit_status);
    } else {
        printf("%-15s %s\n", "Exit_Status:", "-");
    }
}

/*
* Create a delete request message and call RPC
*/
static int client_event(struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_events_request request = { 0 };
    struct isula_events_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_events_response));
    if (response == NULL) {
        ERROR("Event: Out of memory");
        return -1;
    }

    request.cb = print_events_callback;
    request.id = args->name;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.events) {
        ERROR("Unimplemented event op");
        ret = -1;
        goto out;
    }

    if (args->since && !get_timestamp(args->since, &request.since)) {
        COMMAND_ERROR("Failed to get since timestamp");
        ret = -1;
        goto out;
    }

    if (args->until && !get_timestamp(args->until, &request.until)) {
        COMMAND_ERROR("Failed to get until timestamp");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.events(&request, response, &config);
    if (ret != 0) {
        COMMAND_ERROR("Failed to get container events, %s",
                      response->errmsg ? response->errmsg : errno_to_error_message(response->cc));
    }

out:
    isula_events_response_free(response);
    return ret;
}

int cmd_events_main(int argc, const char **argv)
{
    struct log_config lconf = { 0 };
    command_t cmd;

    set_default_command_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_events_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_events_args.progname = argv[0];
    struct command_option options[] = {
        LOG_OPTIONS(lconf),
        EVENTS_OPTIONS(g_cmd_events_args),
        COMMON_OPTIONS(g_cmd_events_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_events_desc,
                 g_cmd_events_usage);
    if (command_parse_args(&cmd, &g_cmd_events_args.argc, &g_cmd_events_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (log_init(&lconf)) {
        COMMAND_ERROR("Events: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_events_args.socket == NULL) {
        COMMAND_ERROR("Missing --host,-H option");
        exit(EINVALIDARGS);
    }

    if (client_event(&g_cmd_events_args)) {
        if (g_cmd_events_args.name != NULL) {
            ERROR("Container \"%s\" event failed", g_cmd_events_args.name);
        } else {
            ERROR("Container events failed");
        }
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}

