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
 * Description: provide container events functions
 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "error.h"
#include "events.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "connect.h"
#include "libisula.h"
#include "utils.h"
#include "utils_timestamp.h"

const char g_cmd_events_desc[] = "Get real time events from the server";
const char g_cmd_events_usage[] = "events [command options]";

struct client_arguments g_cmd_events_args = {
    .since = NULL,
    .until = NULL,
};

static size_t calacute_annotations_msg_len(const container_events_format_t *event)
{
    size_t annos_msg_len = 0;
    size_t i;

    for (i = 0; i < event->annotations_len; i++) {
        annos_msg_len += strlen(event->annotations[i]);
    }
    annos_msg_len += event->annotations_len * 2;

    return annos_msg_len;
}

static size_t calacute_event_msg_len(const container_events_format_t *event, const char *timebuffer)
{
    size_t msg_len = 0;
    // format : timestamp (container|image opt) id (annotaions)
    msg_len += strlen(timebuffer) + 1 + strlen(event->opt) + 1 + strlen(event->id) + 1;
    msg_len += calacute_annotations_msg_len(event);
    msg_len += 1; // '\0'

    return msg_len;
}

static int generate_annotations_msg(const container_events_format_t *event, char **anno_msg)
{
    size_t i;
    size_t anno_msg_len = calacute_annotations_msg_len(event) + 1;

    if (anno_msg_len == 1) {
        return 0;
    }

    *anno_msg = (char *)util_common_calloc_s(anno_msg_len);
    if (*anno_msg == NULL) {
        ERROR("Event: Out of memory");
        return -1;
    }

    (void)strcat(*anno_msg, "(");
    for (i = 0; i < event->annotations_len; i++) {
        (void)strcat(*anno_msg, event->annotations[i]);
        if (i != event->annotations_len - 1) {
            (void)strcat(*anno_msg, ", ");
        }
    }
    (void)strcat(*anno_msg, ")");
    (*anno_msg)[anno_msg_len - 1] = '\0';

    return 0;
}

static char *generate_event_msg(const container_events_format_t *event, const char *timebuffer, size_t len)
{
    int nret = 0;
    char *anno_msg = NULL;
    char *msg = NULL;

    if (generate_annotations_msg(event, &anno_msg) != 0) {
        ERROR("Event: Failed to generate annotations msg");
        return NULL;
    }

    msg = (char *)util_common_calloc_s(len);
    if (msg == NULL) {
        ERROR("Event: Out of memory");
        goto err_out;
    }
    if (anno_msg != NULL) {
        nret = snprintf(msg, len, "%s %s %s %s", timebuffer, event->opt, event->id, anno_msg);
    } else {
        nret = snprintf(msg, len, "%s %s %s", timebuffer, event->opt, event->id);
    }
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Event: compose event massage failed");
        goto err_out;
    }
    msg[len - 1] = '\0';

    free(anno_msg);
    return msg;

err_out:
    free(anno_msg);
    free(msg);
    return NULL;
}

static void print_events_callback(const container_events_format_t *event)
{
    char timebuffer[512] = { 0 };
    char *msg = NULL;
    size_t msg_len = 0;

    if (event == NULL) {
        return;
    }

    if (!get_time_buffer(&(event->timestamp), timebuffer, sizeof(timebuffer))) {
        (void)strcpy(timebuffer, "-");
    }

    msg_len = calacute_event_msg_len(event, timebuffer);

    msg = generate_event_msg(event, timebuffer, msg_len);
    if (msg == NULL) {
        printf("generate event message failed\n");
        return;
    }

    printf("%s\n", msg);

    free(msg);
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
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;

    if (client_arguments_init(&g_cmd_events_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_events_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf) EVENTS_OPTIONS(g_cmd_events_args)
        COMMON_OPTIONS(g_cmd_events_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_events_desc,
                 g_cmd_events_usage);
    if (command_parse_args(&cmd, &g_cmd_events_args.argc, &g_cmd_events_args.argv)) {
        exit(EINVALIDARGS);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
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
