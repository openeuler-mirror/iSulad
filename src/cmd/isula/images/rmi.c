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
 * Description: provide container remove functions
 ******************************************************************************/
#include "rmi.h"
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"

const char g_cmd_rmi_desc[] = "Remove one or more images";
const char g_cmd_rmi_usage[] = "rmi [OPTIONS] IMAGE [IMAGE...]";

struct client_arguments g_cmd_rmi_args = { .force = false };

/*
 * remove a image from DB
 */
static int client_rmi(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_rmi_request request = { 0 };
    struct isula_rmi_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    if (strcmp(args->image_name, "none") == 0 || strcmp(args->image_name, "none:latest") == 0) {
        COMMAND_ERROR("Can not remove image '%s', image name 'none' or 'none:latest' is reserved", args->image_name);
        return -1;
    }

    response = util_common_calloc_s(sizeof(struct isula_rmi_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    request.image_name = args->image_name;
    request.force = args->force;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->image.remove) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->image.remove(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        if (response->server_errono) {
            ret = ESERVERERROR;
        }
        goto out;
    }
out:
    isula_rmi_response_free(response);
    return ret;
}

int cmd_rmi_main(int argc, const char **argv)
{
    int i = 0;
    int err = 0;
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = 1; /* exit 1 if remove failed because docker return 1 */
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_rmi_args),
               RMI_OPTIONS(g_cmd_rmi_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_rmi_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_rmi_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_rmi_desc,
                 g_cmd_rmi_usage);
    if (command_parse_args(&cmd, &g_cmd_rmi_args.argc, &g_cmd_rmi_args.argv)) {
        exit(exit_code);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("RMI: log init failed");
        exit(exit_code);
    }

    if (g_cmd_rmi_args.argc == 0) {
        COMMAND_ERROR("\"rmi\" requires at least 1 image names");
        exit(exit_code);
    }

    if (g_cmd_rmi_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many images to remove.");
        exit(exit_code);
    }

    for (i = 0; i < g_cmd_rmi_args.argc; i++) {
        g_cmd_rmi_args.image_name = g_cmd_rmi_args.argv[i];
        int ret = client_rmi(&g_cmd_rmi_args);
        if (ret != 0) {
            ERROR("Image \"%s\" remove failed", g_cmd_rmi_args.image_name);
            err = ret;
            continue;
        }
        printf("Image \"%s\" removed\n", g_cmd_rmi_args.image_name);
    }

    if (err) {
        exit(exit_code);
    }
    exit(EXIT_SUCCESS);
}
