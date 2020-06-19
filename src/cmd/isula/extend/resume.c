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
 * Description: provide container resume functions
 ******************************************************************************/
#include "resume.h"
#include "utils.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"

const char g_cmd_resume_desc[] = "Unpause all processes within one or more containers";
const char g_cmd_resume_usage[] = "unpause [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_resume_args = {};

/*
 * Create a resume request message and call RPC
 */
static int client_resume(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_resume_request request = { 0 };
    struct isula_resume_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_resume_response));
    if (response == NULL) {
        ERROR("Resume: Out of memory");
        return -1;
    }

    request.name = args->name;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.resume) {
        ERROR("Unimplemented resume op");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->container.resume(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }
out:
    isula_resume_response_free(response);
    return ret;
}

int cmd_resume_main(int argc, const char **argv)
{
    int i = 0;
    int status = 0;
    struct isula_libutils_log_config lconf = { 0 };

    lconf.name = argv[0];
    lconf.quiet = true;
    lconf.driver = "stdout";
    lconf.file = NULL;
    lconf.priority = "ERROR";
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Resume: log init failed");
        exit(ECOMMON);
    }

    command_t cmd;
    if (client_arguments_init(&g_cmd_resume_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        exit(ECOMMON);
    }
    g_cmd_resume_args.progname = argv[0];
    struct command_option options[] = { COMMON_OPTIONS(g_cmd_resume_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_resume_desc,
                 g_cmd_resume_usage);
    if (command_parse_args(&cmd, &g_cmd_resume_args.argc, &g_cmd_resume_args.argv)) {
        exit(EINVALIDARGS);
    }

    if (g_cmd_resume_args.argc == 0) {
        COMMAND_ERROR("Pause requires at least 1 container names");
        exit(EINVALIDARGS);
    }

    if (g_cmd_resume_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to resume.");
        exit(EINVALIDARGS);
    }

    for (i = 0; i < g_cmd_resume_args.argc; i++) {
        g_cmd_resume_args.name = g_cmd_resume_args.argv[i];
        if (client_resume(&g_cmd_resume_args)) {
            ERROR("Container \"%s\" resume failed", g_cmd_resume_args.name);
            status = -1;
            continue;
        }

        printf("%s\n", g_cmd_resume_args.name);
    }

    if (status) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
