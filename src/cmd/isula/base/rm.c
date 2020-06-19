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
#include <limits.h>
#include "rm.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "isula_commands.h"
#include "console.h"
#include "utils.h"

const char g_cmd_delete_desc[] = "Remove one or more containers";
const char g_cmd_delete_usage[] = "rm [OPTIONS] CONTAINER [CONTAINER...]";

struct client_arguments g_cmd_delete_args = {
    .force = false,
    .volume = false,
};
/*
* Create a rm request message and call RPC
*/
static int client_delete(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_delete_request request = { 0 };
    struct isula_delete_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_delete_response));
    if (response == NULL) {
        ERROR("RM: Out of memory");
        return -1;
    }

    request.name = args->name;
    request.force = args->force;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.remove) {
        ERROR("Unimplemented rm op");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->container.remove(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }

    if (response->name != NULL) {
        free(g_cmd_delete_args.name);
        g_cmd_delete_args.name = util_strdup_s(response->name);
    }

out:
    isula_delete_response_free(response);
    return ret;
}

static void do_delete_console_fifo(const char *name, const char *stdflag)
{
    int ret = 0;
    char fifo_dir[PATH_MAX] = { 0 };
    char fifo_name[PATH_MAX] = { 0 };

    ret = console_fifo_name(CLIENT_RUNDIR, name, stdflag, fifo_name, sizeof(fifo_name), fifo_dir, sizeof(fifo_dir),
                            false);
    if (ret != 0) {
        ERROR("Failed to get console fifo name.");
        goto out;
    }

    console_fifo_delete(fifo_name);

    if (util_recursive_rmdir(fifo_dir, 0)) {
        ERROR("Failed to delete FIFO path:%s", fifo_dir);
    }

out:
    return;
}

static void delete_console_fifo(const char *name)
{
    do_delete_console_fifo(name, "in");
    do_delete_console_fifo(name, "out");
    do_delete_console_fifo(name, "err");

    return;
}

int cmd_delete_main(int argc, const char **argv)
{
    int i = 0;
    bool status = false;
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_delete_args),
                                        DELETE_OPTIONS(g_cmd_delete_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_delete_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_delete_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_delete_desc,
                 g_cmd_delete_usage);
    if (command_parse_args(&cmd, &g_cmd_delete_args.argc, &g_cmd_delete_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Rm: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_delete_args.argc == 0) {
        COMMAND_ERROR("\"%s rm\" requires at least 1 argument(s).", g_cmd_delete_args.progname);
        COMMAND_ERROR("See '%s rm --help'.", g_cmd_delete_args.progname);
        exit(ECOMMON);
    }

    if (g_cmd_delete_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many containers to remove.");
        exit(ECOMMON);
    }

    for (i = 0; i < g_cmd_delete_args.argc; i++) {
        free(g_cmd_delete_args.name);
        g_cmd_delete_args.name = util_strdup_s(g_cmd_delete_args.argv[i]);
        if (client_delete(&g_cmd_delete_args)) {
            ERROR("Container \"%s\" rm failed", g_cmd_delete_args.name);
            status = true;
            continue;
        }
        delete_console_fifo(g_cmd_delete_args.name);
        printf("%s\n", g_cmd_delete_args.name);
    }

    if (status) {
        exit(ECOMMON);
    }
    exit(EXIT_SUCCESS);
}
