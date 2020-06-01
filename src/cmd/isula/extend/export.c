/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2019-04-04
 * Description: provide container export functions
 ******************************************************************************/
#include "export.h"
#include <limits.h>
#include "utils.h"
#include "arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"

const char g_cmd_export_desc[] = "export container";
const char g_cmd_export_usage[] = "export [command options] [ID|NAME]";

struct client_arguments g_cmd_export_args = {};

/*
 * Create a export request message and call RPC
 */
static int client_export(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_export_request request;
    struct isula_export_response *response = NULL;
    client_connect_config_t config = { 0 };

    (void)memset(&request, 0, sizeof(request));
    response = util_common_calloc_s(sizeof(struct isula_export_response));
    if (response == NULL) {
        ERROR("Resume: Out of memory");
        return -1;
    }

    request.name = args->name;
    request.file = args->file;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.export_rootfs) {
        ERROR("Unimplemented export op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.export_rootfs(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }
out:
    isula_export_response_free(response);
    return ret;
}

int cmd_export_main(int argc, const char **argv)
{
    int i = 0;
    char file[PATH_MAX] = { 0 };
    struct isula_libutils_log_config lconf = { 0 };

    lconf.name = argv[0];
    lconf.quiet = true;
    lconf.driver = "stdout";
    lconf.file = NULL;
    lconf.priority = "ERROR";
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Export: log init failed");
        exit(ECOMMON);
    }

    command_t cmd;
    if (client_arguments_init(&g_cmd_export_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_export_args.progname = argv[0];
    struct command_option options[] = { COMMON_OPTIONS(g_cmd_export_args), EXPORT_OPTIONS(g_cmd_export_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_export_desc,
                 g_cmd_export_usage);
    if (command_parse_args(&cmd, &g_cmd_export_args.argc, &g_cmd_export_args.argv)) {
        exit(EINVALIDARGS);
    }

    if (g_cmd_export_args.argc != 1) {
        COMMAND_ERROR("Export requires exactly 1 container name");
        exit(EINVALIDARGS);
    }

    if (g_cmd_export_args.file == NULL) {
        COMMAND_ERROR("Missing output file, use -o,--output option");
        exit(EINVALIDARGS);
    }

    /* If it's not a absolute path, add cwd to be absolute path */
    if (g_cmd_export_args.file[0] != '/') {
        int sret;
        char cwd[PATH_MAX] = { 0 };
        if (!getcwd(cwd, sizeof(cwd))) {
            COMMAND_ERROR("get cwd failed:%s", strerror(errno));
            exit(ECOMMON);
        }
        sret = snprintf(file, sizeof(file), "%s/%s", cwd, g_cmd_export_args.file);
        if (sret < 0 || (size_t)sret >= sizeof(file)) {
            COMMAND_ERROR("filename too long");
            exit(EINVALIDARGS);
        }
        g_cmd_export_args.file = file;
    }

    g_cmd_export_args.name = g_cmd_export_args.argv[i];
    if (client_export(&g_cmd_export_args)) {
        COMMAND_ERROR("Container \"%s\" export failed", g_cmd_export_args.name);
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}

