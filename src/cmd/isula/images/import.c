/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2020-05-26
 * Description: provide image import functions
 ******************************************************************************/
#include "import.h"
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"

const char g_cmd_import_desc[] = "Import the contents from a tarball to create a filesystem image";
const char g_cmd_import_usage[] = "import file REPOSITORY[:TAG]";

struct client_arguments g_cmd_import_args = {};

/*
 * Import rootfs to be image
 */
static int client_import(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_import_request request = { 0 };
    struct isula_import_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_import_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    request.file = args->file;
    request.tag = args->tag;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->image.import) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->image.import(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        if (response->server_errono) {
            ret = ESERVERERROR;
        }
        goto out;
    }

    if (response->id != NULL) {
        printf("sha256:%s\n", response->id);
    }

out:
    isula_import_response_free(response);
    return ret;
}

int cmd_import_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    char file[PATH_MAX] = { 0 };
    int exit_code = 1;
    command_t cmd;
    struct command_option options[] = {
        LOG_OPTIONS(lconf),
        COMMON_OPTIONS(g_cmd_import_args),
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_import_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_import_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_import_desc,
                 g_cmd_import_usage);
    if (command_parse_args(&cmd, &g_cmd_import_args.argc, &g_cmd_import_args.argv)) {
        exit(exit_code);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Import: log init failed");
        exit(exit_code);
    }

    if (g_cmd_import_args.argc != 2) {
        COMMAND_ERROR("\"import\" requires exactly 2 arguments.");
        exit(exit_code);
    }

    g_cmd_import_args.file = g_cmd_import_args.argv[0];
    g_cmd_import_args.tag = g_cmd_import_args.argv[1];

    if (!util_valid_tag(g_cmd_import_args.tag)) {
        COMMAND_ERROR("%s is not a valid image name", g_cmd_import_args.tag);
        exit(exit_code);
    }

    /* If it's not a absolute path, add cwd to be absolute path */
    if (g_cmd_import_args.file[0] != '/') {
        char cwd[PATH_MAX] = { 0 };
        int len = 0;

        if (!getcwd(cwd, sizeof(cwd))) {
            COMMAND_ERROR("get cwd failed:%s", strerror(errno));
            exit(exit_code);
        }

        len = snprintf(file, sizeof(file), "%s/%s", cwd, g_cmd_import_args.file);
        if (len < 0 || (size_t)len >= sizeof(file)) {
            COMMAND_ERROR("filename too long");
            exit(exit_code);
        }
        g_cmd_import_args.file = file;
    }

    int ret = client_import(&g_cmd_import_args);
    if (ret != 0) {
        COMMAND_ERROR("Import tarball \"%s\" to \"%s\" failed", g_cmd_import_args.file, g_cmd_import_args.tag);
        exit(exit_code);
    }

    exit(EXIT_SUCCESS);
}
