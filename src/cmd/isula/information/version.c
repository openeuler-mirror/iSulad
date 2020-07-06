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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container version functions
 ******************************************************************************/
#include "version.h"

#include <stdio.h>
#include <stdlib.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "config.h"
#include "isula_connect.h"
#include "command_parser.h"
#include "connect.h"
#include "constants.h"
#include "libisula.h"

const char g_cmd_version_desc[] = "Display information about isula";
const char g_cmd_version_usage[] = "version";

struct client_arguments g_cmd_version_args = {};

static void client_version_info_client()
{
    printf("Client:\n");
    printf("  Version:\t%s\n", VERSION);
    printf("  Git commit:\t%s\n", ISULAD_GIT_COMMIT);
    printf("  Built:\t%s\n", ISULAD_BUILD_TIME);
    printf("\n");
}
static void client_version_info_oci_config()
{
    printf("OCI config:\n");
    printf("  Version:\t%s\n", OCI_VERSION);
    printf("  Default file:\t%s\n", OCICONFIG_PATH);
    printf("\n");
}
static void client_version_info_server(const struct isula_version_response *response)
{
    printf("Server:\n");
    printf("  Version:\t%s\n", response->version ? response->version : "");
    printf("  Git commit:\t%s\n", response->git_commit ? response->git_commit : "");
    printf("  Built:\t%s\n", response->build_time ? response->build_time : "");
    printf("\n");
}

static int client_version(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_version_request request = { 0 };
    struct isula_version_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_version_response));
    if (response == NULL) {
        ERROR("Version: Out of memory");
        return -1;
    }

    client_version_info_client();

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.version) {
        ERROR("Unimplemented version op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.version(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

    client_version_info_server(response);
    client_version_info_oci_config();
out:
    isula_version_response_free(response);
    return ret;
}

int cmd_version_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_version_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_version_args)) {
        COMMAND_ERROR("client arguments init failed\n");
        exit(ECOMMON);
    }
    g_cmd_version_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_version_desc,
                 g_cmd_version_usage);
    if (command_parse_args(&cmd, &g_cmd_version_args.argc, &g_cmd_version_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Version: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_version_args.argc > 0) {
        COMMAND_ERROR("%s: \"version\" requires 0 arguments.", g_cmd_version_args.progname);
        exit(ECOMMON);
    }

    if (client_version(&g_cmd_version_args)) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
