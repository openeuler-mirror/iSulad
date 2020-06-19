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
 * Create: 2020-04-15
 * Description: provide image tag functions
 ******************************************************************************/
#include "tag.h"
#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"

const char g_cmd_tag_desc[] = "Create a tag TARGET_IMAGE that refers to SOURCE_IMAGE";
const char g_cmd_tag_usage[] = "tag SOURCE_IMAGE[:TAG] TARGET_IMAGE[:TAG]";

struct client_arguments g_cmd_tag_args = {};

/*
 * Add a tag to the image
 */
static int client_tag(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_tag_request request = { 0 };
    struct isula_tag_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_tag_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    request.src_name = args->image_name;
    request.dest_name = args->tag;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->image.tag) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }
    config = get_connect_config(args);
    ret = ops->image.tag(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        if (response->server_errono) {
            ret = ESERVERERROR;
        }
        goto out;
    }
out:
    isula_tag_response_free(response);
    return ret;
}

int cmd_tag_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = 1;
    command_t cmd;
    struct command_option options[] = {
        LOG_OPTIONS(lconf),
        COMMON_OPTIONS(g_cmd_tag_args),
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_tag_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_tag_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_tag_desc,
                 g_cmd_tag_usage);
    if (command_parse_args(&cmd, &g_cmd_tag_args.argc, &g_cmd_tag_args.argv)) {
        exit(exit_code);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("RMI: log init failed");
        exit(exit_code);
    }

    if (g_cmd_tag_args.argc != 2) {
        COMMAND_ERROR("\"tag\" requires exactly 2 arguments.");
        exit(exit_code);
    }

    g_cmd_tag_args.image_name = g_cmd_tag_args.argv[0];
    g_cmd_tag_args.tag = g_cmd_tag_args.argv[1];

    if (!util_valid_image_name(g_cmd_tag_args.image_name)) {
        COMMAND_ERROR("%s is not a valid image name", g_cmd_tag_args.image_name);
        exit(exit_code);
    }

    if (!util_valid_tag(g_cmd_tag_args.tag)) {
        COMMAND_ERROR("%s is not a valid tag", g_cmd_tag_args.tag);
        exit(exit_code);
    }

    int ret = client_tag(&g_cmd_tag_args);
    if (ret != 0) {
        COMMAND_ERROR("Tag image \"%s\" to \"%s\" failed", g_cmd_tag_args.image_name, g_cmd_tag_args.tag);
        exit(exit_code);
    }

    exit(EXIT_SUCCESS);
}
