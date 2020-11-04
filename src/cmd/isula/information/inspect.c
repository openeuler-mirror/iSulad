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
 * Description: provide container inspect functions
 ******************************************************************************/

#include "inspect.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "utils.h"
#include "connect.h"
#include "inspect_format.h"

const char g_cmd_inspect_desc[] = "Return low-level information on a container or image";
const char g_cmd_inspect_usage[] = "inspect [options] CONTAINER|IMAGE [CONTAINER|IMAGE...]";

struct client_arguments g_cmd_inspect_args = {
    .format = NULL,
    .time = 120, // timeout time
};

#define CONTAINER_INSPECT_ERR (-1)
#define CONTAINER_NOT_FOUND (-2)

/*
 * RETURN VALUE:
 * 0: inspect container success
 * CONTAINER_INSPECT_ERR: have the container, but failed to inspect due to other reasons
 * CONTAINER_NOT_FOUND: no such container
*/
static int client_inspect_container(const struct isula_inspect_request *request,
                                    struct isula_inspect_response *response, client_connect_config_t *config,
                                    const isula_connect_ops *ops)
{
    int ret = 0;

    ret = ops->container.inspect(request, response, config);
    if (ret != 0) {
        if ((response->errmsg != NULL) &&
            (strstr(response->errmsg, "Inspect invalid name") != NULL ||
             strstr(response->errmsg, "No such image or container or accelerator") != NULL)) {
            return CONTAINER_NOT_FOUND;
        }

        /* have the container, but failed to inspect due to other reasons */
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = CONTAINER_INSPECT_ERR;
    }

    return ret;
}

static int client_inspect_image(const struct isula_inspect_request *request, struct isula_inspect_response *response,
                                client_connect_config_t *config, const isula_connect_ops *ops)
{
    int ret = 0;

    ret = ops->image.inspect(request, response, config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
    }

    return ret;
}

/*
 * Create a inspect request message and call RPC
 */
static int client_inspect(const struct client_arguments *args, const char *filter, container_tree_t *tree_array)
{
    isula_connect_ops *ops = NULL;
    struct isula_inspect_request request = { 0 };
    struct isula_inspect_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;
    yajl_val tree = NULL;

    response = util_common_calloc_s(sizeof(struct isula_inspect_response));
    if (response == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    request.name = args->name;
    request.bformat = args->format ? true : false;
    request.timeout = args->time;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.inspect == NULL || ops->image.inspect == NULL) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = client_inspect_container(&request, response, &config, ops);
    if (ret == CONTAINER_NOT_FOUND) {
        isula_inspect_response_free(response);
        response = NULL;

        response = util_common_calloc_s(sizeof(struct isula_inspect_response));
        if (response == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }

        ret = client_inspect_image(&request, response, &config, ops);
    }

    if (ret != 0) {
        goto out;
    }

    if (response == NULL || response->json == NULL) {
        ERROR("Container or image json is empty");
        ret = -1;
        goto out;
    }

    tree = inspect_load_json(response->json);
    if (tree == NULL) {
        ret = -1;
        goto out;
    }

    if (!inspect_filter_done(tree, filter, tree_array)) {
        ret = -1;
        yajl_tree_free(tree);
        goto out;
    }

    tree_array->tree_root = tree;

out:
    isula_inspect_response_free(response);
    return ret;
}

int cmd_inspect_main(int argc, const char **argv)
{
    int i = 0;
    int status = 0;
    struct isula_libutils_log_config lconf = { 0 };
    int success_counts = 0;
    char *filter_string = NULL;
    container_tree_t *tree_array = NULL;
    size_t array_size = 0;
    command_t cmd;
    bool json_format = true;

    if (client_arguments_init(&g_cmd_inspect_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_inspect_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf) INSPECT_OPTIONS(g_cmd_inspect_args),
               COMMON_OPTIONS(g_cmd_inspect_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_inspect_desc,
                 g_cmd_inspect_usage);
    if (command_parse_args(&cmd, &g_cmd_inspect_args.argc, &g_cmd_inspect_args.argv)) {
        exit(EINVALIDARGS);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_inspect_args.argc == 0) {
        COMMAND_ERROR("\"inspect\" requires a minimum of 1 argument.");
        exit(EINVALIDARGS);
    }

    if (g_cmd_inspect_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many arguments.");
        exit(EINVALIDARGS);
    }

    if ((size_t)g_cmd_inspect_args.argc > SIZE_MAX / sizeof(container_tree_t) - 1) {
        COMMAND_ERROR("The number of parameters of inspect is too large");
        exit(ECOMMON);
    }
    array_size = sizeof(container_tree_t) * (size_t)(g_cmd_inspect_args.argc + 1);
    tree_array = (container_tree_t *)util_common_calloc_s(array_size);
    if (tree_array == NULL) {
        ERROR("Malloc failed\n");
        exit(ECOMMON);
    }

    if (g_cmd_inspect_args.format != NULL) {
        int ret;
        ret = inspect_check_format_f(g_cmd_inspect_args.format, &json_format);
        if (ret != 0) {
            free(tree_array);
            tree_array = NULL;
            exit(ECOMMON);
        }

        filter_string = inspect_pause_filter(g_cmd_inspect_args.format);
        if (filter_string == NULL) {
            COMMAND_ERROR("Inspect format parameter invalid: %s", g_cmd_inspect_args.format);
            free(tree_array);
            tree_array = NULL;
            exit(EINVALIDARGS);
        }
    }

    for (i = 0; i < g_cmd_inspect_args.argc; i++) {
        g_cmd_inspect_args.name = g_cmd_inspect_args.argv[i];

        if (client_inspect(&g_cmd_inspect_args, filter_string, &tree_array[i])) {
            status = -1;
            break;
        }
        success_counts++;
    }

    if (tree_array != NULL) {
        inspect_show_result(success_counts, tree_array, g_cmd_inspect_args.format, json_format);
        inspect_free_trees(success_counts, tree_array);
    }
    free(tree_array);
    free(filter_string);

    if (status) {
        COMMAND_ERROR("Inspect error: No such object:%s", g_cmd_inspect_args.name);
        exit(ECOMMON);
    }
    exit(EXIT_SUCCESS);
}
