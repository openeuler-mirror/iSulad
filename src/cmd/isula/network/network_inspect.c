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
 * Author: zhangxiaoyu
 * Create: 2020-09-02
 * Description: provide network inspect functions
 ******************************************************************************/
#include "network_inspect.h"

#include "isula_libutils/log.h"
#include "inspect_format.h"
#include "utils.h"

const char g_cmd_network_inspect_desc[] = "Inspect networks";
const char g_cmd_network_inspect_usage[] = "inspect [OPTIONS] NETWORK [NETWORK...]";

struct client_arguments g_cmd_network_inspect_args = {
    .format = NULL,
};

static int network_inspect(const struct client_arguments *args, const char *filter, container_tree_t *tree_array)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_network_inspect_request request = { 0 };
    struct isula_network_inspect_response *response = NULL;
    client_connect_config_t config = { 0 };
    yajl_val tree = NULL;

    response = util_common_calloc_s(sizeof(struct isula_network_inspect_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    request.name = args->network_name;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->network.inspect == NULL) {
        ERROR("Unimplemented network inspect op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->network.inspect(&request, response, &config);
    if (ret != 0 || response->json == NULL) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
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
    isula_network_inspect_response_free(response);
    return ret;
}

int cmd_network_inspect_main(int argc, const char **argv)
{
    int i = 0;
    int success_counts = 0;
    bool json_format = true;
    bool failed = false;
    char *filter_string = NULL;

    container_tree_t *tree_array = NULL;
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;

    struct command_option options[] = { LOG_OPTIONS(lconf) NETWORK_INSPECT_OPTIONS(g_cmd_network_inspect_args)
        COMMON_OPTIONS(g_cmd_network_inspect_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);

    if (client_arguments_init(&g_cmd_network_inspect_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_network_inspect_args.progname = util_string_join(" ", argv, 2);
    subcommand_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv,
                    g_cmd_network_inspect_desc, g_cmd_network_inspect_usage);
    if (command_parse_args(&cmd, &g_cmd_network_inspect_args.argc, &g_cmd_network_inspect_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_network_inspect_args.argc == 0) {
        COMMAND_ERROR("\"%s inspect\" requires at least 1 network name", g_cmd_network_inspect_args.progname);
        exit(EINVALIDARGS);
    }

    if (g_cmd_network_inspect_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many arguments.");
        exit(EINVALIDARGS);
    }

    tree_array = (container_tree_t *)util_smart_calloc_s(sizeof(container_tree_t),
                                                         (size_t)(g_cmd_network_inspect_args.argc + 1));
    if (tree_array == NULL) {
        ERROR("Out of memory\n");
        exit(ECOMMON);
    }

    if (g_cmd_network_inspect_args.format != NULL) {
        if (inspect_check_format_f(g_cmd_network_inspect_args.format, &json_format) != 0) {
            free(tree_array);
            tree_array = NULL;
            exit(ECOMMON);
        }

        filter_string = inspect_pause_filter(g_cmd_network_inspect_args.format);
        if (filter_string == NULL) {
            COMMAND_ERROR("Inspect format parameter invalid: %s", g_cmd_network_inspect_args.format);
            free(tree_array);
            tree_array = NULL;
            exit(EINVALIDARGS);
        }
    }

    for (i = 0; i < g_cmd_network_inspect_args.argc; i++) {
        g_cmd_network_inspect_args.network_name = g_cmd_network_inspect_args.argv[i];

        if (network_inspect(&g_cmd_network_inspect_args, filter_string, &tree_array[i]) != 0) {
            failed = true;
            break;
        }
        success_counts++;
    }

    if (tree_array != NULL) {
        inspect_show_result(success_counts, tree_array, g_cmd_network_inspect_args.format, json_format);
        inspect_free_trees(success_counts, tree_array);
    }
    free(tree_array);
    free(filter_string);

    if (failed) {
        COMMAND_ERROR("Inspect error, cannot find such network: %s", g_cmd_network_inspect_args.network_name);
        exit(ECOMMON);
    }
    exit(EXIT_SUCCESS);
}
