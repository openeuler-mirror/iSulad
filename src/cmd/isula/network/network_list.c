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
 * Description: provide network list functions
 ******************************************************************************/
#include "network_list.h"

#include "isula_libutils/log.h"
#include "utils.h"

const char g_cmd_network_list_desc[] = "List networks";
const char g_cmd_network_list_usage[] = "ls [flags]";

struct client_arguments g_cmd_network_list_args = { 0 };
/* keep track of field widths for printing. */
struct lengths {
    unsigned int name_length;
    unsigned int version_length;
    unsigned int plugin_length;
};

/*
* used by qsort function for comparing network name
*/
static inline int isula_network_cmp(struct isula_network_info **first, struct isula_network_info **second)
{
    return strcmp((*first)->name, (*second)->name);
}

static void network_list_print_quiet(const struct isula_network_list_response *response)
{
    size_t i;
    const struct isula_network_info *info = NULL;

    for (i = 0; i < response->network_num; i++) {
        info = response->network_info[i];
        if (info == NULL) {
            continue;
        }
        printf("%s\n", info->name);
    }
}

static void network_list_filed_width(const struct isula_network_info **network_info, const size_t network_num,
                                     struct lengths *l)
{
    size_t i;

    for (i = 0; i < network_num; i++) {
        size_t j, len;

        len = strlen(network_info[i]->name);
        if (len > l->name_length) {
            l->name_length = (unsigned int)len;
        }

        if (network_info[i]->version == NULL) {
            len = strlen("<none>");
        } else {
            len = strlen(network_info[i]->version);
        }
        if (len > l->version_length) {
            l->version_length = (unsigned int)len;
        }

        if (network_info[i]->plugins == NULL) {
            continue;
        }
        len = 0;
        for (j = 0; j < network_info[i]->plugin_num; j++) {
            len += strlen(network_info[i]->plugins[j]) + 1;
        }
        if (len > l->plugin_length) {
            l->plugin_length = (unsigned int)len;
        }
    }
}

static void network_list_print_table(const struct isula_network_info **network_info, const size_t network_num,
                                     const struct lengths *l)
{
    size_t i;
    char *plugins = NULL;

    /* print header */
    printf("%-*s ", (int)l->name_length, "NAME");
    printf("%-*s ", (int)l->version_length, "VERSION");
    printf("%-*s ", (int)l->plugin_length, "PLUGIN");
    printf("\n");

    for (i = 0; i < network_num; i++) {
        printf("%-*s ", (int)l->name_length, network_info[i]->name);
        printf("%-*s ", (int)l->version_length, network_info[i]->version ? network_info[i]->version : "<none>");

        plugins = util_string_join(",", (const char **)network_info[i]->plugins, network_info[i]->plugin_num);
        printf("%-*s ", (int)l->plugin_length, plugins ? plugins : "<none>");
        free(plugins);
        plugins = NULL;
        printf("\n");
    }
}

static void network_list_print(const struct isula_network_list_response *response)
{
    struct lengths max_len = {
        .name_length = 20,
        .version_length = 15,
        .plugin_length = 30,
    };

    network_list_filed_width((const struct isula_network_info **)response->network_info, response->network_num, &max_len);
    network_list_print_table((const struct isula_network_info **)response->network_info, response->network_num, &max_len);
}

int network_list(const struct client_arguments *args)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    struct isula_network_list_request request = { 0 };
    struct isula_network_list_response *response = NULL;
    client_connect_config_t config = { 0 };

    response = util_common_calloc_s(sizeof(struct isula_network_list_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (args->filters != NULL) {
        request.filters =
            isula_filters_parse_args((const char **)args->filters, util_array_len((const char **)(args->filters)));
        if (request.filters == NULL) {
            ERROR("Failed to parse filters args");
            ret = -1;
            goto out;
        }
    }

    ops = get_connect_client_ops();
    if (ops == NULL || ops->network.list == NULL) {
        ERROR("Unimplemented network list op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->network.list(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = -1;
        goto out;
    }

    if (response->network_num != 0) {
        qsort(response->network_info, response->network_num,
              sizeof(struct isula_network_info *), (int (*)(const void *, const void *))isula_network_cmp);
    }

    if (args->dispname) {
        network_list_print_quiet(response);
    } else {
        network_list_print(response);
    }

out:
    isula_network_list_response_free(response);
    return ret;
}

int cmd_network_list_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf) NETWORK_LIST_OPTIONS(g_cmd_network_list_args)
        COMMON_OPTIONS(g_cmd_network_list_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);

    if (client_arguments_init(&g_cmd_network_list_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_network_list_args.progname = util_string_join(" ", argv, 2);
    command_network_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv,
                         g_cmd_network_list_desc,
                         g_cmd_network_list_usage);
    if (command_parse_args(&cmd, &g_cmd_network_list_args.argc, &g_cmd_network_list_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_network_list_args.argc > 0) {
        COMMAND_ERROR("\"%s ls\" requires 0 arguments", g_cmd_network_list_args.progname);
        exit(EINVALIDARGS);
    }

    if (network_list(&g_cmd_network_list_args)) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}