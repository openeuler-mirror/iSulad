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
 * Author: haozi007
 * Create: 2020-12-26
 * Description: provide container port command
 ******************************************************************************/
#include "port.h"
#include <isula_libutils/container_inspect.h>
#include <isula_libutils/log.h>

#include "client_arguments.h"
#include "isula_connect.h"
#include "utils.h"
#include "utils_port.h"
#include "connect.h"

const char g_cmd_port_desc[] = "List port mappings of the container";
const char g_cmd_port_usage[] = "port CONTAINER [PRIVATE_PORT[/PROTO]]";

struct client_arguments g_cmd_port_args = { 0 };

#define CONTAINER_PORT_ERR (-1)
#define CONTAINER_NOT_FOUND (-2)

/*
 * Create a inspect request message and call RPC
 */
static char *do_inspect_container(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_inspect_request request = { 0 };
    struct isula_inspect_response *resp = NULL;
    client_connect_config_t config = { 0 };
    int nret = 0;
    char *json = NULL;

    resp = util_common_calloc_s(sizeof(struct isula_inspect_response));
    if (resp == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    request.name = args->name;
    request.timeout = args->time;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.inspect == NULL || ops->image.inspect == NULL) {
        ERROR("Unimplemented ops");
        nret = -1;
        goto out;
    }

    config = get_connect_config(args);
    nret = ops->container.inspect(&request, resp, &config);
    if (nret != 0) {
        if ((resp->errmsg != NULL) &&
            (strstr(resp->errmsg, "Inspect invalid name") != NULL ||
             strstr(resp->errmsg, "No such image or container or accelerator") != NULL)) {
            ERROR("Out of memory");
        }

        /* have the container, but failed to inspect due to other reasons */
        client_print_error(resp->cc, resp->server_errono, resp->errmsg);
        nret = CONTAINER_PORT_ERR;
        goto out;
    }

    if (resp == NULL || resp->json == NULL) {
        ERROR("Container json is empty");
        nret = -1;
        goto out;
    }

    json = resp->json;
    resp->json = NULL;
out:
    isula_inspect_response_free(resp);
    return json;
}

static container_inspect *get_container_info(const struct client_arguments *args)
{
    char *info_str = NULL;
    parser_error jerr = NULL;
    container_inspect *c_info = NULL;

    info_str = do_inspect_container(args);
    if (info_str == NULL) {
        COMMAND_ERROR("do inspect container: %s failed", args->name);
        return NULL;
    }

    c_info = container_inspect_parse_data(info_str, NULL, &jerr);
    
    free(jerr);
    free(info_str);
    return c_info;
}

static int do_port(const struct client_arguments *args, struct network_port *n_port)
{
    container_inspect *c_info = NULL;
    int ret = 0;
    size_t i;

    c_info = get_container_info(args);
    if (c_info == NULL) {
        return CONTAINER_PORT_ERR;
    }

    if (c_info->network_settings == NULL || c_info->network_settings->ports == NULL) {
        goto out;
    }

    for (i = 0; i < c_info->network_settings->ports->len; i++) {
        size_t j;
        if (c_info->network_settings->ports->keys[i] == NULL || c_info->network_settings->ports->values[i] == NULL ||
            c_info->network_settings->ports->values[i]->element == NULL) {
            continue;
        }
        if (n_port != NULL && n_port->format_str != NULL) {
            if (strcmp(n_port->format_str, c_info->network_settings->ports->keys[i]) != 0) {
                continue;
            }
        }

        for (j = 0; j < c_info->network_settings->ports->values[i]->element->host_len; j++) {
            network_port_binding_host_element *tmp = c_info->network_settings->ports->values[i]->element->host[j];
            const char *use_ip = util_valid_str(tmp->host_ip) ? tmp->host_ip : "0.0.0.0";
            printf("%s -> %s:%s\n", c_info->network_settings->ports->keys[i], use_ip, tmp->host_port);
        }
    }

out:
    free_container_inspect(c_info);
    return ret;
}

static struct network_port *parse_user_ports(const char *port)
{
    struct network_port *res = NULL;
    char **parts = NULL;
    size_t parts_len;
    const char *work_proto = "tcp";
    const char *work_port = port;

    parts = util_string_split(port, '/');
    if (parts == NULL) {
        COMMAND_ERROR("Out of memory");
        return NULL;
    }
    parts_len = util_array_len((const char **)parts);
    // invalid port format check in next step
    if (parts_len == 2 && parts[1] != NULL) {
        work_port = parts[0];
        work_proto = parts[1];
    }

    if (!util_new_network_port(work_proto, work_port, &res)) {
        COMMAND_ERROR("invalid port argument: %s", port);
        goto out;
    }

out:
    util_free_array_by_len(parts, parts_len);
    return res;
}

int cmd_port_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct network_port *n_port = NULL;

    if (client_arguments_init(&g_cmd_port_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_port_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf) COMMON_OPTIONS(g_cmd_port_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_port_desc,
                 g_cmd_port_usage);
    if (command_parse_args(&cmd, &g_cmd_port_args.argc, &g_cmd_port_args.argv)) {
        exit(EINVALIDARGS);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_port_args.argc == 0) {
        COMMAND_ERROR("\"port\" requires a minimum of 1 argument.");
        exit(EINVALIDARGS);
    }

    if (g_cmd_port_args.argc >= MAX_CLIENT_ARGS) {
        COMMAND_ERROR("You specify too many arguments.");
        exit(EINVALIDARGS);
    }

    g_cmd_port_args.name = g_cmd_port_args.argv[0];
    if (g_cmd_port_args.argc > 1) {
        g_cmd_port_args.port = g_cmd_port_args.argv[1];
        n_port = parse_user_ports(g_cmd_port_args.port);
        if (n_port == NULL) {
            exit(CONTAINER_PORT_ERR);
        }
    }

    if (do_port(&g_cmd_port_args, n_port) != 0) {
        util_free_network_port(n_port);
        exit(CONTAINER_PORT_ERR);
    }
    util_free_network_port(n_port);

    exit(EXIT_SUCCESS);
}
