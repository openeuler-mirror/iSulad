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
 * Author: maoweiyong
 * Create: 2018-11-08
 * Description: provide container info functions
 ******************************************************************************/
#include "info.h"

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "command_parser.h"
#include "connect.h"
#include "libisula.h"

const char g_cmd_info_desc[] = "Display system-wide information";
const char g_cmd_info_usage[] = "info";

struct client_arguments g_cmd_info_args = {};

static void print_with_space(const char *info)
{
    size_t i = 0;
    size_t size = 0;
    bool print_space = true;

    if (info == NULL) {
        return;
    }

    size = strlen(info);
    for (i = 0; i < size; i++) {
        if (print_space) {
            printf(" ");
            print_space = false;
        }
        if (info[i] == '\n') {
            print_space = true;
        }
        printf("%c", info[i]);
    }

    return;
}

static void client_info_server(const struct isula_info_response *response)
{
    printf("Containers: %u\n", (unsigned int)(response->containers_num));
    printf(" Running: %u\n", (unsigned int)(response->c_running));
    printf(" Paused: %u\n", (unsigned int)(response->c_paused));
    printf(" Stopped: %u\n", (unsigned int)(response->c_stopped));
    printf("Images: %u\n", (unsigned int)(response->images_num));
    if (response->version != NULL) {
        printf("Server Version: %s\n", response->version);
    }
    if (response->driver_name != NULL) {
        printf("Storage Driver: %s\n", response->driver_name);
    }
    if (response->driver_status != NULL) {
        print_with_space(response->driver_status);
    }
    if (response->logging_driver != NULL) {
        printf("Logging Driver: %s\n", response->logging_driver);
    }
    if (response->cgroup_driver != NULL) {
        printf("Cgroup Driverr: %s\n", response->cgroup_driver);
    }
    if (response->huge_page_size != NULL) {
        printf("Hugetlb Pagesize: %s\n", response->huge_page_size);
    }
    if (response->kversion != NULL) {
        printf("Kernel Version: %s\n", response->kversion);
    }
    if (response->operating_system != NULL) {
        printf("Operating System: %s\n", response->operating_system);
    }
    if (response->os_type != NULL) {
        printf("OSType: %s\n", response->os_type);
    }
    if (response->architecture != NULL) {
        printf("Architecture: %s\n", response->architecture);
    }

    printf("CPUs: %u\n", (unsigned int)(response->cpus));
    printf("Total Memory: %u GB\n", (unsigned int)(response->total_mem));
    if (response->nodename != NULL) {
        printf("Name: %s\n", response->nodename);
    }
    if (response->isulad_root_dir != NULL) {
        printf("iSulad Root Dir: %s\n", response->isulad_root_dir);
    }
    if (response->http_proxy != NULL) {
        printf("Http Proxy: %s\n", response->http_proxy);
    }
    if (response->https_proxy != NULL) {
        printf("Https Proxy: %s\n", response->https_proxy);
    }
    if (response->no_proxy != NULL) {
        printf("No Proxy: %s\n", response->no_proxy);
    }
}

static int client_info(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_info_request request = { 0 };
    struct isula_info_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_info_response));
    if (response == NULL) {
        ERROR("Info: Out of memory");
        return -1;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || (ops->container.info) == NULL) {
        ERROR("Unimplemented info op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->container.info(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

    client_info_server(response);

out:
    isula_info_response_free(response);
    return ret;
}

int cmd_info_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;

    if (client_arguments_init(&g_cmd_info_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_info_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf), COMMON_OPTIONS(g_cmd_info_args) };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_info_desc,
                 g_cmd_info_usage);
    if (command_parse_args(&cmd, &g_cmd_info_args.argc, &g_cmd_info_args.argv) != 0) {
        exit(EINVALIDARGS);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf) != 0) {
        COMMAND_ERROR("Info: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_info_args.argc > 0) {
        COMMAND_ERROR("%s: \"info\" requires 0 arguments.", g_cmd_info_args.progname);
        exit(ECOMMON);
    }

    if (client_info(&g_cmd_info_args) != 0) {
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
