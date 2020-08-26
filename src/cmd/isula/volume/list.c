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
 * Create: 2020-09-05
 * Description: provide list volume functions
 ******************************************************************************/
#include "list.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"
#include "command_parser.h"
#include "connect.h"
#include "protocol_type.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_verify.h"

#define VOLUME_OPTIONS(cmdargs)                                                                                        \
    { CMD_OPT_TYPE_BOOL, false, "quiet", 'q', &((cmdargs).dispname), "Only display volume names", NULL },

const char g_cmd_volume_ls_desc[] = "List volumes";
const char g_cmd_volume_ls_usage[] = "ls [OPTIONS]";

struct client_arguments g_cmd_volume_ls_args;

/* keep track of field widths for printing. */
struct lengths {
    unsigned int driver_length;
    unsigned int name_length;
};

/* list print table */
static void list_print_table(const struct isula_list_volume_response *resp, const struct lengths *length)
{
    size_t i = 0;

    /* print header */
    printf("%-*s ", (int)length->driver_length, "DRIVER");
    printf("%-*s ", (int)length->name_length, "VOLUME NAME");
    printf("\n");

    for (i = 0; i < resp->volumes_len; i++) {
        printf("%-*s ", (int)length->driver_length, resp->volumes[i].driver);
        printf("%-*s ", (int)length->name_length, resp->volumes[i].name);
        printf("\n");
    }
}

/* list field width */
static void list_field_width(const struct isula_list_volume_response *resp, struct lengths *l)
{
    size_t i = 0;

    for (i = 0; i < resp->volumes_len; i++) {
        if (strlen(resp->volumes[i].driver) > l->driver_length) {
            l->driver_length = (unsigned int)strlen(resp->volumes[i].driver);
        }
        if (strlen(resp->volumes[i].name) > l->driver_length) {
            l->name_length = (unsigned int)strlen(resp->volumes[i].name);
        }
    }
}

/*
 * list all volume from isulad
 */
static void volume_info_print(const struct isula_list_volume_response *response)
{
    struct lengths max_len = {
        .driver_length = 20,
        .name_length = 10,
    };

    list_field_width(response, &max_len);
    list_print_table(response, &max_len);
}

/* volume info print quiet */
static void volume_info_print_quiet(const struct isula_list_volume_response *response)
{
    size_t i = 0;

    for (i = 0; i < response->volumes_len; i++) {
        printf("%s\n", response->volumes[i].name);
    }
}

/*
 * list volume
 */
static int list_volume(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_list_volume_request request = { 0 };
    struct isula_list_volume_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_list_volume_response));
    if (response == NULL) {
        ERROR("volume ls: Out of memory");
        return -1;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || ops->volume.list == NULL) {
        ERROR("Unimplemented volume list op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->volume.list(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

    if (args->dispname) {
        volume_info_print_quiet(response);
    } else {
        volume_info_print(response);
    }

out:
    isula_list_volume_response_free(response);
    return ret;
}

/* cmd volume main */
int cmd_volume_ls_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = ECOMMON;
    command_t cmd;

    if (client_arguments_init(&g_cmd_volume_ls_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_volume_ls_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf) VOLUME_OPTIONS(g_cmd_volume_ls_args)
        COMMON_OPTIONS(g_cmd_volume_ls_args)
    };

    subcommand_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_volume_ls_desc,
                    g_cmd_volume_ls_usage);
    if (command_parse_args(&cmd, &g_cmd_volume_ls_args.argc, &g_cmd_volume_ls_args.argv)) {
        exit(exit_code);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("volume ls: log init failed");
        exit(exit_code);
    }

    if (g_cmd_volume_ls_args.argc != 0) {
        COMMAND_ERROR("%s: \"volume ls\" requires exactly 0 arguments.", g_cmd_volume_ls_args.progname);
        exit(exit_code);
    }

    if (list_volume(&g_cmd_volume_ls_args)) {
        ERROR("Can not list any volume");
        exit(exit_code);
    }

    exit(EXIT_SUCCESS);
}
