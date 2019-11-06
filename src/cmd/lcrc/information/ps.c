/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container ps functions
 ******************************************************************************/
#include <string.h>
#include <errno.h>
#include "securec.h"
#include "arguments.h"
#include "ps.h"
#include "utils.h"
#include "log.h"
#include "lcrc_connect.h"

const char g_cmd_list_desc[] = "List containers";
const char g_cmd_list_usage[] = "ps [command options]";

#define COMMAND_LENGTH_MAX 22
#define TIME_DURATION_MAX_LEN 32

struct client_arguments g_cmd_list_args = {
    .dispname = false,
    .list_all = false,
};

/* keep track of field widths for printing. */
struct lengths {
    unsigned int id_length;
    unsigned int state_length;
    unsigned int image_length;
    unsigned int command_length;
    unsigned int init_length;
    unsigned int exit_length;
    unsigned int rscont_length;
    unsigned int startat_length;
    unsigned int finishat_length;
    unsigned int runtime_length;
    unsigned int name_length;
};

const char * const g_containerstatusstr[] = { "unknown", "inited", "starting",  "running",
                                              "exited",  "paused", "restarting"
                                            };

static const char *lcrc_lcrsta2str(Container_Status sta)
{
    if (sta >= CONTAINER_STATUS_MAX_STATE) {
        return NULL;
    }
    return g_containerstatusstr[sta];
}

static void list_print_quiet(struct lcrc_container_summary_info **info, const size_t size,
                             const struct lengths *length)
{
    const char *status = NULL;
    size_t i = 0;

    for (i = 0; i < size; i++) {
        const struct lcrc_container_summary_info *in = NULL;
        in = info[i];
        status = lcrc_lcrsta2str(in->status);
        if (status == NULL) {
            continue;
        }

        printf("%-*s ", (int)length->id_length, in->id ? in->id : "-");
        printf("\n");
    }
}

static int mix_container_status(const struct lcrc_container_summary_info *in, char *status, size_t len)
{
    int ret = 0;
    const char *container_status = NULL;

    container_status = lcrc_lcrsta2str(in->status);
    if (container_status == NULL) {
        ret = strcpy_s(status, len, "-");
        if (ret < 0) {
            ERROR("Failed to copy string");
            ret = -1;
            goto out;
        }
    } else {
        if (strcpy_s(status, len, container_status) != EOK) {
            ERROR("Failed to copy string");
            ret = -1;
            goto out;
        }
        if (in->health_state != NULL) {
            if (strcat_s(status, len, in->health_state) != EOK) {
                ERROR("Failed to cat string");
                ret = -1;
                goto out;
            }
        }
    }

out:
    return ret;
}

static void ps_print_header(struct lengths *length)
{
    /* print header */
    printf("%-*s ", (int)length->state_length, "STATUS");
    printf("%-*s ", (int)length->init_length, "PID");
    printf("%-*s ", (int)length->image_length, "IMAGE");
    if (length->command_length > COMMAND_LENGTH_MAX) {
        printf("%-*s ", COMMAND_LENGTH_MAX, "COMMAND");
        length->command_length = COMMAND_LENGTH_MAX;
    } else {
        printf("%-*s ", (int)length->command_length, "COMMAND");
    }
    printf("%-*s ", (int)length->exit_length, "EXIT_CODE");
    printf("%-*s ", (int)length->rscont_length, "RESTART_COUNT");
    printf("%-*s ", (int)length->startat_length, "STARTAT");
    printf("%-*s ", (int)length->finishat_length, "FINISHAT");
    printf("%-*s ", (int)length->runtime_length, "RUNTIME");
    printf("%-*s ", (int)length->id_length, "ID");
    printf("%-*s ", (int)length->name_length, "NAMES");
    printf("\n");
}

static void ps_print_container_info_pre(const struct lcrc_container_summary_info *in, const char *status,
                                        const struct lengths *length)
{
    const char *cmd = (in->command != NULL) ? in->command : "-";
    int cmd_len = (int)strlen(cmd);

    printf("%-*s ", (int)length->state_length, status);
    if (in->has_pid) {
        printf("%-*u ", (int)length->init_length, in->pid);
    } else {
        printf("%-*s ", (int)length->init_length, "-");
    }
    printf("%-*s ", (int)length->image_length, in->image ? in->image : "none");
    if (cmd_len > COMMAND_LENGTH_MAX - 2) {
        printf("\"%-*.*s...\" ", COMMAND_LENGTH_MAX - 5, COMMAND_LENGTH_MAX - 5, cmd);
    } else {
        int space_len = ((int)(length->command_length) - cmd_len) - 2;
        printf("\"%-*.*s\"%*s ", cmd_len, cmd_len, cmd, space_len, (space_len == 0) ? "" : " ");
    }
}

static void ps_print_container_info(const struct lcrc_container_summary_info *in, const char *status,
                                    const struct lengths *length)
{
    char finishat_duration[TIME_DURATION_MAX_LEN] = { 0 };
    char startat_duration[TIME_DURATION_MAX_LEN] = { 0 };

    ps_print_container_info_pre(in, status, length);

    printf("%-*u ", (int)length->exit_length, in->exit_code);
    printf("%-*u ", (int)length->rscont_length, in->restart_count);
    time_format_duration(in->startat, startat_duration, sizeof(startat_duration));
    printf("%-*s ", (int)length->startat_length, in->startat ? startat_duration : "-");
    time_format_duration(in->finishat, finishat_duration, sizeof(finishat_duration));
    printf("%-*s ", (int)length->finishat_length, in->finishat ? finishat_duration : "-");
    printf("%-*s ", (int)length->runtime_length, in->runtime ? in->runtime : "lcr");
    printf("%-*.*s ", (int)length->id_length, (int)length->id_length, in->id ? in->id : "-");
    printf("%-*s ", (int)length->name_length, in->name ? in->name : "-");
    printf("\n");
}

static void list_print_table(struct lcrc_container_summary_info **info, const size_t size, struct lengths *length)
{
    const struct lcrc_container_summary_info *in = NULL;
    size_t i = 0;
    char status[32] = { 0 };

    ps_print_header(length);

    for (i = 0; i < size; i++) {
        in = info[i];
        if (mix_container_status(in, status, sizeof(status))) {
            return;
        }

        ps_print_container_info(in, status, length);
    }
}

static void calculate_str_length(const char *str, unsigned int *length)
{
    size_t len = 0;

    if (str == NULL) {
        return;
    }

    len = strlen(str);
    if (len > (*length)) {
        *length = (unsigned int)len;
    }
}

static void calculate_status_str_length(const struct lcrc_container_summary_info *in, unsigned int *length)
{
    const char *status = NULL;

    status = lcrc_lcrsta2str(in->status);
    if (status != NULL) {
        size_t len;
        len = strlen(status);
        if (in->health_state != NULL) {
            len += strlen(in->health_state);
        }
        if (len > (*length)) {
            *length = (unsigned int)len;
        }
    }
}

static void calculate_uint_str_length(uint32_t data, unsigned int *length)
{
    int len = 0;
    char tmpbuffer[UINT_LEN + 1] = { 0 };

    len = sprintf_s(tmpbuffer, sizeof(tmpbuffer), "%u", data);
    if (len < 0) {
        ERROR("sprintf buffer failed");
        return;
    }
    if ((unsigned int)len > (*length)) {
        *length = (unsigned int)len;
    }
}

static void calculate_time_str_length(const char *str, unsigned int *length)
{
    size_t len = 0;
    char time_duration[TIME_DURATION_MAX_LEN];

    if (time_format_duration(str, time_duration, sizeof(time_duration)) < 0) {
        ERROR("Format time duration failed");
    }
    len = strlen(time_duration);
    if (len > (*length)) {
        *length = (unsigned int)len;
    }
}

static void list_field_width(struct lcrc_container_summary_info **info, const size_t size, struct lengths *l)
{
    size_t i = 0;
    const struct lcrc_container_summary_info *in = NULL;

    if (info == NULL || l == NULL) {
        return;
    }

    for (i = 0; i < size; i++, in++) {
        in = info[i];
        calculate_str_length(in->name, &l->name_length);
        calculate_str_length(in->runtime, &l->runtime_length);
        calculate_status_str_length(in, &l->state_length);
        if (in->pid != -1) {
            calculate_uint_str_length(in->pid, &l->init_length);
        }

        calculate_str_length(in->image, &l->image_length);
        if (in->command != NULL) {
            size_t cmd_len;
            cmd_len = strlen(in->command) + 2;
            if (cmd_len > l->command_length) {
                l->command_length = (unsigned int)cmd_len;
            }
        }

        calculate_uint_str_length(in->exit_code, &l->exit_length);

        calculate_uint_str_length(in->restart_count, &l->rscont_length);

        if (in->startat != NULL) {
            calculate_time_str_length(in->startat, &l->startat_length);
        }

        if (in->finishat != NULL) {
            calculate_time_str_length(in->finishat, &l->finishat_length);
        }
    }
}

/*
* used by qsort function for comparing container start time
*/
static inline int lcrc_container_cmp(struct lcrc_container_summary_info **first,
                                     struct lcrc_container_summary_info **second)
{
    return strcmp((*second)->startat, (*first)->startat);
}

/*
* Create a list request message and call RPC
*/
static int client_list(const struct client_arguments *args)
{
    lcrc_connect_ops *ops = NULL;
    struct lcrc_list_request request = { 0 };
    struct lcrc_list_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;
    struct lengths max_len = {
        .name_length = 5, /* NAMES */
        .id_length = 12, /* ID */
        .state_length = 5, /* STATE */
        .image_length = 5, /* IMAGE */
        .command_length = 7, /* COMMAND */
        .init_length = 3, /* PID */
        .exit_length = 9, /* EXIT_CODE*/
        .rscont_length = 13, /* RESTART_COUNT*/
        .startat_length = 7, /* STARTAT*/
        .finishat_length = 8, /* FINISHAT*/
        .runtime_length = 7, /* RUNTIME */
    };

    response = util_common_calloc_s(sizeof(struct lcrc_list_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->container.list) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    if (args->filters != NULL) {
        request.filters = lcrc_filters_parse_args((const char **)args->filters,
                                                  util_array_len((const char **)(args->filters)));
        if (!request.filters) {
            ERROR("Failed to parse filters args");
            ret = -1;
            goto out;
        }
    }
    request.all = args->list_all;

    config = get_connect_config(args);
    ret = ops->container.list(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }
    if (response->container_num != 0)
        qsort(response->container_summary, (size_t)(response->container_num),
              sizeof(struct lcrc_container_summary_info *), (int (*)(const void *, const void *))lcrc_container_cmp);

    if (args->dispname) {
        list_print_quiet(response->container_summary, response->container_num, &max_len);
    } else {
        list_field_width(response->container_summary, response->container_num, &max_len);
        list_print_table(response->container_summary, response->container_num, &max_len);
    }

out:
    lcrc_filters_free(request.filters);
    lcrc_list_response_free(response);
    return ret;
}

int cmd_list_main(int argc, const char **argv)
{
    struct log_config lconf = { 0 };
    command_t cmd;

    set_default_command_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_list_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_list_args.progname = argv[0];
    struct command_option options[] = {
        LOG_OPTIONS(lconf),
        LIST_OPTIONS(g_cmd_list_args),
        COMMON_OPTIONS(g_cmd_list_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_list_desc,
                 g_cmd_list_usage);
    if (command_parse_args(&cmd, &g_cmd_list_args.argc, &g_cmd_list_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (log_init(&lconf)) {
        COMMAND_ERROR("PS: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_list_args.argc > 0) {
        COMMAND_ERROR("%s: \"ps\" requires 0 arguments.", g_cmd_list_args.progname);
        exit(ECOMMON);
    }
    if (client_list(&g_cmd_list_args)) {
        ERROR("Can not ps any containers");
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}

