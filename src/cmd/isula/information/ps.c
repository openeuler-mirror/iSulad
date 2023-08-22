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
 * Description: provide container ps functions
 ******************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <regex.h>
#include <stdint.h>

#include "client_arguments.h"
#include "ps.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "connect.h"
#include "constants.h"
#include "client_show_format.h"

#include "utils_array.h"
#include "utils_string.h"
#include "utils_timestamp.h"

const char g_cmd_list_desc[] = "List containers";
const char g_cmd_list_usage[] = "ps [OPTIONS]";

#define COMMAND_LENGTH_MAX 22
#define TIME_DURATION_MAX_LEN 32

struct client_arguments g_cmd_list_args = {
    .dispname = false,
    .list_all = false,
    .list_latest = false,
    .list_last_n = 0,
    .no_trunc = false,
};

/* keep track of field widths for printing. */
struct lengths {
    /* basic info */
    unsigned int id_length;
    unsigned int image_length;
    unsigned int command_length;
    unsigned int created_length;
    unsigned int status_length;
    unsigned int ports_length;
    unsigned int name_length;
    /* external info */
    unsigned int state_length;
    unsigned int init_length;
    unsigned int exit_length;
    unsigned int rscont_length;
    unsigned int startat_length;
    unsigned int finishat_length;
    unsigned int runtime_length;
};

const char * const g_containerstatusstr[] = { "unknown", "inited", "starting",  "running",
                                              "exited",  "paused", "restarting"
                                            };
#define DEFAULT_CONTAINER_TABLE_FORMAT          \
    "table {{.ID}}\t{{.Image}}\t{{.Command}}\t" \
    "{{.Created}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}"

static const char *isula_lcrsta2str(Container_Status sta)
{
    if (sta >= CONTAINER_STATUS_MAX_STATE) {
        return NULL;
    }
    return g_containerstatusstr[sta];
}

static void list_print_quiet(struct isula_container_summary_info **info, const size_t size,
                             const struct lengths *length)
{
    const char *status = NULL;
    size_t i = 0;

    for (i = 0; i < size; i++) {
        const struct isula_container_summary_info *in = NULL;
        in = info[i];
        status = isula_lcrsta2str(in->status);
        if (status == NULL) {
            continue;
        }

        printf("%-*s", (int)length->id_length, in->id ? in->id : "-");
        printf("\n");
    }
}

static int mix_container_state(const struct isula_container_summary_info *in, char *state, size_t len)
{
    int ret = 0;
    const char *container_status = NULL;

    container_status = isula_lcrsta2str(in->status);
    if (container_status == NULL) {
        (void)strcpy(state, "-");
    } else {
        (void)strcpy(state, container_status);
    }

    return ret;
}

static int handle_running_status(const char *start_at, const struct isula_container_summary_info *in, char *status,
                                 size_t len)
{
    int ret = 0;
    int nret;

    if (in->health_state != NULL) {
        nret = snprintf(status, len, "Up %s (%s)", start_at, in->health_state);
        if (nret < 0 || (size_t)nret >= len) {
            ERROR("Failed to compose string");
            ret = -1;
            goto out;
        }
    } else {
        nret = snprintf(status, len, "Up %s", start_at);
        if (nret < 0 || (size_t)nret >= len) {
            ERROR("Failed to compose string");
            ret = -1;
            goto out;
        }
    }

out:
    return ret;
}

static int mix_container_status(const struct isula_container_summary_info *in, char *status, size_t len)
{
    int ret = -1;
    int sret = 0;
    char startat_duration[TIME_DURATION_MAX_LEN] = { 0 };
    char finishat_duration[TIME_DURATION_MAX_LEN] = { 0 };
    char *start_at = NULL;
    char *finish_at = NULL;
    util_time_format_duration(in->startat, startat_duration, sizeof(startat_duration));
    util_time_format_duration_ago(in->finishat, finishat_duration, sizeof(finishat_duration));
    start_at = in->startat ? startat_duration : "-";
    finish_at = in->finishat ? finishat_duration : "-";

    if (in->status == CONTAINER_STATUS_RUNNING) {
        if (handle_running_status(start_at, in, status, len) != 0) {
            goto out;
        }
    } else {
        if (in->status == CONTAINER_STATUS_CREATED) {
            sret = snprintf(status, len, "Created");
        } else if (in->status == CONTAINER_STATUS_RESTARTING) {
            sret = snprintf(status, len, "Restarting (%d) %s", (int)in->exit_code, finish_at);
        } else if (in->status == CONTAINER_STATUS_PAUSED) {
            sret = snprintf(status, len, "Up %s (Paused)", start_at);
        } else if (in->status == CONTAINER_STATUS_STARTING) {
            sret = snprintf(status, len, "Starting %s", start_at);
        } else {
            sret = snprintf(status, len, "Exited (%d) %s", (int)in->exit_code, finish_at);
        }
        if (sret < 0 || (size_t)sret >= len) {
            goto out;
        }
    }

    ret = 0;

out:
    return ret;
}

static void printf_enable_interpretation_of_backslash_escapes(const char *str)
{
    unsigned char ch;
    char const *s = str;

    if (str == NULL) {
        return;
    }

    ch = *s++;
    while (ch != '\0') {
        if (*s != '\0' && ch == '\\') {
            ch = *s++;
            switch (ch) {
                case 'n':
                    ch = '\n';
                    break;
                case 't':
                    ch = '\t';
                    break;
                case '\\':
                    break;
                default:
                    putchar('\\');
                    break;
            }
        }
        putchar(ch);
        ch = *s++;
    }
}

static bool should_print_table_header(const struct format_filters *ff)
{
    return ff != NULL && ff->field_len != 0 && ff->fields[0]->name != NULL &&
           strcmp(ff->fields[0]->name, "table") == 0 && ff->fields[0]->is_field;
}

static void print_table_header_item(const char *name, struct lengths *length)
{
    if (strcmp(name, "ID") == 0) {
        printf("%-*s", (int)length->id_length, "CONTAINER ID");
    } else if (strcmp(name, "Image") == 0) {
        printf("%-*s", (int)length->image_length, "IMAGE");
    } else if (strcmp(name, "Status") == 0) {
        printf("%-*s", (int)length->status_length, "STATUS");
    } else if (strcmp(name, "Pid") == 0) {
        printf("%-*s", (int)length->init_length, "PID");
    } else if (strcmp(name, "Command") == 0) {
        if (length->command_length > COMMAND_LENGTH_MAX) {
            printf("%-*s", COMMAND_LENGTH_MAX, "COMMAND");
            length->command_length = COMMAND_LENGTH_MAX;
        } else {
            printf("%-*s", (int)length->command_length, "COMMAND");
        }
    } else if (strcmp(name, "ExitCode") == 0) {
        printf("%-*s", (int)length->exit_length, "EXIT_CODE");
    } else if (strcmp(name, "RestartCount") == 0) {
        printf("%-*s", (int)length->rscont_length, "RESTART_COUNT");
    } else if (strcmp(name, "StartAt") == 0) {
        printf("%-*s", (int)length->startat_length, "STARTAT");
    } else if (strcmp(name, "FinishAt") == 0) {
        printf("%-*s", (int)length->finishat_length, "FINISHAT");
    } else if (strcmp(name, "Runtime") == 0) {
        printf("%-*s", (int)length->runtime_length, "RUNTIME");
    } else if (strcmp(name, "Names") == 0) {
        printf("%-*s", (int)length->name_length, "NAMES");
    } else if (strcmp(name, "Created") == 0) {
        printf("%-*s", (int)length->created_length, "CREATED");
    } else if (strcmp(name, "Ports") == 0) {
        printf("%-*s", (int)length->ports_length, "PORTS");
    } else if (strcmp(name, "State") == 0) {
        printf("%-*s", (int)length->state_length, "STATE");
    }
}

static void ps_print_header(struct lengths *length, const struct format_filters *ff)
{
    size_t i;

    if (!should_print_table_header(ff)) {
        return;
    }

    /* print header */
    for (i = 1; i < ff->field_len; i++) {
        if (ff->fields[i]->is_field) {
            print_table_header_item(ff->fields[i]->name, length);
        } else {
            printf_enable_interpretation_of_backslash_escapes(ff->fields[i]->name);
        }
    }
    printf("\n");
}

static int get_created_time_buffer(int64_t created, char *timebuffer, size_t len)
{
    types_timestamp_t timestamp;

    if (!unix_nanos_to_timestamp(created, &timestamp)) {
        ERROR("Failed to get timestamp");
        return -1;
    }
    if (!util_get_time_buffer(&timestamp, timebuffer, len)) {
        ERROR("Failed to get timebuffer from timestamp");
        return -1;
    }

    return 0;
}
static void print_created_field(int64_t created, unsigned int length)
{
    char timebuffer[TIME_STR_SIZE] = { 0 };
    char created_duration[TIME_DURATION_MAX_LEN] = { 0 };

    if (get_created_time_buffer(created, timebuffer, TIME_STR_SIZE) != 0) {
        return;
    }
    if (util_time_format_duration_ago(timebuffer, created_duration, sizeof(created_duration)) != 0) {
        return;
    }
    printf("%-*s", (int)length, created_duration);
}

static void print_basic_container_info_item(const struct isula_container_summary_info *in, const char *status,
                                            const char *name, const struct lengths *length)
{
    if (strcmp(name, "ID") == 0) {
        printf("%-*.*s", (int)length->id_length, (int)length->id_length, in->id ? in->id : "-");
    } else if (strcmp(name, "Image") == 0) {
        printf("%-*s", (int)length->image_length, in->image ? in->image : "none");
    } else if (strcmp(name, "Status") == 0) {
        printf("%-*s", (int)length->status_length, status);
    } else if (strcmp(name, "Pid") == 0) {
        if (in->has_pid) {
            printf("%-*u", (int)length->init_length, in->pid);
        } else {
            printf("%-*s", (int)length->init_length, "-");
        }
    } else if (strcmp(name, "Command") == 0) {
        const char *cmd = (in->command != NULL) ? in->command : "-";
        int cmd_len = (int)strlen(cmd);
        if (cmd_len > COMMAND_LENGTH_MAX - 2) {
            printf("\"%-*.*s...\" ", COMMAND_LENGTH_MAX - 5, COMMAND_LENGTH_MAX - 5, cmd);
        } else {
            int space_len = ((int)(length->command_length) - cmd_len) - 2;
            printf("\"%-*.*s\"%*s", cmd_len, cmd_len, cmd, space_len, (space_len == 0) ? "" : " ");
        }
    } else if (strcmp(name, "Created") == 0) {
        print_created_field(in->created, length->created_length);
    } else if (strcmp(name, "Ports") == 0) {
        printf("%-*s", (int)length->ports_length, "     ");
    }
}

static void print_extern_container_info_item(const struct isula_container_summary_info *in, const char *state,
                                             const char *name, const struct lengths *length)
{
    if (strcmp(name, "ExitCode") == 0) {
        printf("%-*u", (int)length->exit_length, in->exit_code);
    } else if (strcmp(name, "RestartCount") == 0) {
        printf("%-*u", (int)length->rscont_length, in->restart_count);
    } else if (strcmp(name, "StartAt") == 0) {
        char startat_duration[TIME_DURATION_MAX_LEN] = { 0 };
        util_time_format_duration(in->startat, startat_duration, sizeof(startat_duration));
        printf("%-*s", (int)length->startat_length, in->startat ? startat_duration : "-");
    } else if (strcmp(name, "FinishAt") == 0) {
        char finishat_duration[TIME_DURATION_MAX_LEN] = { 0 };
        util_time_format_duration(in->finishat, finishat_duration, sizeof(finishat_duration));
        printf("%-*s", (int)length->finishat_length, in->finishat ? finishat_duration : "-");
    } else if (strcmp(name, "Runtime") == 0) {
        printf("%-*s", (int)length->runtime_length, in->runtime ? in->runtime : "lcr");
    } else if (strcmp(name, "Names") == 0) {
        printf("%-*s", (int)length->name_length, in->name ? in->name : "-");
    } else if (strcmp(name, "State") == 0) {
        printf("%-*s", (int)length->state_length, state);
    }
}
static void print_container_info_item(const struct isula_container_summary_info *in, const char *state,
                                      const char *status, const char *name, const struct lengths *length)
{
    print_basic_container_info_item(in, status, name, length);
    print_extern_container_info_item(in, state, name, length);
}

static void ps_print_container_info(const struct isula_container_summary_info *in, const char *state,
                                    const char *status, const struct lengths *length, const struct format_filters *ff)
{
    size_t i = should_print_table_header(ff) ? 1 : 0;

    for (; i < ff->field_len; i++) {
        if (ff->fields[i]->is_field) {
            print_container_info_item(in, state, status, ff->fields[i]->name, length);
        } else {
            printf_enable_interpretation_of_backslash_escapes(ff->fields[i]->name);
        }
    }
    printf("\n");
}

static void list_print_table(struct isula_container_summary_info **info, const size_t size, struct lengths *length,
                             const struct format_filters *ff)
{
#define MAX_STATE_LEN 32
#define MAX_STATUS_LEN 100
    const struct isula_container_summary_info *in = NULL;
    size_t i = 0;

    char state[MAX_STATE_LEN] = { 0 };
    char status[MAX_STATUS_LEN] = { 0 };
    ps_print_header(length, ff);

    for (i = 0; i < size; i++) {
        in = info[i];
        if (mix_container_state(in, state, sizeof(state))) {
            ERROR("Failed to mix container state");
            return;
        }
        if (mix_container_status(in, status, sizeof(status))) {
            ERROR("Failed to mix container status");
            return;
        }
        ps_print_container_info(in, state, status, length, ff);
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

static void calculate_status_str_length(const struct isula_container_summary_info *in, unsigned int *length)
{
#define MAX_STATUS_LEN 100
    size_t len;
    char status[MAX_STATUS_LEN] = { 0 };
    if (mix_container_status(in, status, sizeof(status))) {
        return;
    }
    len = strlen(status);
    if (len > (*length)) {
        *length = (unsigned int)len;
    }
}

static void calculate_state_str_length(const struct isula_container_summary_info *in, unsigned int *length)
{
    const char *state = NULL;

    state = isula_lcrsta2str(in->status);
    if (state != NULL) {
        size_t len;
        len = strlen(state);
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

    len = snprintf(tmpbuffer, sizeof(tmpbuffer), "%u", data);
    if (len < 0 || (size_t)len >= sizeof(tmpbuffer)) {
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

    if (util_time_format_duration_ago(str, time_duration, sizeof(time_duration)) < 0) {
        ERROR("Format time duration failed");
    }

    len = strlen(time_duration);
    if (len > (*length)) {
        *length = (unsigned int)len;
    }
}

static void calculate_created_str_length(int64_t created, unsigned int *length)
{
    char timebuffer[TIME_STR_SIZE] = { 0 };

    if (get_created_time_buffer(created, timebuffer, TIME_STR_SIZE) != 0) {
        return;
    }

    calculate_time_str_length(timebuffer, length);
}

static void list_field_width(struct isula_container_summary_info **info, const size_t size, struct lengths *l)
{
    size_t i = 0;
    const struct isula_container_summary_info *in = NULL;

    if (info == NULL || l == NULL) {
        return;
    }

    for (i = 0; i < size; i++, in++) {
        in = info[i];
        if (g_cmd_list_args.no_trunc) {
            calculate_str_length(in->id, &l->id_length);
        }
        calculate_str_length(in->image, &l->image_length);
        calculate_created_str_length(in->created, &l->created_length);
        if (in->command != NULL) {
            size_t cmd_len;
            cmd_len = strlen(in->command) + 2;
            if (cmd_len > l->command_length) {
                l->command_length = (unsigned int)cmd_len;
            }
        }

        calculate_str_length(in->name, &l->name_length);
        calculate_str_length(in->runtime, &l->runtime_length);
        calculate_status_str_length(in, &l->status_length);
        calculate_state_str_length(in, &l->state_length);
        if (in->pid != -1) {
            calculate_uint_str_length(in->pid, &l->init_length);
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
static inline int isula_container_cmp(struct isula_container_summary_info **first,
                                      struct isula_container_summary_info **second)
{
    return strcmp((*second)->startat, (*first)->startat);
}

/*
* Create a list request message and call RPC
*/
static int client_list(const struct client_arguments *args, const struct format_filters *ff)
{
    isula_connect_ops *ops = NULL;
    struct isula_list_request request = { 0 };
    struct isula_list_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;
    struct lengths max_len = {
        .id_length = 12, /* CONTAINER ID */
        .image_length = 5, /* IMAGE */
        .command_length = 7, /* COMMAND */
        .created_length = 7, /* CREATED */
        .status_length = 6, /* STATUS */
        .ports_length = 5, /* PORTS */
        .name_length = 5, /* NAMES */

        .state_length = 5, /* STATE */
        .init_length = 3, /* PID */
        .exit_length = 9, /* EXIT_CODE */
        .rscont_length = 13, /* RESTART_COUNT */
        .startat_length = 7, /* STARTAT */
        .finishat_length = 8, /* FINISHAT */
        .runtime_length = 7, /* RUNTIME */
    };

    response = util_common_calloc_s(sizeof(struct isula_list_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.list == NULL) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
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
    request.all = args->list_all;

    if (args->list_last_n > 0 || args->list_latest) {
        size_t lastest_n = args->list_last_n;
        if (args->list_latest) {
            lastest_n = 1;
        }

        isula_filters_last_parse_args(lastest_n, &request.filters);
        if (request.filters == NULL) {
            ERROR("Failed to parse lastest n containers filters args");
            ret = -1;
            goto out;
        }
    }

    config = get_connect_config(args);
    ret = ops->container.list(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

    /* ps -a need sort again, ps -l/-n is already sorted */
    if (response->container_num != 0 && args->list_all) {
        qsort(response->container_summary, (size_t)(response->container_num),
              sizeof(struct isula_container_summary_info *), (int (*)(const void *, const void *))isula_container_cmp);
    }

    if (args->dispname) {
        list_print_quiet(response->container_summary, response->container_num, &max_len);
    } else {
        list_field_width(response->container_summary, response->container_num, &max_len);
        list_print_table(response->container_summary, response->container_num, &max_len, ff);
    }

out:
    isula_filters_free(request.filters);
    isula_list_response_free(response);
    return ret;
}

int cmd_list_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct format_filters *ff = NULL;
    char *format_str = NULL;
    const char *support_field[] = {
        "ID",  "Image",    "Command",      "Created", "Status",   "Ports",   "Names", // basic info
        "Pid", "ExitCode", "RestartCount", "StartAt", "FinishAt", "Runtime", "State" // external info
    };

    if (client_arguments_init(&g_cmd_list_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_list_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf) LIST_OPTIONS(g_cmd_list_args),
               COMMON_OPTIONS(g_cmd_list_args)
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_list_desc,
                 g_cmd_list_usage);
    if (command_parse_args(&cmd, &g_cmd_list_args.argc, &g_cmd_list_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("PS: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_list_args.argc > 0) {
        COMMAND_ERROR("%s: \"ps\" requires 0 arguments.", g_cmd_list_args.progname);
        exit(ECOMMON);
    }

    ff = (struct format_filters *)util_common_calloc_s(sizeof(struct format_filters));
    if (ff == NULL) {
        ERROR("Out of memory");
        exit(EXIT_FAILURE);
    }

    format_str = g_cmd_list_args.format;
    if (format_str == NULL || strcmp(format_str, "table") == 0) {
        format_str = DEFAULT_CONTAINER_TABLE_FORMAT;
    }

    if (get_format_filters_field(format_str, ff, support_field, sizeof(support_field) / sizeof(char *), true) != 0) {
        free_format_filters(ff);
        COMMAND_ERROR("Failed to get filter field");
        exit(EXIT_FAILURE);
    }

    if (client_list(&g_cmd_list_args, ff)) {
        free_format_filters(ff);
        ERROR("Can not ps any containers");
        exit(ECOMMON);
    }

    free_format_filters(ff);
    exit(EXIT_SUCCESS);
}
