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
#include <ctype.h>
#include <regex.h>
#include <errno.h>
#include "client_arguments.h"
#include "ps.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"

const char g_cmd_list_desc[] = "List containers";
const char g_cmd_list_usage[] = "ps [command options]";

#define COMMAND_LENGTH_MAX 22
#define TIME_DURATION_MAX_LEN 32
#define MAX_TIMESTAMP_LEN 128

struct client_arguments g_cmd_list_args = {
    .dispname = false,
    .list_all = false,
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

struct filter_field {
    char *name;
    bool is_field;
};

struct filters {
    struct filter_field **fields;
    size_t field_len;
};

static void free_filter_field(struct filter_field *field)
{
    if (field == NULL) {
        return;
    }
    free(field->name);
    field->name = NULL;

    free(field);
}

static void free_filters(struct filters *f)
{
    size_t i;
    if (f == NULL) {
        return;
    }
    for (i = 0; i < f->field_len; i++) {
        free_filter_field(f->fields[i]);
        f->fields[i] = NULL;
    }
    free(f->fields);
    f->fields = NULL;
    free(f);
}

static int append_field(struct filters *ff, struct filter_field *field)
{
    struct filter_field **tmp_fields = NULL;
    size_t old_size, new_size;

    if (field == NULL) {
        return 0;
    }

    if (ff->field_len > SIZE_MAX / sizeof(struct filters) - 1) {
        ERROR("Too many filter conditions");
        return -1;
    }

    old_size = ff->field_len * sizeof(struct filters);
    new_size = old_size + sizeof(struct filters);

    if (mem_realloc((void **)(&tmp_fields), new_size, ff->fields, old_size) != 0) {
        ERROR("Out of memory");
        return -1;
    }
    ff->fields = tmp_fields;

    ff->fields[ff->field_len] = field;
    ff->field_len++;

    return 0;
}

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
        nret = snprintf(status, len, "Up %s %s", start_at, in->health_state);
        if (nret < 0 || nret >= len) {
            ERROR("Failed to compose string");
            ret = -1;
            goto out;
        }
    } else {
        nret = snprintf(status, len, "Up %s", start_at);
        if (nret < 0 || nret >= len) {
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
    time_format_duration(in->startat, startat_duration, sizeof(startat_duration));
    time_format_duration_ago(in->finishat, finishat_duration, sizeof(finishat_duration));
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

static bool should_print_table_header(const struct filters *ff)
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

static void ps_print_header(struct lengths *length, const struct filters *ff)
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
    if (!get_time_buffer(&timestamp, timebuffer, len)) {
        ERROR("Failed to get timebuffer from timestamp");
        return -1;
    }

    return 0;
}
static void print_created_field(int64_t created, unsigned int length)
{
    char timebuffer[MAX_TIMESTAMP_LEN] = { 0 };
    char created_duration[TIME_DURATION_MAX_LEN] = { 0 };

    if (get_created_time_buffer(created, timebuffer, MAX_TIMESTAMP_LEN) != 0) {
        return;
    }
    if (time_format_duration_ago(timebuffer, created_duration, sizeof(created_duration)) != 0) {
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
        time_format_duration(in->startat, startat_duration, sizeof(startat_duration));
        printf("%-*s", (int)length->startat_length, in->startat ? startat_duration : "-");
    } else if (strcmp(name, "FinishAt") == 0) {
        char finishat_duration[TIME_DURATION_MAX_LEN] = { 0 };
        time_format_duration(in->finishat, finishat_duration, sizeof(finishat_duration));
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
                                    const char *status, const struct lengths *length, const struct filters *ff)
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
                             const struct filters *ff)
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

    if (time_format_duration_ago(str, time_duration, sizeof(time_duration)) < 0) {
        ERROR("Format time duration failed");
    }

    len = strlen(time_duration);
    if (len > (*length)) {
        *length = (unsigned int)len;
    }
}

static void calculate_created_str_length(int64_t created, unsigned int *length)
{
    char timebuffer[MAX_TIMESTAMP_LEN] = { 0 };

    if (get_created_time_buffer(created, timebuffer, MAX_TIMESTAMP_LEN) != 0) {
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
static int client_list(const struct client_arguments *args, const struct filters *ff)
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

    config = get_connect_config(args);
    ret = ops->container.list(&request, response, &config);
    if (ret) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }
    if (response->container_num != 0)
        qsort(response->container_summary, (size_t)(response->container_num),
              sizeof(struct isula_container_summary_info *), (int (*)(const void *, const void *))isula_container_cmp);

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

static int append_header_field(const char **index, struct filters *ff)
{
    int ret = 0;
    struct filter_field *tmp = NULL;

    if (strncmp(*index, "table", strlen("table")) != 0) {
        return 0;
    }

    tmp = (struct filter_field *)util_common_calloc_s(sizeof(struct filter_field));
    if (tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp->name = util_strdup_s("table");
    tmp->is_field = true;
    if (append_field(ff, tmp) != 0) {
        ret = -1;
        goto out;
    }
    *index += strlen("table");
    tmp = NULL;

out:
    free_filter_field(tmp);
    return ret;
}

static int append_first_non_header_field(const char *index, struct filters *ff)
{
    int ret = 0;
    char *prefix = strstr(index, "{{");
    struct filter_field *tmp = NULL;
    char *first_non_field = NULL;

    if (prefix == NULL) {
        return 0;
    }

    first_non_field = util_sub_string(index, 0, prefix - index);
    if (util_is_space_string(first_non_field)) {
        goto out;
    }
    tmp = (struct filter_field *)util_common_calloc_s(sizeof(struct filter_field));
    if (tmp == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    tmp->name = first_non_field;
    tmp->is_field = false;
    if (append_field(ff, tmp) != 0) {
        ERROR("Failed to append field");
        ret = -1;
        goto out;
    }
    tmp = NULL;
    first_non_field = NULL;

out:
    free_filter_field(tmp);
    free(first_non_field);
    return ret;
}

static int get_header_field(const char *patten, struct filters *ff)
{
    const char *index = patten;

    if (append_header_field(&index, ff) != 0) {
        ERROR("Failed to append header field");
        return -1;
    }

    if (append_first_non_header_field(index, ff) != 0) {
        ERROR("Failed to append first non header field");
        return -1;
    }

    return 0;
}

static int format_field_check(const char *source, const char *patten)
{
#define MATCH_NUM 1
#define CHECK_FAILED (-1)
    int status = 0;
    regmatch_t pmatch[MATCH_NUM] = { { 0 } };
    regex_t reg;

    if (source == NULL) {
        ERROR("Filter string is NULL.");
        return CHECK_FAILED;
    }

    regcomp(&reg, patten, REG_EXTENDED);

    status = regexec(&reg, source, MATCH_NUM, pmatch, 0);
    regfree(&reg);

    if (status != 0) {
        return CHECK_FAILED;
    }

    return 0;
}

/* arg string format: "{{json .State.Running}}"
 * ret_string should be free outside by free().
 */
static char *get_filter_string(const char *arg)
{
    char *input_str = NULL;
    char *p = NULL;
    char *ret_string = NULL;
    char *next_context = NULL;

    input_str = util_strdup_s(arg);

    p = strtok_r(input_str, ".", &next_context);
    if (p == NULL) {
        goto out;
    }

    p = next_context;
    if (p == NULL) {
        goto out;
    }

    p = strtok_r(p, " }", &next_context);
    if (p == NULL) {
        goto out;
    }

    ret_string = util_strdup_s(p);

out:
    free(input_str);
    return ret_string;
}

static bool valid_format_field(const char *field)
{
    size_t i;
    const char *support_field[] = {
        "ID",  "Image",    "Command",      "Created", "Status",   "Ports",   "Names", // basic info
        "Pid", "ExitCode", "RestartCount", "StartAt", "FinishAt", "Runtime", "State" // external info
    };

    for (i = 0; i < sizeof(support_field) / sizeof(char *); i++) {
        if (strcmp(field, support_field[i]) == 0) {
            return true;
        }
    }

    return false;
}

static int append_header_item_field(const char *index, const char *prefix, const char *suffix, struct filters *ff)
{
#define SINGLE_PATTEN "\\{\\{\\s*\\.\\w+\\s*\\}\\}"
    int ret = 0;
    char *filter_string = NULL;
    struct filter_field *field = NULL;
    char *sub_patten = util_sub_string(index, prefix - index, suffix - prefix + 2);

    if (format_field_check(sub_patten, SINGLE_PATTEN) != 0) {
        COMMAND_ERROR("invalid format field: %s", sub_patten);
        ret = -1;
        goto out;
    }

    filter_string = get_filter_string(sub_patten);
    if (filter_string == NULL) {
        ERROR("Invalid filter: %s", sub_patten);
        ret = -1;
        goto out;
    }

    field = (struct filter_field *)util_common_calloc_s(sizeof(struct filter_field));
    if (field == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (!valid_format_field(filter_string)) {
        COMMAND_ERROR("--format not support the field: %s", filter_string);
        ret = -1;
        goto out;
    }
    field->name = filter_string;
    field->is_field = true;
    if (append_field(ff, field) != 0) {
        ERROR("Failed to append field");
        ret = -1;
        goto out;
    }

    field = NULL;
    filter_string = NULL;

out:
    free(sub_patten);
    free(filter_string);
    free_filter_field(field);
    return ret;
}

static int append_non_header_item_field(const char *prefix, const char *non_field, struct filters *ff)
{
    int ret = 0;
    char *non_field_string = NULL;
    struct filter_field *field = NULL;

    if (prefix == NULL) {
        non_field_string = util_strdup_s(non_field);
    } else {
        non_field_string = util_sub_string(non_field, 0, prefix - non_field);
    }
    field = (struct filter_field *)util_common_calloc_s(sizeof(struct filter_field));
    if (field == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    field->name = non_field_string;
    field->is_field = false;
    if (append_field(ff, field) != 0) {
        ERROR("Failed to append field");
        ret = -1;
        goto out;
    }
    non_field_string = NULL;
    field = NULL;

out:
    free_filter_field(field);
    free(non_field_string);
    return ret;
}

static int get_filter_field(const char *patten, struct filters *ff)
{
#define SINGLE_PATTEN "\\{\\{\\s*\\.\\w+\\s*\\}\\}"
#define DEFAULT_CONTAINER_TABLE_FORMAT          \
    "table {{.ID}}\t{{.Image}}\t{{.Command}}\t" \
    "{{.Created}}\t{{.Status}}\t{{.Ports}}\t{{.Names}}"
    const char *prefix = NULL;
    const char *suffix = NULL;
    const char *index = patten;

    if (patten == NULL || strcmp(index, "table") == 0) {
        index = DEFAULT_CONTAINER_TABLE_FORMAT;
    }

    if (get_header_field(index, ff) != 0) {
        ERROR("failed to get header field");
        return -1;
    }
    prefix = strstr(index, "{{");
    if (prefix == NULL) {
        return 0;
    }

    suffix = strstr(index, "}}");
    while (prefix != NULL && suffix != NULL) {
        if (append_header_item_field(index, prefix, suffix, ff) != 0) {
            ERROR("failed to append header item field");
            return -1;
        }
        if (strlen(suffix + 2) == 0) {
            return 0;
        }
        prefix = strstr(suffix + 2, "{{");
        if (append_non_header_item_field(prefix, suffix + 2, ff) != 0) {
            ERROR("failed to append non-header item field");
            return -1;
        }

        index = prefix;
        if (index != NULL) {
            suffix = strstr(index, "}}");
        } else {
            suffix = NULL;
        }
    }

    return 0;
}

int cmd_list_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct filters *ff = NULL;

    if (client_arguments_init(&g_cmd_list_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_list_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf), LIST_OPTIONS(g_cmd_list_args),
               COMMON_OPTIONS(g_cmd_list_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_list_desc,
                 g_cmd_list_usage);
    if (command_parse_args(&cmd, &g_cmd_list_args.argc, &g_cmd_list_args.argv)) {
        exit(EINVALIDARGS);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("PS: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_list_args.argc > 0) {
        COMMAND_ERROR("%s: \"ps\" requires 0 arguments.", g_cmd_list_args.progname);
        exit(ECOMMON);
    }

    ff = (struct filters *)util_common_calloc_s(sizeof(struct filters));
    if (ff == NULL) {
        ERROR("Out of memory");
        exit(EXIT_FAILURE);
    }

    if (get_filter_field(g_cmd_list_args.format, ff) != 0) {
        free_filters(ff);
        COMMAND_ERROR("Failed to get filter field");
        exit(EXIT_FAILURE);
    }

    if (client_list(&g_cmd_list_args, ff)) {
        free_filters(ff);
        ERROR("Can not ps any containers");
        exit(ECOMMON);
    }

    free_filters(ff);
    exit(EXIT_SUCCESS);
}
