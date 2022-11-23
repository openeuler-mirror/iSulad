/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-10-17
 * Description: provide search image
 ********************************************************************************/
#include "search.h"

#include <stdio.h>
#include <stdlib.h>
#include <isula_libutils/log.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "command_parser.h"
#include "connect.h"
#include "client_show_format.h"

const char g_cmd_search_desc[] = "Search the registry for images";
const char g_cmd_search_usage[] = "search [OPTIONS] TERM";
#define DEFAULT_LIMIT 25
#define DEFAULT_SEARCH_TABLE_FORMAT                \
    "table {{.Name}}\t{{.Description}}\t{{.StarCount}}\t" \
    "{{.IsOfficial}}\t{{.IsAutomated}}"

struct client_arguments g_cmd_search_args = {
    .search_name = NULL,
    .limit = DEFAULT_LIMIT,
    .filters = NULL,
    .no_trunc = false,
    .format = NULL,
};

/* keep track of field widths for printing. */
struct show_search_result_lengths {
    unsigned int name_length;
    unsigned int descreption_length;
    unsigned int stars_length;
    unsigned int official_length;
    unsigned int automated_length;
    unsigned int space_length;
};

// set default print length for show_search_result_lengths.
const unsigned int name_len = 24;
const unsigned int descreption_len = 48;
const unsigned int stars_len = 6;
const unsigned int official_len = 9;
const unsigned int automated_len = 10;
const unsigned int space_len = 4;

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

static void calculate_uint_length(uint32_t data, unsigned int *length)
{
    char *temp = NULL;
    size_t temp_len;

    temp = util_uint_to_string(data);
    if (temp == NULL) {
        DEBUG("Uint to string failed");
        return;
    }

    temp_len = strlen(temp);
    if (temp_len > (*length)) {
        *length = (unsigned int)temp_len;
    }

    free(temp);
}

static void search_field_width(const struct search_image_info *info, const size_t size,
                               struct show_search_result_lengths *lens)
{
    size_t i = 0;
    const struct search_image_info *tmp = info;

    for (i = 0; i < size; i++, tmp++) {
        calculate_str_length(tmp->name, &lens->name_length);
        if (g_cmd_search_args.no_trunc) {
            calculate_str_length(tmp->description, &lens->descreption_length);
        }
        calculate_uint_length(tmp->star_count, &lens->stars_length);
    }
}

static void print_table_header_item(const char *name, struct show_search_result_lengths *length)
{
    if (strcmp(name, "Name") == 0) {
        printf("%-*.*s", (int)length->name_length, (int)length->name_length, "NAME");
    } else if (strcmp(name, "Description") == 0) {
        printf("%-*.*s", (int)length->descreption_length, (int)length->descreption_length, "DESCRIPTION");
    } else if (strcmp(name, "StarCount") == 0) {
        printf("%-*.*s", (int)length->stars_length, (int)length->stars_length, "STARS");
    } else if (strcmp(name, "IsOfficial") == 0) {
        printf("%-*.*s", (int)length->official_length, (int)length->official_length, "OFFICIAL");
    } else if (strcmp(name, "IsAutomated") == 0) {
        printf("%-*.*s", (int)length->automated_length, (int)length->automated_length, "AUTOMATED");
    }
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
        if (*s == '\0' || ch != '\\') {
            continue;
        }

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
        putchar(ch);
        ch = *s++;
    }
}

static bool should_print_table_header(const struct format_filters *format)
{
    return format != NULL && format->field_len != 0 && format->fields[0]->name != NULL &&
           strcmp(format->fields[0]->name, "table") == 0 && format->fields[0]->is_field;
}

static void search_print_header(struct show_search_result_lengths *length, const struct format_filters *format)
{
    size_t i;

    if (!should_print_table_header(format)) {
        return;
    }

    for (i = 1; i < format->field_len; i++) {
        if (format->fields[i]->is_field) {
            print_table_header_item(format->fields[i]->name, length);
            printf("%-*.*s", (int)length->space_length, (int)length->space_length, "  ");
        } else {
            printf_enable_interpretation_of_backslash_escapes(format->fields[i]->name);
        }
    }
    printf("\n");
}

static void print_search_image_info_item(const struct search_image_info *in, const char *name,
                                         const struct show_search_result_lengths *length)
{
    int temp_len;
    if (strcmp(name, "Name") == 0) {
        printf("%-*.*s", (int)length->name_length, (int)length->name_length, in->name ? in->name : "<none>");
    } else if (strcmp(name, "Description") == 0) {
        if (length->descreption_length < strlen(in->description)) {
            temp_len = (int)length->descreption_length - (int)length->space_length;
            printf("%-*.*s", temp_len, temp_len, in->description ? in->description : " ");
            printf("%-*.*s", (int)length->space_length, (int)length->space_length, in->description ? "..." : "  ");
            return;
        }
        printf("%-*.*s", (int)length->descreption_length, (int)length->descreption_length,
               in->description ? in->description : " ");
    } else if (strcmp(name, "StarCount") == 0) {
        printf("%-*u", (int)length->stars_length, in->star_count);
    } else if (strcmp(name, "IsOfficial") == 0) {
        printf("%-*.*s", (int)length->official_length, (int)length->official_length, in->is_official ? "[OK]" : " ");
    } else if (strcmp(name, "IsAutomated") == 0) {
        printf("%-*.*s", (int)length->automated_length, (int)length->automated_length, in->is_automated ? "[OK]" : " ");
    }
}

static void search_print_search_image_info(const struct search_image_info *in,
                                           const struct show_search_result_lengths *length,
                                           const struct format_filters *format)
{
    size_t i;
    i = should_print_table_header(format) ? 1 : 0;

    for (; i < format->field_len; i++) {
        if (format->fields[i]->is_field) {
            print_search_image_info_item(in, format->fields[i]->name, length);
            printf("%-*.*s", (int)length->space_length, (int)length->space_length, "  ");
        } else {
            printf_enable_interpretation_of_backslash_escapes(format->fields[i]->name);
        }
    }
    printf("\n");
}

static void search_print_table(struct search_image_info *info, const size_t size,
                               struct show_search_result_lengths *length,
                               const struct format_filters *format)
{
    const struct search_image_info *tmp = NULL;
    size_t i = 0;

    search_print_header(length, format);

    tmp = info;
    for (i = 0; i < size; i++, tmp++) {
        search_print_search_image_info(tmp, length, format);
    }
}

static inline int isula_search_cmp(struct search_image_info *first, struct search_image_info *second)
{
    if (second->star_count > first->star_count) {
        return 1;
    }
    return -1;
}

int client_search(const struct client_arguments *args, const struct format_filters *format)
{
    isula_connect_ops *ops = NULL;
    struct isula_search_request request = { 0 };
    struct isula_search_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;
    struct show_search_result_lengths max_len = {
        .name_length = name_len,
        .descreption_length = descreption_len,
        .stars_length = stars_len,
        .official_length = official_len,
        .automated_length = automated_len,
        .space_length = space_len,
    };

    response = util_common_calloc_s(sizeof(struct isula_search_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    request.search_name = util_strdup_s(args->search_name);
    request.limit = args->limit;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->image.search == NULL) {
        ERROR("Unimplemented search ops");
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

    config = get_connect_config(args);
    ret = ops->image.search(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = -1;
        goto out;
    }

    if (response->search_result != NULL && response->result_num > 0) {
        qsort(response->search_result, (size_t)(response->result_num), sizeof(struct search_image_info),
              (int (*)(const void *, const void *))isula_search_cmp);
    }

    search_field_width(response->search_result, response->result_num, &max_len);
    search_print_table(response->search_result, response->result_num, &max_len, format);

out:
    isula_search_response_free(response);
    return ret;
}

int cmd_search_main(int argc, const char **argv)
{
    command_t cmd;
    struct isula_libutils_log_config lconf = { 0 };
    struct format_filters *format = NULL;
    char *format_str = NULL;
    struct command_option options[] = { LOG_OPTIONS(lconf) SEARCH_OPTIONS(g_cmd_search_args)
        COMMON_OPTIONS(g_cmd_search_args)
    };
    const char *support_field[] = {
        "Name", "Description", "StarCount", "IsOfficial", "IsAutomated",
    };

    if (client_arguments_init(&g_cmd_search_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }

    g_cmd_search_args.progname = argv[0];
    isula_libutils_default_log_config(argv[0], &lconf);

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_search_desc,
                 g_cmd_search_usage);

    if (command_parse_args(&cmd, &g_cmd_search_args.argc, &g_cmd_search_args.argv)) {
        exit(EINVALIDARGS);
    }

    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Search: log init failed");
        exit(ECOMMON);
    }

    if (g_cmd_search_args.argc != 1) {
        COMMAND_ERROR("Search requires 1 argument.");
        exit(EINVALIDARGS);
    }

    g_cmd_search_args.search_name = g_cmd_search_args.argv[0];

    if (g_cmd_search_args.limit < 0 || g_cmd_search_args.limit > MAX_LIMIT) {
        COMMAND_ERROR("Limit %d is outside the range of [1, 100]", g_cmd_search_args.limit);
        exit(EINVALIDARGS);
    }

    if (g_cmd_search_args.limit == 0) {
        g_cmd_search_args.limit = DEFAULT_LIMIT;
    }

    format = (struct format_filters *)util_common_calloc_s(sizeof(struct format_filters));
    if (format == NULL) {
        ERROR("Out of memory");
        exit(EXIT_FAILURE);
    }

    format_str = g_cmd_search_args.format;
    if (format_str == NULL || strcmp(format_str, "table") == 0) {
        format_str = DEFAULT_SEARCH_TABLE_FORMAT;
    }

    if (get_format_filters_field(format_str, format, support_field, sizeof(support_field) / sizeof(char *), false) != 0) {
        free_format_filters(format);
        COMMAND_ERROR("Failed to get valid format");
        exit(EXIT_FAILURE);
    }

    if (client_search(&g_cmd_search_args, format) != 0) {
        COMMAND_ERROR("Search %s error", g_cmd_search_args.search_name);
        free_format_filters(format);
        exit(ECOMMON);
    }

    free_format_filters(format);
    exit(EXIT_SUCCESS);
}
