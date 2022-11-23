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
 * Create: 2022-11-06
 * Description: provide format functions
 ******************************************************************************/
#include "client_show_format.h"

#include <regex.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "template_string_parse.h"

#ifdef __ANDROID__
#define SINGLE_PATTEN "{{[ \t\r\n\v\f]*\\.[0-9A-Za-z_]+[ \t\r\n\v\f]*}}"
#else
#define SINGLE_PATTEN "\\{\\{\\s*\\.\\w+\\s*\\}\\}"
#endif

static void free_filter_field(struct filters_field *field)
{
    if (field == NULL) {
        return;
    }
    free(field->name);
    field->name = NULL;

    free(field);
}

static int append_header_field(const char **index, struct format_filters *format)
{
    int ret = 0;
    struct filters_field *tmp = NULL;

    tmp = (struct filters_field *)util_common_calloc_s(sizeof(struct filters_field));
    if (tmp == NULL) {
        ERROR("Out of memory");
        return -1;
    }
    tmp->name = util_strdup_s("table");
    tmp->is_field = true;
    if (append_format_filters_field(format, tmp) != 0) {
        ret = -1;
        goto out;
    }
    *index += strlen("table");
    tmp = NULL;

out:
    free_filter_field(tmp);
    return ret;
}

static int append_first_non_header_field(const char *index, struct format_filters *format)
{
    int ret = 0;
    char *prefix = strstr(index, "{{");
    struct filters_field *tmp = NULL;
    char *first_non_field = NULL;

    if (prefix == NULL) {
        return 0;
    }

    first_non_field = util_sub_string(index, 0, prefix - index);
    if (util_is_space_string(first_non_field)) {
        goto out;
    }
    tmp = (struct filters_field *)util_common_calloc_s(sizeof(struct filters_field));
    if (tmp == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    tmp->name = first_non_field;
    first_non_field = NULL;
    tmp->is_field = false;
    if (append_format_filters_field(format, tmp) != 0) {
        ERROR("Failed to append field");
        ret = -1;
        goto out;
    }
    tmp = NULL;

out:
    free_filter_field(tmp);
    free(first_non_field);
    return ret;
}

static int append_header_item_field(char *sub_patten, struct format_filters *format, const char **support_field,
                                    size_t len)
{
    int ret = 0;
    char *filter_string = NULL;
    struct filters_field *field = NULL;

    if (format_filters_field_check(sub_patten, SINGLE_PATTEN) != 0) {
        COMMAND_ERROR("invalid format field: %s", sub_patten);
        ret = -1;
        goto out;
    }

    filter_string = parse_single_template_string(sub_patten);
    if (filter_string == NULL) {
        ERROR("Invalid filter: %s", sub_patten);
        ret = -1;
        goto out;
    }

    field = (struct filters_field *)util_common_calloc_s(sizeof(struct filters_field));
    if (field == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    if (!valid_format_filters_field(filter_string, support_field, len)) {
        COMMAND_ERROR("--format not support the field: %s", filter_string);
        ret = -1;
        goto out;
    }
    field->name = filter_string;
    filter_string = NULL;
    field->is_field = true;
    if (append_format_filters_field(format, field) != 0) {
        ERROR("Failed to append field");
        ret = -1;
        goto out;
    }
    field = NULL;

out:
    free(filter_string);
    free_filter_field(field);
    return ret;
}

static int append_non_header_item_field(const char *prefix, const char *non_field, struct format_filters *format)
{
    int ret = 0;
    char *non_field_string = NULL;
    struct filters_field *field = NULL;

    if (prefix == NULL) {
        non_field_string = util_strdup_s(non_field);
    } else {
        non_field_string = util_sub_string(non_field, 0, prefix - non_field);
    }
    field = (struct filters_field *)util_common_calloc_s(sizeof(struct filters_field));
    if (field == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    field->name = non_field_string;
    non_field_string = NULL;
    field->is_field = false;

    if (append_format_filters_field(format, field) != 0) {
        ERROR("Failed to append field");
        ret = -1;
        goto out;
    }
    field = NULL;

out:
    free_filter_field(field);
    free(non_field_string);
    return ret;
}

static int get_header_field(const char *patten, struct format_filters *ff)
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

void free_format_filters(struct format_filters *f)
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

int format_filters_field_check(const char *source, const char *patten)
{
    int status = 0;

    if (source == NULL || patten == NULL) {
        ERROR("Filter string or pattern is NULL.");
        return -1;
    }

    status = util_reg_match(patten, source);
    if (status != 0) {
        ERROR("Output format error, E.g \"{{.Name}}\" is right.");
        return -1;
    }

    return 0;
}

bool valid_format_filters_field(const char *field, const char **support_field, size_t len)
{
    size_t i;

    if (field == NULL || support_field == NULL) {
        return false;
    }

    for (i = 0; i < len; i++) {
        if (strcmp(field, support_field[i]) == 0) {
            return true;
        }
    }

    return false;
}

int append_format_filters_field(struct format_filters *format, struct filters_field *field)
{
    struct filters_field **tmp_fields = NULL;
    size_t old_size, new_size;


    if (format == NULL || field == NULL) {
        ERROR("NULL format or field");
        return -1;
    }

    if (format->field_len > SIZE_MAX / sizeof(struct format_filters) - 1) {
        ERROR("Too many filter conditions");
        return -1;
    }

    old_size = format->field_len * sizeof(struct format_filters);
    new_size = old_size + sizeof(struct format_filters);

    if (util_mem_realloc((void **)(&tmp_fields), new_size, format->fields, old_size) != 0) {
        ERROR("Out of memory");
        return -1;
    }

    format->fields = tmp_fields;
    format->fields[format->field_len] = field;
    format->field_len++;

    return 0;
}

int get_format_filters_field(const char *patten, struct format_filters *format, const char **support_field, size_t len,
                             bool has_non_header)
{
    int ret;
    const char *prefix = NULL;
    const char *suffix = NULL;
    const char *index = patten;
    char *sub_patten = NULL;

    if (patten == NULL ||  format == NULL || support_field == NULL) {
        ERROR("Null argument");
        return -1;
    }

    if (has_non_header) {
        ret = get_header_field(index, format);
    } else {
        ret = append_header_field(&index, format);
    }

    if (ret != 0) {
        ERROR("Failed to get header field");
        return -1;
    }
    prefix = strstr(index, "{{");
    if (prefix == NULL) {
        return 0;
    }

    suffix = strstr(index, "}}");
    while (prefix != NULL && suffix != NULL) {
        sub_patten = util_sub_string(index, prefix - index, suffix - prefix + 2);
        if (append_header_item_field(sub_patten, format, support_field, len) != 0) {
            ERROR("failed to append header item field");
            free(sub_patten);
            return -1;
        }
        free(sub_patten);
        sub_patten = NULL;

        if (strlen(suffix + 2) == 0) {
            return 0;
        }
        prefix = strstr(suffix + 2, "{{");

        if (has_non_header && append_non_header_item_field(prefix, suffix + 2, format) != 0) {
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
