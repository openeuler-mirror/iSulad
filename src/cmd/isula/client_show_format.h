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
 * Description: provide format function definition
 ******************************************************************************/
#ifndef CMD_ISULA_CLIENT_SHOW_FORMAT_H
#define CMD_ISULA_CLIENT_SHOW_FORMAT_H

#include <stdbool.h>
#include <stdio.h>

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

struct filters_field {
    char *name;
    bool is_field;
};

struct format_filters {
    struct filters_field **fields;
    size_t field_len;
};

void free_format_filters(struct format_filters *f);

int format_filters_field_check(const char *source, const char *patten);

bool valid_format_filters_field(const char *field, const char **support_field, size_t len);

int append_format_filters_field(struct format_filters *format, struct filters_field *field);

int get_format_filters_field(const char *patten, struct format_filters *format, const char **support_field, size_t len,
                             bool has_non_header);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif // CMD_ISULA_CLIENT_SHOW_FORMAT_H

