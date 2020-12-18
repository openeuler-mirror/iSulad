/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide version function definition
 *********************************************************************************/
#ifndef CLIBCNI_VERSION_VERSION_H
#define CLIBCNI_VERSION_VERSION_H

#include <stdbool.h>
#include "libcni_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CURRENT_VERSION "0.4.0"

struct plugin_info {
    char *cniversion;

    char **supported_versions;
    size_t supported_versions_len;
};

void free_plugin_info(struct plugin_info *pinfo);

struct plugin_info *plugin_supports(const char * const *supported_versions, size_t len);

struct plugin_info *plugin_info_decode(const char *jsonstr);

char *cniversion_decode(const char *jsonstr);

static inline const char *current()
{
    return CURRENT_VERSION;
}

typedef struct result *(*new_result_t)(const char *json_data);

struct result_factories {
    const char **supported_versions;
    new_result_t new_result_op;
};

struct result *new_result(const char *version, const char *jsonstr);

int version_greater_than_or_equal_to(const char *first, const char *second, bool *result);

#ifdef __cplusplus
}
#endif
#endif
