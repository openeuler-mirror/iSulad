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

struct plugin_info *plugin_supports(const char * const *supported_versions, size_t len, char **errmsg);

struct plugin_info *plugin_info_decode(const char *jsonstr, char **errmsg);

char *cniversion_decode(const char *jsonstr, char **errmsg);

static inline const char *current()
{
    return CURRENT_VERSION;
}

typedef struct result *(*new_result_t)(const char *json_data, char **err);

struct result_factories {
    const char **supported_versions;
    new_result_t new_result_op;
};

struct result *new_result(const char *version, const char *jsonstr, char **err);

#ifdef __cplusplus
}
#endif
#endif
