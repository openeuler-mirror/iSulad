/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
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
 * Description: provide result function definition
 ********************************************************************************/
#ifndef CLIBCNI_TYPES_CURRENT_H
#define CLIBCNI_TYPES_CURRENT_H

#include "libcni_result_type.h"
#include "isula_libutils/cni_result_curr.h"

typedef struct cni_opt_result *(*new_result_t)(const char *json_data);

struct cni_opt_result_factories {
    const char **supported_versions;
    new_result_t new_result_op;
};

struct cni_opt_result *new_result(const char *version, const char *jsonstr);

struct cni_opt_result *new_curr_result(const char *json_data);

cni_result_curr *cni_result_curr_to_json_result(const struct cni_opt_result *src);

struct cni_opt_result *copy_result_from_current(const cni_result_curr *curr_result);

#endif
