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
 * Create: 2020-09-28
 * Description: provide ulimit options parse function
 ******************************************************************************/
#ifndef CMD_OPTIONS_ULIMIT_H
#define CMD_OPTIONS_ULIMIT_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "isula_libutils/host_config.h"

#ifdef __cplusplus
extern "C" {
#endif

int check_opt_ulimit_type(const char *type);
host_config_ulimits_element *parse_opt_ulimit(const char *val);

#ifdef __cplusplus
}
#endif

#endif
