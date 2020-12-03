/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2020-11-13
 * Description: provide log options parse function
 ******************************************************************************/
#ifndef CMD_OPTIONS_LOG_H
#define CMD_OPTIONS_LOG_H

#include <stdbool.h>
#include <isula_libutils/json_common.h>

#ifdef __cplusplus
extern "C" {
#endif

bool check_raw_log_opt(const char *key);

bool check_opt_container_log_opt(const char *driver, const char *opt);

bool check_opt_container_log_driver(const char *driver);

bool parse_container_log_opt(const char *key, const char *val, json_map_string_string *opts);

bool parse_container_log_opts(json_map_string_string **opts);

#ifdef __cplusplus
}
#endif

#endif
