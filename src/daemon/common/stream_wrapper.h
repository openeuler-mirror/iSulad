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
 * Author: lifeng
 * Create: 2020-06-08
 * Description: provide container isulad definition
 ******************************************************************************/
#ifndef DAEMON_COMMON_STREAM_WRAPPER_H
#define DAEMON_COMMON_STREAM_WRAPPER_H

#include <stdbool.h>
#include <stdint.h>
#include "utils_timestamp.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef bool (*stream_check_call_cancelled)(void *context);
typedef bool (*stream_write_fun_t)(void *writer, void *data);
typedef bool (*stream_read_fun_t)(void *reader, void *data);
typedef bool (*stream_add_initial_metadata_fun_t)(void *context, const char *header, const char *val);

typedef struct {
    void *context;
    stream_check_call_cancelled is_cancelled;
    stream_add_initial_metadata_fun_t add_initial_metadata;
    void *writer;
    stream_write_fun_t write_func;
    void *reader;
    stream_read_fun_t read_func;
} stream_func_wrapper;

#ifdef __cplusplus
}
#endif

#endif
