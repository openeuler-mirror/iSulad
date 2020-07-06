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
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide typedef functions definition
 ********************************************************************************/
#ifndef _TYPES_DEF_H_
#define _TYPES_DEF_H_

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

struct tm;

#ifdef __cplusplus
extern "C" {
#endif

typedef struct types_timestamp {
    bool has_seconds;
    int64_t seconds;
    bool has_nanos;
    int32_t nanos;
} types_timestamp_t;

struct types_timezone {
    int hour;
    int min;
};

bool unix_nanos_to_timestamp(int64_t nanos, types_timestamp_t *timestamp);

int64_t time_seconds_since(const char *in);

int types_timestamp_cmp(const types_timestamp_t *t1, const types_timestamp_t *t2);

bool get_timestamp(const char *str_time, types_timestamp_t *timestamp);

bool get_time_buffer(const types_timestamp_t *timestamp, char *timebuffer, size_t maxsize);

bool get_now_time_stamp(types_timestamp_t *timestamp);

bool get_now_local_utc_time_buffer(char *timebuffer, size_t maxsize);

bool get_now_time_buffer(char *timebuffer, size_t maxsize);

int get_time_interval(types_timestamp_t first, types_timestamp_t last, int64_t *result);

int to_unix_nanos_from_str(const char *str, int64_t *nanos);

bool parsing_time(const char *format, const char *time, struct tm *tm, int32_t *nanos);

bool fix_date(struct tm *tm);

bool get_tm_from_str(const char *str, struct tm *tm, int32_t *nanos);

int time_format_duration(const char *in, char *out, size_t len);

int time_format_duration_ago(const char *in, char *out, size_t len);

int64_t get_now_time_nanos();
#ifdef __cplusplus
}
#endif

#endif

