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
#ifndef UTILS_CUTILS_UTILS_TIMESTAMP_H
#define UTILS_CUTILS_UTILS_TIMESTAMP_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

struct tm;

#ifdef __cplusplus
extern "C" {
#endif

#define Time_Nano 1LL
#define Time_Micro (1000LL * Time_Nano)
#define Time_Milli (1000LL * Time_Micro)
#define Time_Second (1000LL * Time_Milli)
#define Time_Minute (60LL * Time_Second)
#define Time_Hour (60LL * Time_Minute)

#define rFC339Local "2006-01-02T15:04:05"
#define rFC339NanoLocal "2006-01-02T15:04:05.999999999"
#define dateLocal "2006-01-02"
#define defaultContainerTime "0001-01-01T00:00:00Z"

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

int64_t util_time_seconds_since(const char *in);

int util_types_timestamp_cmp(const types_timestamp_t *t1, const types_timestamp_t *t2);

bool util_get_timestamp(const char *str_time, types_timestamp_t *timestamp);

bool util_get_time_buffer(const types_timestamp_t *timestamp, char *timebuffer, size_t maxsize);

bool util_get_now_time_stamp(types_timestamp_t *timestamp);

bool util_get_now_local_utc_time_buffer(char *timebuffer, size_t maxsize);

bool util_get_now_time_buffer(char *timebuffer, size_t maxsize);

int util_get_time_interval(types_timestamp_t first, types_timestamp_t last, int64_t *result);

int util_to_unix_nanos_from_str(const char *str, int64_t *nanos);

bool util_parsing_time(const char *format, const char *time, struct tm *tm, int32_t *nanos);

bool util_fix_date(struct tm *tm);

bool util_get_tm_from_str(const char *str, struct tm *tm, int32_t *nanos);

int util_time_format_duration(const char *in, char *out, size_t len);

int util_time_format_duration_ago(const char *in, char *out, size_t len);

types_timestamp_t util_to_timestamp_from_str(const char *str);

int util_time_str_to_nanoseconds(const char *value, int64_t *nanoseconds);

int64_t util_get_now_time_nanos();
#ifdef __cplusplus
}
#endif

#endif
