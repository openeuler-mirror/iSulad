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
 * Description: provide typedef  functions
 ********************************************************************************/
#include "utils_timestamp.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#include "isula_libutils/log.h"
#include "utils.h"

bool unix_nanos_to_timestamp(int64_t nanos, types_timestamp_t *timestamp)
{
    if (timestamp == NULL) {
        return false;
    }
    timestamp->has_seconds = true;
    timestamp->seconds = nanos / Time_Second;
    timestamp->has_nanos = true;
    timestamp->nanos = nanos % Time_Second;

    return true;
}

int types_timestamp_cmp_check(const types_timestamp_t *t1, const types_timestamp_t *t2)
{
    if (t1 == NULL && t2 == NULL) {
        return 0;
    }
    if (t1 != NULL && t2 == NULL) {
        return 1;
    }
    if (t1 == NULL && t2 != NULL) {
        return -1;
    }

    return 2;
}

int types_timestamp_cmp_nanos(const types_timestamp_t *t1, const types_timestamp_t *t2)
{
    if (t1->has_nanos && t2->has_nanos) {
        if (t1->nanos > t2->nanos) {
            return 1;
        }
        if (t1->nanos < t2->nanos) {
            return -1;
        }
        return 0;
    }
    if (t1->has_nanos) {
        return 1;
    }

    if (t2->has_nanos) {
        return -1;
    }

    return 0;
}

/* types timestamp cmp */
int types_timestamp_cmp(const types_timestamp_t *t1, const types_timestamp_t *t2)
{
    int ret = 0;

    ret = types_timestamp_cmp_check(t1, t2);
    if (ret != 2) {
        return ret;
    }

    if (t1->has_seconds && t2->has_seconds) {
        if (t1->seconds > t2->seconds) {
            return 1;
        }
        if (t1->seconds < t2->seconds) {
            return -1;
        }
        return types_timestamp_cmp_nanos(t1, t2);
    }

    if (t1->has_seconds) {
        return 1;
    }
    if (t2->has_seconds) {
        return -1;
    }
    return 0;
}

/* get timestamp */
bool get_timestamp(const char *str_time, types_timestamp_t *timestamp)
{
    int64_t seconds = 0;
    int32_t nanos = 0;
    struct tm tm_day;

    (void)memset(&tm_day, 0, sizeof(tm_day));

    if (timestamp == NULL || str_time == NULL) {
        return false;
    }

    if (!get_tm_from_str(str_time, &tm_day, &nanos)) {
        return false;
    }

    // set tm_isdst be kept as -1 to let the system decide if its dst or not
    tm_day.tm_isdst = -1;

    seconds = (int64_t)mktime(&tm_day);
    timestamp->has_seconds = true;
    timestamp->seconds = seconds;
    if (nanos) {
        timestamp->has_nanos = true;
        timestamp->nanos = nanos;
    }

    return true;
}

bool get_time_buffer_help(const types_timestamp_t *timestamp, char *timebuffer, size_t maxsize, bool local_utc)
{
    struct tm tm_utc = { 0 };
    struct tm tm_local = { 0 };
    int tm_zone = 0;
    int32_t nanos;
    int nret = 0;
    time_t seconds;

    if (timebuffer == NULL || maxsize == 0 || !timestamp->has_seconds) {
        return false;
    }

    seconds = (time_t)timestamp->seconds;
    localtime_r(&seconds, &tm_local);
    strftime(timebuffer, maxsize, "%Y-%m-%dT%H:%M:%S", &tm_local);

    if (timestamp->has_nanos) {
        nanos = timestamp->nanos;
    } else {
        nanos = 0;
    }

    if (local_utc) {
        nret = snprintf(timebuffer + strlen(timebuffer), maxsize - strlen(timebuffer), ".%09dZ", nanos);
        goto out;
    }

    gmtime_r(&seconds, &tm_utc);
    tm_zone = tm_local.tm_hour - tm_utc.tm_hour;
    if (tm_zone < -12) {
        tm_zone += 24;
    } else if (tm_zone > 12) {
        tm_zone -= 24;
    }

    if (tm_zone >= 0) {
        nret = snprintf(timebuffer + strlen(timebuffer), maxsize - strlen(timebuffer), ".%09d+%02d:00", nanos, tm_zone);
    } else {
        nret = snprintf(timebuffer + strlen(timebuffer), maxsize - strlen(timebuffer), ".%09d-%02d:00", nanos,
                        -tm_zone);
    }

out:
    if (nret < 0 || nret >= maxsize - strlen(timebuffer)) {
        ERROR("sprintf timebuffer failed");
        return false;
    }

    return true;
}

/* get time buffer */
bool get_time_buffer(const types_timestamp_t *timestamp, char *timebuffer, size_t maxsize)
{
    return get_time_buffer_help(timestamp, timebuffer, maxsize, false);
}

bool get_now_time_stamp(types_timestamp_t *timestamp)
{
    int err = 0;
    struct timespec ts;

    err = clock_gettime(CLOCK_REALTIME, &ts);
    if (err != 0) {
        ERROR("failed to get time");
        return false;
    }
    timestamp->has_seconds = true;
    timestamp->seconds = (int64_t)ts.tv_sec;
    timestamp->has_nanos = true;
    timestamp->nanos = (int32_t)ts.tv_nsec;
    return true;
}

int64_t get_now_time_nanos()
{
    int err = 0;
    struct timespec ts;

    err = clock_gettime(CLOCK_REALTIME, &ts);
    if (err != 0) {
        ERROR("failed to get time");
        return 0;
    }

    return ts.tv_sec * Time_Second + ts.tv_nsec;
}

/* get now time buffer */
bool get_now_time_buffer(char *timebuffer, size_t maxsize)
{
    types_timestamp_t timestamp;

    if (get_now_time_stamp(&timestamp) == false) {
        return false;
    }

    return get_time_buffer(&timestamp, timebuffer, maxsize);
}

/* get now local utc time buffer */
bool get_now_local_utc_time_buffer(char *timebuffer, size_t maxsize)
{
    types_timestamp_t timestamp;

    if (get_now_time_stamp(&timestamp) == false) {
        return false;
    }

    return get_time_buffer_help(&timestamp, timebuffer, maxsize, true);
}

int get_time_interval(types_timestamp_t first, types_timestamp_t last, int64_t *result)
{
    int64_t seconds_diff = 0;
    int64_t nanos_diff = 0;

    if (result == NULL) {
        return -1;
    }

    seconds_diff = (last.has_seconds ? last.seconds : 0) - (first.has_seconds ? first.seconds : 0);
    nanos_diff = (last.has_nanos ? last.nanos : 0) - (first.has_nanos ? first.nanos : 0);

    if (seconds_diff > INT64_MAX / Time_Second ||
        (seconds_diff == INT64_MAX / Time_Second && nanos_diff > INT64_MAX % Time_Second)) {
        return -1;
    }
    *result = (seconds_diff * Time_Second) + nanos_diff;

    return 0;
}

static int parsing_time_to_digit(const char *time, size_t *i)
{
    int sum = 0;

    while (time[*i] != '\0' && isdigit(time[*i])) {
        sum = sum * 10 + time[*i] - '0';
        (*i)++;
    }
    return sum;
}

static void parsing_time_data_year(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_year = parsing_time_to_digit(time, i);
}

static void parsing_time_data_month(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_mon = parsing_time_to_digit(time, i);
}

static void parsing_time_data_day(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_mday = parsing_time_to_digit(time, i);
}

static void parsing_time_data_hour(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_hour = parsing_time_to_digit(time, i);
}

static void parsing_time_data_min(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_min = parsing_time_to_digit(time, i);
}

static void parsing_time_data_sec(struct tm *tm, const char *time, size_t *i)
{
    tm->tm_sec = parsing_time_to_digit(time, i);
}

static void parsing_time_data(const char *time, struct tm *tm)
{
    size_t i = 0;

    parsing_time_data_year(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_month(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_day(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_hour(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_min(tm, time, &i);
    if (time[i] == '\0') {
        return;
    }
    i++;

    parsing_time_data_sec(tm, time, &i);
}

bool parsing_time(const char *format, const char *time, struct tm *tm, int32_t *nanos)
{
    size_t len_format = 0;
    size_t len_time = 0;
    size_t index_nanos = 0;

    if (format == NULL || time == NULL) {
        return false;
    }

    if (strcmp(format, rFC339NanoLocal) == 0) {
        index_nanos = strlen(rFC339Local) + 1;
    }
    len_format = strlen(format);
    len_time = strlen(time);

    if (index_nanos) {
        if (len_format < len_time || index_nanos >= len_time) {
            return false;
        }
    } else {
        if (len_format != len_time) {
            return false;
        }
    }

    if (index_nanos) {
        *nanos = 0;
        while (time[index_nanos] != '\0') {
            *nanos = *nanos * 10 + time[index_nanos] - '0';
            index_nanos++;
        }
        while (index_nanos < len_format) {
            *nanos *= 10;
            index_nanos++;
        }
    } else {
        *nanos = 0;
    }

    parsing_time_data(time, tm);

    return true;
}

static bool is_out_of_range(int value, int lower, int upper)
{
    return (value > upper) || (value < lower);
}

static bool is_leap_year(int year)
{
    return (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
}

int get_valid_days(int mon, int year)
{
    int leap_year = 0;
    int valid_days = 31;

    if (is_leap_year(year)) {
        leap_year = 1;
    }

    switch (mon) {
        case 2:
            valid_days = (valid_days - 3) + leap_year;
            break;
        case 4:
        case 6:
        case 9:
        case 11:
            valid_days = 30;
            break;
        default:
            break;
    }

    return valid_days;
}

bool fix_date(struct tm *tm)
{
    if (tm == NULL) {
        return false;
    }

    bool ret = (is_out_of_range(tm->tm_hour, 0, 23)) || (is_out_of_range(tm->tm_min, 0, 59)) ||
               (is_out_of_range(tm->tm_sec, 0, 59)) || (is_out_of_range(tm->tm_mon, 1, 12)) ||
               (is_out_of_range(tm->tm_year, 1900, 9999));

    if (ret) {
        ERROR("Normal section out of range");
        return false;
    }

    int valid_day = get_valid_days(tm->tm_mon, tm->tm_year);
    ret = ret || is_out_of_range(tm->tm_mday, 1, valid_day);
    if (ret) {
        ERROR("Day out of range");
        return false;
    }
    tm->tm_year -= 1900;
    tm->tm_mon -= 1;
    return true;
}

bool get_tm_from_str(const char *str, struct tm *tm, int32_t *nanos)
{
    char *format = NULL;

    if (str == NULL || tm == NULL || nanos == NULL) {
        return false;
    }

    if (strings_contains_any(str, ".")) {
        format = rFC339NanoLocal;
    } else if (strings_contains_any(str, "T")) {
        int tcolons = strings_count(str, ':');
        switch (tcolons) {
            case 0:
                format = "2016-01-02T15";
                break;
            case 1:
                format = "2016-01-02T15:04";
                break;
            case 2:
                format = rFC339Local;
                break;
            default:
                ERROR("date format error");
                return false;
        }
    } else {
        format = dateLocal;
    }

    if (!parsing_time(format, str, tm, nanos)) {
        ERROR("Failed to parse time \"%s\" with format \"%s\"", str, format);
        return false;
    }

    if (!fix_date(tm)) {
        ERROR("\"%s\" is invalid", str);
        return false;
    }

    return true;
}

static char *tm_get_zp(const char *tmstr)
{
    char *zp = NULL;

    zp = strrchr(tmstr, '+');
    if (zp == NULL) {
        zp = strrchr(tmstr, '-');
    }
    return zp;
}

static inline bool hasnil(const char *str, struct tm *tm, int32_t *nanos, struct types_timezone *tz)
{
    if (str == NULL || tm == NULL || nanos == NULL || tz == NULL) {
        return true;
    }
    return false;
}

static size_t tz_init_hour(struct types_timezone *tz, const char *zonestr, size_t i)
{
    int positive = 1;
    int sum = 0;

    if (zonestr[0] == '-') {
        positive = -1;
    }

    sum = parsing_time_to_digit(zonestr, &i);
    tz->hour = positive * sum;
    return i;
}

static size_t tz_init_min(struct types_timezone *tz, const char *zonestr, size_t i)
{
    int positive = 1;
    int sum = 0;

    if (zonestr[0] == '-') {
        positive = -1;
    }

    sum = parsing_time_to_digit(zonestr, &i);
    tz->min = positive * sum;
    return i;
}

static bool tz_init_ok(struct types_timezone *tz, const char *zonestr)
{
    size_t i = 0;

    i = tz_init_hour(tz, zonestr, 1);
    if (zonestr[i] == '\0') {
        return false;
    }
    tz_init_min(tz, zonestr, i + 1);
    return true;
}

static bool get_tm_zone_from_str(const char *str, struct tm *tm, int32_t *nanos, struct types_timezone *tz)
{
    char *tmstr = NULL;
    char *zp = NULL;
    char *zonestr = NULL;

    if (hasnil(str, tm, nanos, tz)) {
        ERROR("Get tm and timezone from str input error");
        goto err_out;
    }

    tmstr = util_strdup_s(str);
    zp = tm_get_zp(tmstr);
    if (zp == NULL) {
        ERROR("No time zone symbol found in input string");
        goto err_out;
    }
    zonestr = util_strdup_s(zp);
    *zp = '\0';

    if (!get_tm_from_str(tmstr, tm, nanos)) {
        ERROR("Get tm from str failed");
        goto err_out;
    }

    if (!tz_init_ok(tz, zonestr)) {
        ERROR("init tz failed");
        goto err_out;
    }

    free(tmstr);
    free(zonestr);
    return true;

err_out:
    free(tmstr);
    free(zonestr);
    return false;
}

static int64_t get_minmus_time(struct tm *tm1, struct tm *tm2)
{
    int64_t tmseconds1, tmseconds2, result;

    if (tm1 == NULL || tm2 == NULL) {
        return -1;
    }

    // set tm_isdst be kept as -1 to let the system decide if its dst or not
    tm1->tm_isdst = -1;
    tmseconds1 = (int64_t)mktime(tm1);
    // set tm_isdst be kept as -1 to let the system decide if its dst or not
    tm2->tm_isdst = -1;
    tmseconds2 = (int64_t)mktime(tm2);
    result = tmseconds1 - tmseconds2;
    return result;
}

int64_t time_seconds_since(const char *in)
{
    int32_t nanos = 0;
    int64_t result = 0;
    struct tm tm = { 0 };
    struct tm *currentm = NULL;
    struct types_timezone tz = { 0 };
    time_t currentime;

    if (in == NULL || !strcmp(in, defaultContainerTime) || !strcmp(in, "-")) {
        return 0;
    }

    if (!get_tm_zone_from_str(in, &tm, &nanos, &tz)) {
        ERROR("Failed to trans time %s", in);
        return 0;
    }

    time(&currentime);
    currentm = gmtime(&currentime);
    if (currentm == NULL) {
        ERROR("Get time error");
        return 0;
    }

    result = get_minmus_time(currentm, &tm);
    result = result + (int64_t)tz.hour * 3600 + (int64_t)tz.min * 60;

    if (result > 0) {
        return result;
    } else {
        return 0;
    }
}

struct time_human_duration_rule_t {
    bool (*check_human_duration)(int64_t seconds);
    int (*gen_human_duration)(int64_t seconds, char *str, size_t len);
};

static bool check_human_duration_less_1_sec(int64_t seconds)
{
    return seconds < 1;
}

static int gen_human_duration_less_1_sec(int64_t secondes, char *str, size_t len)
{
    return snprintf(str, len, "Less than a second");
}

static bool check_human_duration_less_60_secs(int64_t seconds)
{
    return seconds < 60;
}

static int gen_human_duration_less_60_secs(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "%lld seconds", (long long)seconds);
}

static bool check_human_duration_eq_1_min(int64_t seconds)
{
    return (seconds / 60 == 1);
}

static int gen_human_duration_eq_1_min(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "About a minute");
}

static bool check_human_duration_less_60_mins(int64_t seconds)
{
    return (seconds / 60 < 60);
}

static int gen_human_duration_less_60_mins(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "%lld minutes", (long long)seconds / 60);
}

static bool check_human_duration_eq_1_hour(int64_t seconds)
{
    return (seconds / (60 * 60) == 1);
}

static int gen_human_duration_eq_1_hour(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "About an hour");
}

static bool check_human_duration_less_48_hours(int64_t seconds)
{
    return (seconds / (60 * 60) < 48);
}

static int gen_human_duration_less_48_hours(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "%lld hours", (long long)seconds / (60 * 60));
}

static bool check_human_duration_less_7_days(int64_t seconds)
{
    return (seconds / (60 * 60) < 7 * 48);
}

static int gen_human_duration_less_7_days(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "%lld days", (long long)seconds / (60 * 60 * 24));
}

static bool check_human_duration_less_90_days(int64_t seconds)
{
    return (seconds / (60 * 60) < 24 * 30 * 3);
}

static int gen_human_duration_less_90_days(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "%lld weeks", (long long)seconds / (60 * 60 * 24 * 7));
}

static bool check_human_duration_less_2_years(int64_t seconds)
{
    return (seconds / (60 * 60) < 24 * 365 * 2);
}

static int gen_human_duration_less_2_years(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "%lld months", (long long)seconds / (60 * 60 * 24 * 30));
}

static bool check_human_duration_default(int64_t seconds)
{
    return (seconds / (60 * 60) >= 24 * 365 * 2);
}

static int gen_human_duration_default(int64_t seconds, char *str, size_t len)
{
    return snprintf(str, len, "%lld years", (long long)seconds / (60 * 60 * 24 * 365));
}

typedef struct time_human_duration_rule_t time_human_duration_rule;

static time_human_duration_rule const g_time_human_duration_rules[] = {
    {
        .check_human_duration = check_human_duration_less_1_sec,
        .gen_human_duration = gen_human_duration_less_1_sec,
    },
    {
        .check_human_duration = check_human_duration_less_60_secs,
        .gen_human_duration = gen_human_duration_less_60_secs,
    },
    {
        .check_human_duration = check_human_duration_eq_1_min,
        .gen_human_duration = gen_human_duration_eq_1_min,
    },
    {
        .check_human_duration = check_human_duration_less_60_mins,
        .gen_human_duration = gen_human_duration_less_60_mins,
    },
    {
        .check_human_duration = check_human_duration_eq_1_hour,
        .gen_human_duration = gen_human_duration_eq_1_hour,
    },
    {
        .check_human_duration = check_human_duration_less_48_hours,
        .gen_human_duration = gen_human_duration_less_48_hours,
    },
    {
        .check_human_duration = check_human_duration_less_7_days,
        .gen_human_duration = gen_human_duration_less_7_days,
    },
    {
        .check_human_duration = check_human_duration_less_90_days,
        .gen_human_duration = gen_human_duration_less_90_days,
    },
    {
        .check_human_duration = check_human_duration_less_2_years,
        .gen_human_duration = gen_human_duration_less_2_years,
    },
    {
        .check_human_duration = check_human_duration_default,
        .gen_human_duration = gen_human_duration_default,
    },
};

static bool time_human_duration(int64_t seconds, char *str, size_t len)
{
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
    int nret = 0;
    size_t i;

    if (seconds == 0 || str == NULL || len == 0) {
        return false;
    }

    for (i = 0; i < ARRAY_SIZE(g_time_human_duration_rules); i++) {
        if (g_time_human_duration_rules[i].check_human_duration(seconds)) {
            nret = g_time_human_duration_rules[i].gen_human_duration(seconds, str, len);
            break;
        }
    }

    if (nret < 0 || nret >= len) {
        ERROR("Sprintf buffer failed");
        return false;
    }

    return true;
}

static int time_format_duration_bad(char *out, size_t len)
{
    int nret = snprintf(out, len, "-");
    if (nret < 0 || (size_t)nret >= len) {
        return -1; /* format failed, return -1 */
    }
    return 1; /* format ok with bad data, return 1 */
}

int time_format_duration(const char *in, char *out, size_t len)
{
    int32_t nanos = 0;
    int64_t result = 0;
    struct tm tm = { 0 };
    struct tm *currentm = NULL;
    struct types_timezone tz = { 0 };
    time_t currentime = { 0 };

    if (out == NULL) {
        return -1;
    }

    if (in == NULL || !strcmp(in, defaultContainerTime) || !strcmp(in, "-")) {
        return time_format_duration_bad(out, len);
    }

    if (!get_tm_zone_from_str(in, &tm, &nanos, &tz)) {
        return time_format_duration_bad(out, len);
    }

    time(&currentime);
    currentm = gmtime(&currentime);
    if (currentm == NULL) {
        ERROR("Get time error");
        return -1;
    }

    result = get_minmus_time(currentm, &tm);
    result = result + (int64_t)tz.hour * 3600 + (int64_t)tz.min * 60;

    if (result < 0 || !time_human_duration(result, out, len)) {
        return time_format_duration_bad(out, len);
    }

    return 0;
}

int time_format_duration_ago(const char *in, char *out, size_t len)
{
    if (time_format_duration(in, out, len) != 0) {
        ERROR("Get format duration");
        return -1;
    }

    if (strcmp(out, "-") != 0 && strlen(out) + 5 < len) {
        (void)strcat(out, " ago");
    }

    return 0;
}

static int time_tz_to_seconds_nanos(const char *time_tz, int64_t *seconds, int32_t *nanos)
{
    int nret = 0;
    struct tm t = { 0 };
    int32_t nano = 0;
    char *time_str = NULL;

    if (seconds != NULL) {
        *seconds = 0;
    }
    if (nanos != NULL) {
        *nanos = 0;
    }
    if (time_tz == NULL) {
        return 0;
    }

    /* translate to rfc339NanoLocal */
    time_str = util_strdup_s(time_tz);
    time_str[strlen(time_str) - 1] = '\0'; /* strip last 'Z' */

    if (!get_tm_from_str(time_str, &t, &nano)) {
        ERROR("get tm from string %s failed", time_str);
        nret = -1;
        goto err_out;
    }

    if (seconds != NULL) {
        *seconds = timegm(&t);
    }

    if (nanos != NULL) {
        *nanos = nano;
    }

err_out:
    free(time_str);
    return nret;
}

int to_unix_nanos_from_str(const char *str, int64_t *nanos)
{
    struct tm tm = { 0 };
    struct types_timezone tz;
    int32_t nano = 0;
    types_timestamp_t ts;

    if (nanos == NULL) {
        return -1;
    }

    *nanos = 0;
    if (str == NULL || !strcmp(str, "") || !strcmp(str, defaultContainerTime)) {
        return 0;
    }

    if (!util_valid_time_tz(str)) {
        ERROR("invalid time %s", str);
        return -1;
    }

    if (str[strlen(str) - 1] == 'Z') {
        int ret = time_tz_to_seconds_nanos(str, &ts.seconds, &ts.nanos);
        if (ret != 0) {
            ERROR("Invalid time stamp: %s", str);
            return -1;
        }
        *nanos = ts.seconds * Time_Second + ts.nanos;
        return 0;
    }

    if (!get_tm_zone_from_str(str, &tm, &nano, &tz)) {
        ERROR("Transform str to timestamp failed");
        return -1;
    }

    // set tm_isdst be kept as -1 to let the system decide if its dst or not
    tm.tm_isdst = -1;

    *nanos = mktime(&tm) * Time_Second + nano;
    return 0;
}
