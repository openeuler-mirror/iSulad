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
 * Author: haozi007
 * Create: 2022-10-13
 * Description: utils timestamp unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "utils_timestamp.h"

TEST(utils_timestamp, test_util_types_timestamp_cmp)
{
    types_timestamp_t t1 = { 0 };
    types_timestamp_t t2 = { 0 };

    // t1 == t2
    ASSERT_EQ(util_types_timestamp_cmp(&t1, &t2), 0);

    t1.has_seconds = true;
    t1.seconds = 2;
    t1.has_nanos = false;
    t1.nanos = 0;
    t2.has_seconds = false;
    t2.seconds = 0;
    t2.has_nanos = false;
    t2.nanos = 100;
    // t1 > t2
    ASSERT_EQ(util_types_timestamp_cmp(&t1, &t2), 1);

    t1.has_seconds = false;
    t1.seconds = 2;
    t1.has_nanos = false;
    t1.nanos = 0;
    t2.has_seconds = true;
    t2.seconds = 1;
    t2.has_nanos = true;
    t2.nanos = 100;
    // t1 < t2
    ASSERT_EQ(util_types_timestamp_cmp(&t1, &t2), -1);

    t1.has_seconds = true;
    t1.seconds = 2;
    t1.has_nanos = false;
    t1.nanos = 0;
    t2.has_seconds = true;
    t2.seconds = 2;
    t2.has_nanos = false;
    t2.nanos = 0;
    // t1 == t2
    ASSERT_EQ(util_types_timestamp_cmp(&t1, &t2), 0);

    t1.has_nanos = true;
    t1.nanos = 88;
    t2.has_nanos = true;
    t2.nanos = 88;
    // t1 == t2
    ASSERT_EQ(util_types_timestamp_cmp(&t1, &t2), 0);
}

TEST(utils_timestamp, test_util_get_timestamp)
{
    types_timestamp_t t = { 0 };
    std::string invalid_str = "1970-01-02X:00:xx";
    std::string dstr1 = "1970-01-01T00:00:01.000000800";
    struct tm tm_local = { 0 };
    const time_t now_time = time(NULL);
    long int tm_gmtoff = 0;

    (void)localtime_r(&now_time, &tm_local);
#ifdef __USE_MISC
    tm_gmtoff = tm_local.tm_gmtoff;
#else
    tm_gmtoff = tm_local.__tm_gmtoff;
#endif

    ASSERT_EQ(util_get_timestamp(dstr1.c_str(), &t), true);
    t.seconds += tm_gmtoff;
    ASSERT_EQ(t.has_seconds, true);
    ASSERT_EQ(t.seconds, 1);
    ASSERT_EQ(t.has_nanos, true);
    ASSERT_EQ(t.nanos, 800);

    // invalid agruments check
    ASSERT_EQ(util_get_timestamp(nullptr, &t), false);
    ASSERT_EQ(util_get_timestamp(dstr1.c_str(), nullptr), false);
    ASSERT_EQ(util_get_timestamp(invalid_str.c_str(), nullptr), false);
}

TEST(utils_timestamp, test_util_get_now_local_utc_time_buffer)
{
    char local_time[128] = { 0 };

    ASSERT_EQ(util_get_now_local_utc_time_buffer(local_time, 128), true);
    ASSERT_EQ(util_get_now_local_utc_time_buffer(nullptr, 0), false);
}

TEST(utils_timestamp, test_util_get_time_interval)
{
    types_timestamp_t t1 = { 0 };
    types_timestamp_t t2 = { 0 };
    int64_t ret = 0;

    ASSERT_EQ(util_get_time_interval(t1, t2, &ret), 0);
    ASSERT_EQ(ret, 0);

    t2.has_seconds = true;
    t2.seconds = 8;
    t2.has_nanos = true;
    t2.nanos = 8;
    ASSERT_EQ(util_get_time_interval(t1, t2, &ret), 0);
    ASSERT_EQ(ret, 8000000008);

    t2.has_seconds = true;
    t2.seconds = INT64_MAX;
    t2.has_nanos = false;
    t2.nanos = 0;
    ASSERT_NE(util_get_time_interval(t1, t2, &ret), 0);

    t2.seconds = INT64_MAX - 1;
    t2.has_nanos = true;
    t2.nanos = 100;
    ASSERT_NE(util_get_time_interval(t1, t2, &ret), 0);
}

TEST(utils_timestamp, test_util_get_tm_from_str)
{
    std::string invalid_str = "2016-01-02T15:04:01:03";
    struct tm got = { 0 };
    int32_t nano = 0;

    std::vector<std::tuple<std::string, int, int, int, int, int, int, int>> cases = {
        std::make_tuple("1970-01-01T01", 0, 0, 0, 1, 1, 0, 70),
        std::make_tuple("1980-02-02T02:02", 0, 0, 2, 2, 2, 1, 80),
        std::make_tuple("1990-03-03T03:03:03", 0, 3, 3, 3, 3, 2, 90),
    };

    for (const auto &elem : cases) {
        ASSERT_EQ(util_get_tm_from_str(std::get<0>(elem).c_str(), &got, &nano), true);
        ASSERT_EQ(nano, std::get<1>(elem));
        ASSERT_EQ(got.tm_sec, std::get<2>(elem));
        ASSERT_EQ(got.tm_min, std::get<3>(elem));
        ASSERT_EQ(got.tm_hour, std::get<4>(elem));
        ASSERT_EQ(got.tm_mday, std::get<5>(elem));
        ASSERT_EQ(got.tm_mon, std::get<6>(elem));
        ASSERT_EQ(got.tm_year, std::get<7>(elem));
    }

    // check invalid cases
    ASSERT_NE(util_get_tm_from_str(invalid_str.c_str(), &got, &nano), true);
    ASSERT_NE(util_get_tm_from_str(nullptr, &got, &nano), true);
    ASSERT_NE(util_get_tm_from_str(invalid_str.c_str(), nullptr, &nano), true);
    ASSERT_NE(util_get_tm_from_str(invalid_str.c_str(), &got, nullptr), true);
}

TEST(utils_timestamp, test_util_time_seconds_since)
{
    std::string defaultstr = "-";
    std::string invalid_str = "2016-01-02T15:04:01:03";
    std::string dstr1 = "1990-03-03T03:03:03";
    types_timestamp_t currt = { 0 };
    char tbuf[128] = { 0 };
    int64_t ret;

    ASSERT_EQ(util_get_now_time_stamp(&currt), true);
    currt.seconds -= 10;
    ASSERT_EQ(util_get_time_buffer(&currt, tbuf, 128), true);
    ret = util_time_seconds_since(tbuf);
    ASSERT_GE(ret, 9);
    ASSERT_LE(ret, 11);

    ASSERT_EQ(util_time_seconds_since(dstr1.c_str()), 0);

    // invalid cases
    ASSERT_EQ(util_time_seconds_since(invalid_str.c_str()), 0);
    ASSERT_EQ(util_time_seconds_since(nullptr), 0);
    ASSERT_EQ(util_time_seconds_since(defaultContainerTime), 0);
    ASSERT_EQ(util_time_seconds_since(defaultstr.c_str()), 0);
}

TEST(utils_timestamp, test_util_time_format_duration)
{
    std::string invalid_str = "2016-01-02T15:04:01:03";
    std::string dstr3 = "1990-03-03T03:03:03.000000000+08:00";
    std::string defaultstr = "-";
    char out[128] = { 0 };

    ASSERT_EQ(util_time_format_duration(dstr3.c_str(), out, 128), 0);

    // invalid cases
    ASSERT_EQ(util_time_format_duration(invalid_str.c_str(), out, 128), 1);
    ASSERT_EQ(util_time_format_duration(nullptr, out, 128), 1);
    ASSERT_EQ(util_time_format_duration(defaultContainerTime, out, 128), 1);
    ASSERT_EQ(util_time_format_duration(defaultstr.c_str(), out, 128), 1);
    ASSERT_EQ(util_time_format_duration(invalid_str.c_str(), out, 0), -1);
}

TEST(utils_timestamp, test_util_to_unix_nanos_from_str)
{
    std::string invalid_str = "2016-01-02T15:04:01:03";
    std::string dstr3 = "1970-01-01T00:00:01.0+00:00";
    int64_t ret = 0;

    ASSERT_EQ(util_to_unix_nanos_from_str(dstr3.c_str(), &ret), 0);
    ASSERT_EQ(ret, 1000000000);

    // invalid cases
    ASSERT_NE(util_to_unix_nanos_from_str(invalid_str.c_str(), &ret), 0);
    ASSERT_EQ(util_to_unix_nanos_from_str(nullptr, &ret), 0);
}

TEST(utils_timestamp, test_util_time_str_to_nanoseconds)
{
    int64_t ret = 0;
    std::string invalid_str = "xxxxxxx";
    std::string dstr2 = "1ms";
    std::string dstr3 = "2s";
    std::string dstr4 = "1m";
    std::string dstr5 = "1h";

    ASSERT_EQ(util_time_str_to_nanoseconds(dstr2.c_str(), &ret), 0);
    ASSERT_EQ(ret, Time_Milli);
    ASSERT_EQ(util_time_str_to_nanoseconds(dstr3.c_str(), &ret), 0);
    ASSERT_EQ(ret, 2 * Time_Second);
    ASSERT_EQ(util_time_str_to_nanoseconds(dstr4.c_str(), &ret), 0);
    ASSERT_EQ(ret, 60 * Time_Second);
    ASSERT_EQ(util_time_str_to_nanoseconds(dstr5.c_str(), &ret), 0);
    ASSERT_EQ(ret, 3600 * Time_Second);

    // invalid cases
    ASSERT_NE(util_time_str_to_nanoseconds(invalid_str.c_str(), &ret), 0);
    ASSERT_NE(util_time_str_to_nanoseconds(nullptr, &ret), 0);
    ASSERT_NE(util_time_str_to_nanoseconds(dstr3.c_str(), nullptr), 0);
}