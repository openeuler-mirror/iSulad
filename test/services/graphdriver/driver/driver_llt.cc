/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Description: driver llt
 * Author: wangfengtu
 * Create: 2020-02-19
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "utils.h"
#include "driver_devmapper.h"
#include "image.h"
#include "image_mock.h"
#include "driver_overlay2_mock.h"
#include "isulad_config_mock.h"

using ::testing::Args;
using ::testing::ByRef;
using ::testing::SetArgPointee;
using ::testing::DoAll;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::NotNull;
using ::testing::AtLeast;
using ::testing::Invoke;
using ::testing::_;

using namespace std;

class DriverUnitTest : public testing::Test {
public:
    void SetUp() override
    {
        MockImage_SetMock(&m_image);
        MockIsuladConf_SetMock(&m_isulad_config);
        MockDriverOverlay2_SetMock(&m_driver_overlay2);
        ::testing::Mock::AllowLeak(&m_image);
        ::testing::Mock::AllowLeak(&m_isulad_config);
        ::testing::Mock::AllowLeak(&m_driver_overlay2);
    }
    void TearDown() override
    {
        MockImage_SetMock(nullptr);
        MockIsuladConf_SetMock(nullptr);
        MockDriverOverlay2_SetMock(nullptr);
    }

    NiceMock<MockImage> m_image;
    NiceMock<MockIsuladConf> m_isulad_config;
    NiceMock<MockDriverOverlay2> m_driver_overlay2;
};

// All parameter NULL
TEST(graphdriver_init_llt, test_graphdriver_init_1)
{
    ASSERT_TRUE(graphdriver_init(NULL, NULL, 0) == NULL);
}

// All parameter correct
TEST(graphdriver_init_llt, test_graphdriver_init_2)
{
    struct graphdriver *driver = NULL;
    char **options = NULL;
    size_t options_len = 0;

    options = util_string_split("dm.fs=ext4#dm.thinpooldev=/dev/mapper/isula-thinpool#"
                                "dm.min_free_space=10%#dm.basesize=5G#dm.mountopt=nodiscard#"
                                "dm.mkfsarg=-O ^has_journal#dm.mountopt=nodiscard", '#');
    options_len = util_array_len((const char**)options);
    driver = graphdriver_init("devicemapper", options, options_len);
    ASSERT_TRUE(driver != NULL);
    ASSERT_EQ(driver->name, "devicemapper");
    util_free_array(options);
}

// Parameter dm.fs invalid
TEST(graphdriver_init_llt, test_graphdriver_init_3)
{
    struct graphdriver *driver = NULL;
    char **options = NULL;
    size_t options_len = 0;

    options = util_string_split("dm.fs=xfs", ' ');
    options_len = util_array_len((const char**)options);
    driver = graphdriver_init("devicemapper", options, options_len);
    ASSERT_TRUE(driver == NULL);
    util_free_array(options);
}

// Parameter dm.thinpooldev invalid
TEST(graphdriver_init_llt, test_graphdriver_init_4)
{
    struct graphdriver *driver = NULL;
    char **options = NULL;
    size_t options_len = 0;

    options = util_string_split("dm.thinpooldev=", ' ');
    options_len = util_array_len((const char**)options);
    driver = graphdriver_init("devicemapper", options, options_len);
    ASSERT_TRUE(driver == NULL);
    util_free_array(options);
}

// Parameter dm.min_free_space invalid
TEST(graphdriver_init_llt, test_graphdriver_init_5)
{
    struct graphdriver *driver = NULL;
    char **options = NULL;
    size_t options_len = 0;

    options = util_string_split("dm.min_free_space=101%", ' ');
    options_len = util_array_len((const char**)options);
    driver = graphdriver_init("devicemapper", options, options_len);
    ASSERT_TRUE(driver == NULL);
    util_free_array(options);

    options = util_string_split("dm.min_free_space=100%", ' ');
    options_len = util_array_len((const char**)options);
    driver = graphdriver_init("devicemapper", options, options_len);
    ASSERT_TRUE(driver == NULL);
    util_free_array(options);
}

// Parameter dm.basesize invalid
TEST(graphdriver_init_llt, test_graphdriver_init_6)
{
    struct graphdriver *driver = NULL;
    char **options = NULL;
    size_t options_len = 0;

    options = util_string_split("dm.basesize=-1", ' ');
    options_len = util_array_len((const char**)options);
    driver = graphdriver_init("devicemapper", options, options_len);
    ASSERT_TRUE(driver == NULL);
    util_free_array(options);
}

// None exist parameter
TEST(graphdriver_init_llt, test_graphdriver_init_7)
{
    struct graphdriver *driver = NULL;
    char **options = NULL;
    size_t options_len = 0;

    options = util_string_split("kkkk=aaa", ' ');
    options_len = util_array_len((const char**)options);
    driver = graphdriver_init("devicemapper", options, options_len);
    ASSERT_TRUE(driver == NULL);
    util_free_array(options);
}
