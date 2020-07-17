/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-02-14
 * Description: provide selinux label unit test
 ******************************************************************************/

#include "selinux_label.h"
#include <iostream>
#include <algorithm>
#include <tuple>
#include <fstream>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <selinux/selinux.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "namespace_mock.h"
#include "utils.h"

using namespace std;

class SELinuxLabelUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        selinux_state_init();
    }
    void TearDown() override
    {
        selinux_state_free();
    }
};

TEST_F(SELinuxLabelUnitTest, test_init_label_normal)
{
    const char *disable_label[] = { "disable" };
    const char *user_label[] = { "user:fakeuser" };
    const char *role_label[] = { "role:fakerole" };
    const char *type_label[] = { "type:faketype" };
    const char *level_label[] = { "level:s0:c1,c2" };
    const char *full_label[] = { "user:fakeuser", "level:s0:c1,c2", "type:faketype", "role:fakerole" };

    std::vector<std::tuple<const char **, size_t, int, std::string, std::string>> normal {
        std::make_tuple(disable_label, 1, 0, "", ""),
        std::make_tuple(user_label, 1, 0, "fakeuser:system_r:container_t:s0", "fakeuser:object_r:container_file_t:s0"),
        std::make_tuple(role_label, 1, 0, "system_u:fakerole:container_t:s0", "system_u:object_r:container_file_t:s0"),
        std::make_tuple(type_label, 1, 0, "system_u:system_r:faketype:s0", "system_u:object_r:container_file_t:s0"),
        std::make_tuple(level_label, 1, 0, "system_u:system_r:container_t:s0:c1,c2",
                        "system_u:object_r:container_file_t:s0:c1,c2"),
        std::make_tuple(full_label, 4, 0, "fakeuser:fakerole:faketype:s0:c1,c2",
                        "fakeuser:object_r:container_file_t:s0:c1,c2"),
        std::make_tuple(nullptr, 0, 0, "system_u:system_r:container_t:s0", "system_u:object_r:container_file_t:s0"),
    };

    if (!is_selinux_enabled()) {
        SUCCEED() << "WARNING: The current machine does not support SELinux";
        return;
    }

    for (const auto &elem : normal) {
        char *process_label = nullptr;
        char *mount_label = nullptr;

        ASSERT_EQ(init_label(std::get<0>(elem), std::get<1>(elem), &process_label, &mount_label), std::get<2>(elem));
        if (!std::get<3>(elem).empty()) {
            std::string processLabel { process_label };
            processLabel.resize(std::get<3>(elem).size());
            ASSERT_STREQ(processLabel.c_str(), std::get<3>(elem).c_str());
            free(process_label);
        } else {
            ASSERT_STREQ(process_label, nullptr);
        }

        if (!std::get<4>(elem).empty()) {
            std::string mountLabel { mount_label };
            mountLabel.resize(std::get<4>(elem).size());
            ASSERT_STREQ(mountLabel.c_str(), std::get<4>(elem).c_str());
            free(mount_label);
        } else {
            ASSERT_STREQ(mount_label, nullptr);
        }
    }
}

TEST_F(SELinuxLabelUnitTest, test_init_label_abnormal)
{
    const char *invalid_key_label[] = { "xxx" };
    const char *invalid_value_label[] = { "user:" };

    std::vector<std::tuple<const char **, size_t, int, std::string, std::string>> normal {
        std::make_tuple(invalid_key_label, 1, -1, "", ""),
        std::make_tuple(invalid_value_label, 1, -1, "", ""),
    };

    if (!is_selinux_enabled()) {
        SUCCEED() << "WARNING: The current machine does not support SELinux";
        return;
    }

    for (const auto &elem : normal) {
        char *process_label = nullptr;
        char *mount_label = nullptr;

        ASSERT_EQ(init_label(std::get<0>(elem), std::get<1>(elem), &process_label, &mount_label), std::get<2>(elem));
        ASSERT_STREQ(process_label, nullptr);
        ASSERT_STREQ(mount_label, nullptr);
    }
}

TEST(SELinuxLabelUnitTestWithoutMock, test_dup_security_opt)
{
    const char *label = "system_u:object_r:container_file_t:s0";
    char **dst = nullptr;
    size_t len;

    ASSERT_EQ(dup_security_opt(label, &dst, &len), 0);
    ASSERT_EQ(len, 4);
    ASSERT_STREQ(dst[0], "user:system_u");
    ASSERT_STREQ(dst[1], "role:object_r");
    ASSERT_STREQ(dst[2], "type:container_file_t");
    ASSERT_STREQ(dst[3], "level:s0");
    util_free_array(dst);
    dst = nullptr;
    len = 0;

    ASSERT_EQ(dup_security_opt(nullptr, &dst, &len), 0);
    ASSERT_EQ(dst, nullptr);
}

class SELinuxRelabelUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        CreateTestedObjects();
    }

    void TearDown() override
    {
        ClearTestedObjects();
    }

private:
    void CreateTestedObjects()
    {
        struct stat st;

        if (lstat(m_testDir.c_str(), &st) < 0) {
            (void)mkdir(m_testDir.c_str(), S_IRUSR | S_IWUSR | S_IXUSR | S_IRWXG | S_IRWXO);
        }

        ofstream osm;
        osm.open(m_testFile);
        osm << "SELinux unit test";
        osm.close();
    }

    void ClearTestedObjects()
    {
        remove(m_testFile.c_str());
        rmdir(m_testDir.c_str());
    }

protected:
    std::string m_testDir { "./test_dir" };
    std::string m_testFile { m_testDir + "/file" };
};

TEST_F(SELinuxRelabelUnitTest, test_relabel_normal)
{
    std::vector<std::tuple<std::string, bool, int, std::string>> normal {
        std::make_tuple("system_u:object_r:container_file_t:s0:c100,c200", false, 0,
                        "system_u:object_r:container_file_t:s0:c100,c200"),
        std::make_tuple("system_u:object_r:container_file_t:s0:c300,c300", false, 0,
                        "system_u:object_r:container_file_t:s0:c300"),
        std::make_tuple("system_u:object_r:container_file_t:s0:c100,c200", true, 0,
                        "system_u:object_r:container_file_t:s0"),
        std::make_tuple("system_u:object_r:container_file_t:s0:c300,c300", true, 0,
                        "system_u:object_r:container_file_t:s0"),
    };

    if (!is_selinux_enabled()) {
        SUCCEED() << "WARNING: The current machine does not support SELinux";
        return;
    }

    for (const auto &elem : normal) {
        char *context = nullptr;

        ASSERT_EQ(relabel(m_testDir.c_str(), std::get<0>(elem).c_str(), std::get<1>(elem)), std::get<2>(elem));
        ASSERT_GE(lgetfilecon(m_testFile.c_str(), &context), 0);
        ASSERT_STREQ(context, std::get<3>(elem).c_str());
        freecon(context);
    }
}

TEST_F(SELinuxRelabelUnitTest, test_relabel_abnormal)
{
    std::vector<std::tuple<std::string, std::string, bool, int>> abnormal {
        // exclude path test
        std::make_tuple("/", "system_u:object_r:root_t:s0", true, -1),
        std::make_tuple("/usr", "system_u:object_r:usr_t:s0", true, -1),
        std::make_tuple("/etc", "system_u:object_r:etc_t:s0", true, -1),
        std::make_tuple("/tmp", "system_u:object_r:tmp_t:s0", true, -1),
        std::make_tuple("/home", "system_u:object_r:home_root_t:s0", true, -1),
        std::make_tuple("/run", "system_u:object_r:var_run_t:s0", true, -1),
        std::make_tuple("/var", "system_u:object_r:var_t:s0", true, -1),
        std::make_tuple("/root", "system_u:object_r:admin_home_t:s0", true, -1),
        // bad prefix test
        std::make_tuple("/usr/xxx", "system_u:object_r:usr_t:s0", true, -1),
    };

    if (!is_selinux_enabled()) {
        SUCCEED() << "WARNING: The current machine does not support SELinux";
        return;
    }

    for (const auto &elem : abnormal) {
        ASSERT_EQ(relabel(std::get<0>(elem).c_str(), std::get<1>(elem).c_str(), std::get<2>(elem)), std::get<3>(elem));
    }
}

TEST_F(SELinuxRelabelUnitTest, test_get_disable_security_opt)
{
    char **labels = nullptr;
    size_t labels_len;

    ASSERT_EQ(get_disable_security_opt(&labels, &labels_len), 0);
    ASSERT_EQ(labels_len, 1);
    ASSERT_NE(labels[0], "label=disable");

    util_free_array(labels);
}
