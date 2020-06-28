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
 * Author: zhangxiaoyu
 * Create: 2020-06-24
 * Description: provide oci storage driver unit test
 ******************************************************************************/
#include "driver.h"
#include <cstddef>
#include <cstring>
#include <iostream>
#include <climits>
#include <dirent.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "path.h"
#include "utils_array.h"
#include "driver_overlay2.h"
#include "driver_quota_mock.h"

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
using ::testing::FLAGS_gmock_catch_leaked_mocks;

std::string GetDirectory()
{
    char abs_path[PATH_MAX];
    int ret = readlink("/proc/self/exe", abs_path, sizeof(abs_path));
    if (ret < 0 || (size_t)ret >= sizeof(abs_path)) {
        return "";
    }

    for (int i { ret }; i >= 0; --i) {
        if (abs_path[i] == '/') {
            abs_path[i + 1] = '\0';
            break;
        }
    }

    return static_cast<std::string>(abs_path);
}

bool dirExists(const char *path)
{
    DIR *dp = NULL;
    if ((dp = opendir(path)) == NULL) {
        return false;
    }

    closedir(dp);
    return true;
}

int invokeGetPageSize()
{
    std::string abs_mount = "rw,"
                            "lowerdir=/var/lib/isulad/data/overlay/9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63/empty,"
                            "upperdir=/var/lib/isulad/data/overlay/9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63/diff,"
                            "workdir=/var/lib/isulad/data/overlay/9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63/work";
    return abs_mount.length() - 1;
}

int invokeIOCtl(int fd, int cmd)
{
    return 0;
}

int invokeQuotaCtl(int cmd, const char* special, int id, caddr_t addr)
{
#define XFS_QUOTA_PDQ_ACCT (1<<4)   // project quota accounting
#define XFS_QUOTA_PDQ_ENFD (1<<5)   // project quota limits enforcement

    fs_quota_stat_t* fs_quota_stat_info = (fs_quota_stat_t *)addr;
    fs_quota_stat_info->qs_flags = XFS_QUOTA_PDQ_ACCT | XFS_QUOTA_PDQ_ENFD;

    return 0;
}

class StorageDriverUnitTest : public testing::Test {
protected:
    void SetUp() override
    {
        MockDriverQuota_SetMock(&m_driver_quota_mock);
        std::string isulad_dir { "/var/lib/isulad/" };
        std::string root_dir = isulad_dir + "data";
        std::string run_dir = isulad_dir + "data/run";
        std::string data_dir = GetDirectory() + "/data";
        struct storage_module_init_options *opts;

        ASSERT_STRNE(cleanpath(data_dir.c_str(), data_path, sizeof(data_path)), nullptr);
        std::string cp_command = "cp -r " + std::string(data_path) + " " + isulad_dir;
        ASSERT_EQ(system(cp_command.c_str()), 0);

        std::string mkdir = "mkdir -p " + root_dir + "/overlay/1be74353c3d0fd55fb5638a52953e6f1bc441e5b1710921db9ec2aa202725569/merged "
                          + root_dir + "/overlay/1be74353c3d0fd55fb5638a52953e6f1bc441e5b1710921db9ec2aa202725569/work && "
                            "mkdir -p " + root_dir + "/overlay/9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63/empty "
                          + root_dir + "/overlay/9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63/merged "
                          + root_dir + "/overlay/9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63/work ";
        ASSERT_EQ(system(mkdir.c_str()), 0);

        opts = (struct storage_module_init_options *)malloc(sizeof(struct storage_module_init_options));
        opts->storage_root = strdup(root_dir.c_str());
        opts->storage_run_root = strdup(run_dir.c_str());
        opts->driver_name = strdup("overlay");
        opts->driver_opts = (char **)malloc(4 * sizeof(char *));
        opts->driver_opts[0] = strdup("overlay2.basesize=128M");
        opts->driver_opts[1] = strdup("overlay2.override_kernel_check=true");
        opts->driver_opts[2] = strdup("overlay2.skip_mount_home=false");
        opts->driver_opts[3] = strdup("overlay2.mountopt=rw");
        opts->driver_opts_len = 4;

        EXPECT_CALL(m_driver_quota_mock, QuotaCtl(_, _, _, _)).WillRepeatedly(Invoke(invokeQuotaCtl));
        ASSERT_EQ(graphdriver_init(opts), 0);

        free(opts->storage_root);
        free(opts->storage_run_root);
        free(opts->driver_name);
        util_free_array_by_len(opts->driver_opts, opts->driver_opts_len);
        free(opts);
    }

    void TearDown() override
    {
        MockDriverQuota_SetMock(nullptr);
        ASSERT_EQ(graphdriver_cleanup(), 0);
        std::string rm_command = "rm -rf /var/lib/isulad/data";
        ASSERT_EQ(system(rm_command.c_str()), 0);
    }

    NiceMock<MockDriverQuota> m_driver_quota_mock;
    char data_path[PATH_MAX] = { 0x00 };
};


TEST_F(StorageDriverUnitTest, test_graphdriver_layer_exists)
{
    std::string id { "9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63" };
    std::string incorrectId { "eb29745b8228e1e97c01b1d5c2554a319c00a94d8dd5746a3904222ad65a13f8" };
    ASSERT_TRUE(graphdriver_layer_exists(id.c_str()));
    ASSERT_FALSE(graphdriver_layer_exists(incorrectId.c_str()));
}

TEST_F(StorageDriverUnitTest, test_graphdriver_create_rw)
{
    std::string id { "eb29745b8228e1e97c01b1d5c2554a319c00a94d8dd5746a3904222ad65a13f8" };
    struct driver_create_opts *create_opts;

    create_opts = (struct driver_create_opts *)malloc(sizeof(struct driver_create_opts));
    ASSERT_NE(create_opts, nullptr);

    create_opts->mount_label = strdup("mount_label");    
    create_opts->storage_opt = (json_map_string_string *)malloc(sizeof(json_map_string_string));
    ASSERT_NE(create_opts->storage_opt, nullptr);
    create_opts->storage_opt->keys = (char **)malloc(sizeof(char *));
    create_opts->storage_opt->values = (char **)malloc(sizeof(char *));
    create_opts->storage_opt->keys[0] = strdup("size");
    create_opts->storage_opt->values[0] = strdup("128M");
    create_opts->storage_opt->len = 1;

    EXPECT_CALL(m_driver_quota_mock, IOCtl(_, _)).WillRepeatedly(Invoke(invokeIOCtl));
    ASSERT_EQ(graphdriver_create_rw(id.c_str(), nullptr, create_opts), 0);
    ASSERT_TRUE(graphdriver_layer_exists(id.c_str()));

    ASSERT_EQ(graphdriver_rm_layer(id.c_str()), 0);
    ASSERT_FALSE(graphdriver_layer_exists(id.c_str()));
    free_driver_create_opts(create_opts);
}

TEST_F(StorageDriverUnitTest, test_graphdriver_mount_layer)
{
    std::string id { "9c27e219663c25e0f28493790cc0b88bc973ba3b1686355f221c38a36978ac63" };
    std::string merged_dir = "/var/lib/isulad/data/overlay/" + id + "/merged";
    struct driver_mount_opts *mount_opts = nullptr;
    char* mount_dir = nullptr;

    EXPECT_CALL(m_driver_quota_mock, GetPageSize()).WillRepeatedly(Invoke(invokeGetPageSize));
    FLAGS_gmock_catch_leaked_mocks = false; // the exit in the child without deleting the mock object
    mount_dir = graphdriver_mount_layer(id.c_str(), mount_opts);
    ASSERT_STREQ(mount_dir, merged_dir.c_str());
    FLAGS_gmock_catch_leaked_mocks = true;

    ASSERT_EQ(graphdriver_umount_layer(id.c_str()), 0);
    free(mount_dir);
    mount_dir = nullptr;

    mount_opts = (struct driver_mount_opts *)malloc(sizeof(struct driver_mount_opts));
    ASSERT_NE(mount_opts, nullptr);
    mount_opts->mount_label = strdup("mount_label");
    mount_opts->options = (char **)malloc(1 * sizeof(char *));
    mount_opts->options[0] = strdup("ro");
    mount_opts->options_len = 1;

    FLAGS_gmock_catch_leaked_mocks = false;
    mount_dir = graphdriver_mount_layer(id.c_str(), mount_opts);
    ASSERT_STREQ(mount_dir, merged_dir.c_str());
    FLAGS_gmock_catch_leaked_mocks = true;

    ASSERT_EQ(graphdriver_umount_layer(id.c_str()), 0);
    free_driver_mount_opts(mount_opts);
    free(mount_dir);
}

TEST_F(StorageDriverUnitTest, test_graphdriver_try_repair_lowers)
{
    std::string id { "1be74353c3d0fd55fb5638a52953e6f1bc441e5b1710921db9ec2aa202725569" };
    ASSERT_EQ(graphdriver_try_repair_lowers(id.c_str(), nullptr), 0);
}

TEST(StorageOverlay2QuotaOptionsTest, test_overlay2_is_quota_options)
{
    std::vector<std::string> options { "overlay2.size", "overlay2.basesize" };
    for(auto option : options) {
        ASSERT_TRUE(overlay2_is_quota_options(nullptr, option.c_str()));
    }
}