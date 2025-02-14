/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: sandbox unit test
 * Author: zhongtao
 * Create: 2023-07-25
 */

#include <gtest/gtest.h>
#include <fstream>
#include "sandbox.h"
#include "sandbox_ops.h"
#include "mock.h"
#include "utils_file.h"

extern "C" {
    DECLARE_WRAPPER(util_file_exists, bool, (const char * path));
    DEFINE_WRAPPER(util_file_exists, bool, (const char * path), (path));
    DECLARE_WRAPPER(mount, int, (const char *__special_file, const char *__dir,
		  const char *__fstype, unsigned long int __rwflag,
		  const void *__data));
    DEFINE_WRAPPER(mount, int, (const char *__special_file, const char *__dir,
		  const char *__fstype, unsigned long int __rwflag,
		  const void *__data), (__special_file, __dir, __fstype, __rwflag, __data));
}

namespace sandbox {

class SandboxTest : public testing::Test {
protected:
    void SetUp() override
    {
    }

    void TearDown() override
    {
    }
};

TEST_F(SandboxTest, TestDefaultGetters)
{
    std::string id = "12345678";
    std::string rootdir = "/test/rootdir";
    std::string statedir = "/test/statedir";
    std::string sandbox_rootdir = rootdir + "/" + id;
    std::string sandbox_statedir = statedir + "/" + id;
    std::string name = "test";
    RuntimeInfo info = {"runc", "shim", "kuasar"};
    std::shared_ptr<runtime::v1::PodSandboxConfig> pod_config = std::make_shared<runtime::v1::PodSandboxConfig>();
    pod_config->set_hostname("test");

    auto sandbox = std::unique_ptr<Sandbox>(new Sandbox(id, rootdir, statedir, name, info));
    ASSERT_NE(sandbox, nullptr);

    ASSERT_EQ(sandbox->IsReady(), false);
    ASSERT_STREQ(sandbox->GetId().c_str(), id.c_str());
    ASSERT_STREQ(sandbox->GetName().c_str(), name.c_str());
    ASSERT_STREQ(sandbox->GetRuntime().c_str(), info.runtime.c_str());
    ASSERT_STREQ(sandbox->GetSandboxer().c_str(), info.sandboxer.c_str());
    ASSERT_STREQ(sandbox->GetRuntimeHandle().c_str(), info.runtimeHandler.c_str());
    ASSERT_STREQ(sandbox->GetRootDir().c_str(), sandbox_rootdir.c_str());
    ASSERT_STREQ(sandbox->GetStateDir().c_str(), sandbox_statedir.c_str());
    ASSERT_STREQ(sandbox->GetResolvPath().c_str(), (sandbox_rootdir + "/resolv.conf").c_str());
    ASSERT_STREQ(sandbox->GetShmPath().c_str(), (sandbox_rootdir + "/mounts/shm").c_str());
    ASSERT_EQ(sandbox->GetStatsInfo().timestamp, 0);
    ASSERT_EQ(sandbox->GetStatsInfo().cpuUseNanos, 0);
    ASSERT_EQ(sandbox->GetNetworkReady(), false);
    ASSERT_STREQ(sandbox->GetNetMode().c_str(), DEFAULT_NETMODE.c_str());
    sandbox->SetSandboxConfig(*pod_config);
    ASSERT_STREQ(sandbox->GetMutableSandboxConfig()->hostname().c_str(), pod_config->hostname().c_str());
}

TEST_F(SandboxTest, TestGettersAndSetters)
{
    std::string id = "23456789";
    std::string rootdir = "/test2/rootdir";
    std::string statedir = "/test2/statedir";
    std::string mode = "host";

    auto sandbox = std::unique_ptr<Sandbox>(new Sandbox(id, rootdir, statedir));
    ASSERT_NE(sandbox, nullptr);

    sandbox->SetNetMode(mode);
    ASSERT_STREQ(sandbox->GetNetMode().c_str(), mode.c_str());

    sandbox->AddAnnotations("key", "value");
    EXPECT_EQ(sandbox->GetSandboxConfig().annotations().at("key"), "value");

    sandbox->RemoveAnnotations("key");
    EXPECT_TRUE(sandbox->GetSandboxConfig().annotations().empty());

    sandbox->AddLabels("key", "value");
    EXPECT_EQ(sandbox->GetSandboxConfig().labels().at("key"), "value");

    sandbox->RemoveLabels("key");
    EXPECT_TRUE(sandbox->GetSandboxConfig().labels().empty());

    StatsInfo statsInfo = {1234, 100};
    sandbox->UpdateStatsInfo(statsInfo);
    EXPECT_EQ(sandbox->GetStatsInfo().timestamp, statsInfo.timestamp);
    EXPECT_EQ(sandbox->GetStatsInfo().cpuUseNanos, statsInfo.cpuUseNanos);

    sandbox->SetNetworkReady(true);
    EXPECT_TRUE(sandbox->GetNetworkReady());
}

TEST_F(SandboxTest, TestCreateDefaultResolveConf)
{
    std::string id = "34567890";
    std::string rootdir = "/tmp/test3/rootdir";
    std::string statedir = "/tmp/test3/statedir";
    std::string name = "test";
    RuntimeInfo info = {"runc", "shim", "kuasar"};
    std::string host_nework = "host";
    Errors error;

    auto sandbox = std::unique_ptr<Sandbox>(new Sandbox(id, rootdir, statedir, name, info, host_nework));
    ASSERT_NE(sandbox, nullptr);
    MOCK_SET(util_file_exists, false);
    MOCK_SET(mount, 0);
    sandbox->PrepareSandboxDirs(error);
    ASSERT_TRUE(error.Empty());
    MOCK_CLEAR(util_file_exists);
    MOCK_CLEAR(mount);
    const std::string RESOLVE_CONF = "\nnameserver 8.8.8.8\nnameserver 8.8.4.4\n";
    std::string RESOLVE_PATH = rootdir + "/" + id + "/resolv.conf";
    ASSERT_TRUE(util_file_exists(RESOLVE_PATH.c_str()));
    std::ifstream f(RESOLVE_PATH);
    std::string line;
    std::string content = "";
    while (std::getline(f, line)) {
        content += line;
        content +="\n";
    }
    f.close();
    ASSERT_STREQ(RESOLVE_CONF.c_str(), content.c_str());
    sandbox->CleanupSandboxDirs();
    ASSERT_FALSE(util_file_exists(RESOLVE_PATH.c_str()));
}

TEST_F(SandboxTest, TestSandboxOpsOnExitFailed)
{
    ASSERT_EQ(sandbox_on_sandbox_exit(nullptr, 0), -1);
    ASSERT_EQ(sandbox_on_sandbox_exit("12345678", 0), -1);
}

}