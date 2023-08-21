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

#include "sandbox.h"

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

    auto sandbox = new Sandbox(id, rootdir, statedir, name, info);
    ASSERT_NE(sandbox, nullptr);

    ASSERT_EQ(sandbox->IsReady(), false);
    ASSERT_STREQ(sandbox->GetId().c_str(), id.c_str());
    ASSERT_STREQ(sandbox->GetName().c_str(), name.c_str());
    ASSERT_STREQ(sandbox->GetRuntime().c_str(), info.runtime.c_str());
    ASSERT_STREQ(sandbox->GetSandboxer().c_str(), info.sandboxer.c_str());
    ASSERT_STREQ(sandbox->GetRuntimeHandle().c_str(), info.runtimeHandler.c_str());
    ASSERT_EQ(sandbox->GetContainers().size(), 0);
    ASSERT_STREQ(sandbox->GetRootDir().c_str(), sandbox_rootdir.c_str());
    ASSERT_STREQ(sandbox->GetStateDir().c_str(), sandbox_statedir.c_str());
    ASSERT_STREQ(sandbox->GetResolvPath().c_str(), (sandbox_rootdir + "/resolv.conf").c_str());
    ASSERT_STREQ(sandbox->GetShmPath().c_str(), (sandbox_rootdir + "/mounts/shm").c_str());
    ASSERT_EQ(sandbox->GetStatsInfo().timestamp, 0);
    ASSERT_EQ(sandbox->GetStatsInfo().cpuUseNanos, 0);
    ASSERT_EQ(sandbox->GetNetworkReady(), false);
    ASSERT_STREQ(sandbox->GetNetMode().c_str(), DEFAULT_NETMODE.c_str());
}

TEST_F(SandboxTest, TestGettersAndSetters)
{
    std::string id = "23456789";
    std::string rootdir = "/test2/rootdir";
    std::string statedir = "/test2/statedir";
    std::string mode = "host";

    auto sandbox = new Sandbox(id, rootdir, statedir);
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

    std::string containerId = "container_id";
    sandbox->AddContainer(containerId);
    auto Mycontainers = sandbox->GetContainers();
    auto it = std::find(Mycontainers.begin(), Mycontainers.end(), containerId);
    EXPECT_NE(Mycontainers.end(), it);

    sandbox->RemoveContainer(containerId);
    EXPECT_EQ(sandbox->GetContainers().size(), 0);

    std::vector<std::string> containers = {"container1", "container2"};
    sandbox->SetConatiners(containers);
    EXPECT_EQ(sandbox->GetContainers(), containers);

    StatsInfo statsInfo = {1234, 100};
    sandbox->UpdateStatsInfo(statsInfo);
    EXPECT_EQ(sandbox->GetStatsInfo().timestamp, statsInfo.timestamp);
    EXPECT_EQ(sandbox->GetStatsInfo().cpuUseNanos, statsInfo.cpuUseNanos);

    sandbox->SetNetworkReady(true);
    EXPECT_TRUE(sandbox->GetNetworkReady());
}

}