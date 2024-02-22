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
 * Description: specs unit test
 * Author: huangsong
 * Create: 2023-01-29
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "daemon_arguments.h"
#include "isulad_config.h"
#include "mock.h"
#include "sysinfo.h"
#include "utils.h"

extern "C" {
    DECLARE_WRAPPER(util_common_calloc_s, void *, (size_t size));
    DEFINE_WRAPPER(util_common_calloc_s, void *, (size_t size), (size));
}

struct service_arguments *new_args(int64_t cpu_rt_period, int64_t cpu_rt_runtime)
{
    struct service_arguments *args = (struct service_arguments *)util_common_calloc_s(sizeof(struct service_arguments));
    if (args == nullptr) {
        std::cerr << "Out of memory" << std::endl;
        return nullptr;
    }

    args->json_confs = (isulad_daemon_configs *)util_common_calloc_s(sizeof(isulad_daemon_configs));
    if (args->json_confs == nullptr) {
        std::cerr << "Out of memory" << std::endl;
        free(args);
        return nullptr;
    }

    args->json_confs->cpu_rt_period = cpu_rt_period;
    args->json_confs->cpu_rt_runtime = cpu_rt_runtime;

    return args;
}

TEST(CgroupCpuUnitTest, test_conf_get_cgroup_cpu_rt)
{
    int64_t cpu_rt_period = 0;
    int64_t cpu_rt_runtime = 0;

    ASSERT_EQ(conf_get_cgroup_cpu_rt(nullptr, nullptr), -1);
    ASSERT_EQ(conf_get_cgroup_cpu_rt(&cpu_rt_period, nullptr), -1);
    ASSERT_EQ(conf_get_cgroup_cpu_rt(nullptr, &cpu_rt_runtime), -1);

    struct service_arguments *args = new_args(cpu_rt_period, cpu_rt_runtime);
    ASSERT_EQ(save_args_to_conf(args), 0);
    ASSERT_EQ(conf_get_cgroup_cpu_rt(&cpu_rt_period, &cpu_rt_runtime), 0);
    ASSERT_EQ(cpu_rt_period, 0);
    ASSERT_EQ(cpu_rt_runtime, 0);
}

TEST(CgroupCpuUnitTest, test_common_find_cgroup_mnt_and_root)
{
    char *mnt = NULL;
    char *root = NULL;

    int ret = cgroup_ops_init();
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(common_get_cgroup_mnt_and_root_path(nullptr, &mnt, &root), -1);
}

TEST(CgroupCpuUnitTest, test_sysinfo_cgroup_controller_cpurt_mnt_path)
{
    MOCK_SET(util_common_calloc_s, nullptr);
    ASSERT_EQ(get_sys_info(true), nullptr);
    
    int ret = cgroup_ops_init();
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(sysinfo_get_cpurt_mnt_path(), nullptr);
    MOCK_CLEAR(util_common_calloc_s);
}
