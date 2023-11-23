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
 * Description: specs verify ut
 * Author: xuxuepeng
 * Create: 2023-11-16
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "sysinfo.h"
#include "utils.h"

using namespace std;

#define HOST_CONFIG_FILE "../../../../test/specs/verify/hostconfig.json"
#define OCI_RUNTIME_SPEC_FILE "../../../../test/specs/verify/oci_runtime_spec.json"

extern "C" {
    int verify_resources_cpuset(const sysinfo_t *sysinfo, const char *cpus, const char *mems);
}

/* get sys info */
sysinfo_t *create_sys_info_for_cpuset_test(const char *cpus, const char *mems, int ncpus_conf, int ncpus)
{
    sysinfo_t *sysinfo = NULL;

    sysinfo = (sysinfo_t *)util_common_calloc_s(sizeof(sysinfo_t));
    if (sysinfo == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    sysinfo->ncpus = ncpus;
    sysinfo->ncpus_conf = ncpus_conf;

    sysinfo->cpusetinfo.cpuset = true;
    sysinfo->cpusetinfo.cpus = util_strdup_s(cpus);
    sysinfo->cpusetinfo.mems = util_strdup_s(mems);

    return sysinfo;
}

void test_different_provided_cpus_mems(sysinfo_t *sysinfo, const char *provided_cpus, const char *provided_mems,
                                       int expected)
{
    int ret = 0;
    ret = verify_resources_cpuset(sysinfo, provided_cpus, provided_mems);
    ASSERT_EQ(ret, expected);
}

// Test the case when provided is null, and available is 0-7
TEST(test_verify_resources_cpuset, test_0_7)
{
    sysinfo_t *sysinfo = create_sys_info_for_cpuset_test("0-7", "0-7", 8, 8);
    test_different_provided_cpus_mems(sysinfo, nullptr, nullptr, 0);

    test_different_provided_cpus_mems(sysinfo, "0", "0", 0);
    test_different_provided_cpus_mems(sysinfo, "2", "2", 0);
    test_different_provided_cpus_mems(sysinfo, "7", "7", 0);
    test_different_provided_cpus_mems(sysinfo, "8", "8", -1);

    test_different_provided_cpus_mems(sysinfo, "1,2", "1,2", 0);
    test_different_provided_cpus_mems(sysinfo, "1,3,5", "1,3,5", 0);

    test_different_provided_cpus_mems(sysinfo, "0-7", "0-7", 0);
    test_different_provided_cpus_mems(sysinfo, "0-8", "0-8", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3-7", "0-1,3-7", 0);
    test_different_provided_cpus_mems(sysinfo, "0-1,3,5-7", "0-1,3,5-7", 0);

    free_sysinfo(sysinfo);
}

// Test the case when provided is null, and available is 0-1,3-7
TEST(test_verify_resources_cpuset, test_0_1_3_7)
{
    sysinfo_t *sysinfo = create_sys_info_for_cpuset_test("0-1,3-7", "0-1,3-7", 8, 7);
    test_different_provided_cpus_mems(sysinfo, nullptr, nullptr, 0);

    test_different_provided_cpus_mems(sysinfo, "0", "0", 0);
    test_different_provided_cpus_mems(sysinfo, "2", "2", -1);
    test_different_provided_cpus_mems(sysinfo, "7", "7", 0);
    test_different_provided_cpus_mems(sysinfo, "8", "8", -1);

    test_different_provided_cpus_mems(sysinfo, "1,2", "1,2", -1);
    test_different_provided_cpus_mems(sysinfo, "1,3,5", "1,3,5", 0);

    test_different_provided_cpus_mems(sysinfo, "0-7", "0-7", -1);
    test_different_provided_cpus_mems(sysinfo, "0-8", "0-8", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3-7", "0-1,3-7", 0);
    test_different_provided_cpus_mems(sysinfo, "0-1,3,5-7", "0-1,3,5-7", 0);

    free_sysinfo(sysinfo);
}

// Test the case when provided is null, and available is 0-6
TEST(test_verify_resources_cpuset, test_0_6)
{
    sysinfo_t *sysinfo = create_sys_info_for_cpuset_test("0-6", "0-6", 8, 7);

    test_different_provided_cpus_mems(sysinfo, nullptr, nullptr, 0);

    test_different_provided_cpus_mems(sysinfo, "0", "0", 0);
    test_different_provided_cpus_mems(sysinfo, "2", "2", 0);
    test_different_provided_cpus_mems(sysinfo, "7", "7", -1);
    test_different_provided_cpus_mems(sysinfo, "8", "8", -1);

    test_different_provided_cpus_mems(sysinfo, "1,2", "1,2", 0);
    test_different_provided_cpus_mems(sysinfo, "1,3,5", "1,3,5", 0);

    test_different_provided_cpus_mems(sysinfo, "0-7", "0-7", -1);
    test_different_provided_cpus_mems(sysinfo, "0-8", "0-8", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3-7", "0-1,3-7", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3,5-7", "0-1,3,5-7", -1);

    free_sysinfo(sysinfo);
}

// Test the case when provided is null, and available is 1-7
TEST(test_verify_resources_cpuset, test_1_7)
{
    sysinfo_t *sysinfo = create_sys_info_for_cpuset_test("1-7", "1-7", 8, 7);

    test_different_provided_cpus_mems(sysinfo, nullptr, nullptr, 0);

    test_different_provided_cpus_mems(sysinfo, "0", "0", -1);
    test_different_provided_cpus_mems(sysinfo, "2", "2", 0);
    test_different_provided_cpus_mems(sysinfo, "7", "7", 0);
    test_different_provided_cpus_mems(sysinfo, "8", "8", -1);

    test_different_provided_cpus_mems(sysinfo, "1,2", "1,2", 0);
    test_different_provided_cpus_mems(sysinfo, "1,3,5", "1,3,5", 0);

    test_different_provided_cpus_mems(sysinfo, "0-7", "0-7", -1);
    test_different_provided_cpus_mems(sysinfo, "0-8", "0-8", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3-7", "0-1,3-7", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3,5-7", "0-1,3,5-7", -1);

    free_sysinfo(sysinfo);
}

// Test the case when provided is null, and available is 0,3
TEST(test_verify_resources_cpuset, test_null_03)
{
    sysinfo_t *sysinfo = create_sys_info_for_cpuset_test("0,3", "0,3", 8, 2);
    test_different_provided_cpus_mems(sysinfo, nullptr, nullptr, 0);

    test_different_provided_cpus_mems(sysinfo, "0", "0", 0);
    test_different_provided_cpus_mems(sysinfo, "2", "2", -1);
    test_different_provided_cpus_mems(sysinfo, "7", "7", -1);
    test_different_provided_cpus_mems(sysinfo, "8", "8", -1);

    test_different_provided_cpus_mems(sysinfo, "1,2", "1,2", -1);
    test_different_provided_cpus_mems(sysinfo, "1,3,5", "1,3,5", -1);

    test_different_provided_cpus_mems(sysinfo, "0-7", "0-7", -1);
    test_different_provided_cpus_mems(sysinfo, "0-8", "0-8", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3-7", "0-1,3-7", -1);
    test_different_provided_cpus_mems(sysinfo, "0-1,3,5-7", "0-1,3,5-7", -1);

    free_sysinfo(sysinfo);
}
