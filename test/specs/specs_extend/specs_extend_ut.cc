/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: specs extend unit test
 * Author: lifeng
 * Create: 2020-02-18
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "specs_api.h"
#include "isula_libutils/host_config.h"
#include "isula_libutils/container_config.h"
#include "oci_ut_common.h"
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "isulad_config_mock.h"
#include "isula_libutils/oci_runtime_hooks.h"
#include "utils.h"
#include "specs_extend.h"

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

#define HOOKS_CONFIG_FILE "../../../../test/specs/specs_extend/hooks.json"

TEST(make_sure_oci_spec_linux_ut, test_make_sure_oci_spec_linux)
{
    oci_runtime_spec *oci_spec = NULL;
    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    ASSERT_EQ(make_sure_oci_spec_linux(oci_spec), 0);
    ASSERT_TRUE(oci_spec->linux != NULL);
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}

TEST(make_sure_oci_spec_process_ut, test_make_sure_oci_spec_process)
{
    oci_runtime_spec *oci_spec = NULL;
    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    ASSERT_EQ(make_sure_oci_spec_process(oci_spec), 0);
    ASSERT_TRUE(oci_spec->process != NULL);
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}

TEST(make_sure_oci_spec_linux_resources_ut, test_make_sure_oci_spec_linux_resources)
{
    oci_runtime_spec *oci_spec = NULL;
    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    ASSERT_EQ(make_sure_oci_spec_linux_resources(oci_spec), 0);
    ASSERT_TRUE(oci_spec->linux != NULL);
    ASSERT_TRUE(oci_spec->linux->resources != NULL);
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}

TEST(make_sure_oci_spec_linux_resources_blkio_ut, test_make_sure_oci_spec_linux_resources_blkio)
{
    oci_runtime_spec *oci_spec = NULL;
    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    ASSERT_EQ(make_sure_oci_spec_linux_resources_blkio(oci_spec), 0);
    ASSERT_TRUE(oci_spec->linux != NULL);
    ASSERT_TRUE(oci_spec->linux->resources != NULL);
    ASSERT_TRUE(oci_spec->linux->resources->block_io != NULL);
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}

TEST(merge_hooks_ut, test_merge_hooks_invalid)
{
    ASSERT_NE(merge_hooks(nullptr, nullptr), 0);
}

TEST(merge_hooks_ut, test_merge_hooks_ut_2)
{
    oci_runtime_spec *oci_spec = NULL;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    oci_spec->hooks = (oci_runtime_spec_hooks *)util_common_calloc_s(sizeof(oci_runtime_spec_hooks));
    ASSERT_NE(merge_hooks(oci_spec->hooks, NULL), 0);
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}

TEST(merge_hooks_ut, test_merge_hooks_ut_3)
{
    char *hooks_config_file = NULL;
    oci_runtime_spec_hooks *hooks_spec = NULL;
    char *err = NULL;

    hooks_config_file = json_path(HOOKS_CONFIG_FILE);
    ASSERT_TRUE(hooks_config_file != NULL);
    hooks_spec = oci_runtime_spec_hooks_parse_file(hooks_config_file, NULL, &err);
    ASSERT_TRUE(hooks_spec != NULL);
    free(err);
    err = NULL;
    free(hooks_config_file);
    hooks_config_file = NULL;
    ASSERT_NE(merge_hooks(NULL, hooks_spec), 0);
    free_oci_runtime_spec_hooks(hooks_spec);
    hooks_spec = NULL;
}

TEST(merge_hooks_ut, test_merge_hooks_ut_4)
{
    char *hooks_config_file = NULL;
    oci_runtime_spec_hooks *hooks_spec = NULL;
    oci_runtime_spec *oci_spec = NULL;
    char *err = NULL;

    // All parameter correct
    hooks_config_file = json_path(HOOKS_CONFIG_FILE);
    ASSERT_TRUE(hooks_config_file != NULL);
    hooks_spec = oci_runtime_spec_hooks_parse_file(hooks_config_file, NULL, &err);
    ASSERT_TRUE(hooks_spec != NULL);
    free(err);
    err = NULL;
    free(hooks_config_file);
    hooks_config_file = NULL;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    oci_spec->hooks = (oci_runtime_spec_hooks *)util_common_calloc_s(sizeof(oci_runtime_spec_hooks));

    ASSERT_EQ(merge_hooks(oci_spec->hooks, hooks_spec), 0);

    free_oci_runtime_spec_hooks(hooks_spec);
    hooks_spec = NULL;
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}
TEST(merge_hooks_ut, test_merge_hooks_ut_prestart)
{
    char *hooks_config_file = NULL;
    oci_runtime_spec_hooks *hooks_spec = NULL;
    oci_runtime_spec *oci_spec = NULL;
    char *err = NULL;

    // All parameter correct
    hooks_config_file = json_path(HOOKS_CONFIG_FILE);
    ASSERT_TRUE(hooks_config_file != NULL);
    hooks_spec = oci_runtime_spec_hooks_parse_file(hooks_config_file, NULL, &err);
    ASSERT_TRUE(hooks_spec != NULL);
    free(err);
    err = NULL;
    free(hooks_config_file);
    hooks_config_file = NULL;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    oci_spec->hooks = (oci_runtime_spec_hooks *)util_common_calloc_s(sizeof(oci_runtime_spec_hooks));

    ASSERT_EQ(merge_hooks(oci_spec->hooks, hooks_spec), 0);
    ASSERT_EQ(oci_spec->hooks->prestart_len, 1);
    ASSERT_STREQ(oci_spec->hooks->prestart[0]->path, "/home/hooks/start.bash");
    ASSERT_EQ(oci_spec->hooks->prestart[0]->args_len, 3);
    ASSERT_STREQ(oci_spec->hooks->prestart[0]->args[0], "arg0");
    ASSERT_STREQ(oci_spec->hooks->prestart[0]->args[1], "arg1");
    ASSERT_STREQ(oci_spec->hooks->prestart[0]->args[2], "arg2");
    ASSERT_EQ(oci_spec->hooks->prestart[0]->env_len, 1);
    ASSERT_STREQ(oci_spec->hooks->prestart[0]->env[0], "key1=value1");
    ASSERT_EQ(oci_spec->hooks->prestart[0]->timeout, 40);

    free_oci_runtime_spec_hooks(hooks_spec);
    hooks_spec = NULL;
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}

TEST(merge_hooks_ut, test_merge_hooks_ut_poststart)
{
    char *hooks_config_file = NULL;
    oci_runtime_spec_hooks *hooks_spec = NULL;
    oci_runtime_spec *oci_spec = NULL;
    char *err = NULL;

    // All parameter correct
    hooks_config_file = json_path(HOOKS_CONFIG_FILE);
    ASSERT_TRUE(hooks_config_file != NULL);
    hooks_spec = oci_runtime_spec_hooks_parse_file(hooks_config_file, NULL, &err);
    ASSERT_TRUE(hooks_spec != NULL);
    free(err);
    err = NULL;
    free(hooks_config_file);
    hooks_config_file = NULL;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    oci_spec->hooks = (oci_runtime_spec_hooks *)util_common_calloc_s(sizeof(oci_runtime_spec_hooks));

    ASSERT_EQ(merge_hooks(oci_spec->hooks, hooks_spec), 0);
    ASSERT_EQ(oci_spec->hooks->poststart_len, 2);
    ASSERT_STREQ(oci_spec->hooks->poststart[0]->path, "/home/hooks/post1.bash");
    ASSERT_EQ(oci_spec->hooks->poststart[0]->args_len, 3);
    ASSERT_STREQ(oci_spec->hooks->poststart[0]->args[0], "arg5");
    ASSERT_STREQ(oci_spec->hooks->poststart[0]->args[1], "arg6");
    ASSERT_STREQ(oci_spec->hooks->poststart[0]->args[2], "arg7");
    ASSERT_EQ(oci_spec->hooks->poststart[0]->env_len, 1);
    ASSERT_STREQ(oci_spec->hooks->poststart[0]->env[0], "key2=value221");
    ASSERT_EQ(oci_spec->hooks->poststart[0]->timeout, 60);

    ASSERT_STREQ(oci_spec->hooks->poststart[1]->path, "/home/hooks/post2.bash");
    ASSERT_EQ(oci_spec->hooks->poststart[1]->args_len, 3);
    ASSERT_STREQ(oci_spec->hooks->poststart[1]->args[0], "arg51");
    ASSERT_STREQ(oci_spec->hooks->poststart[1]->args[1], "arg61");
    ASSERT_STREQ(oci_spec->hooks->poststart[1]->args[2], "arg71");
    ASSERT_EQ(oci_spec->hooks->poststart[1]->env_len, 1);
    ASSERT_STREQ(oci_spec->hooks->poststart[1]->env[0], "key3=value3");
    ASSERT_EQ(oci_spec->hooks->poststart[1]->timeout, 61);

    free_oci_runtime_spec_hooks(hooks_spec);
    hooks_spec = NULL;
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}

TEST(merge_hooks_ut, test_merge_hooks_ut_poststop)
{
    char *hooks_config_file = NULL;
    oci_runtime_spec_hooks *hooks_spec = NULL;
    oci_runtime_spec *oci_spec = NULL;
    char *err = NULL;

    // All parameter correct
    hooks_config_file = json_path(HOOKS_CONFIG_FILE);
    ASSERT_TRUE(hooks_config_file != NULL);
    hooks_spec = oci_runtime_spec_hooks_parse_file(hooks_config_file, NULL, &err);
    ASSERT_TRUE(hooks_spec != NULL);
    free(err);
    err = NULL;
    free(hooks_config_file);
    hooks_config_file = NULL;

    oci_spec = (oci_runtime_spec *)util_common_calloc_s(sizeof(oci_runtime_spec));
    ASSERT_TRUE(oci_spec != NULL);
    oci_spec->hooks = (oci_runtime_spec_hooks *)util_common_calloc_s(sizeof(oci_runtime_spec_hooks));

    ASSERT_EQ(merge_hooks(oci_spec->hooks, hooks_spec), 0);
    ASSERT_EQ(oci_spec->hooks->poststop_len, 2);
    ASSERT_STREQ(oci_spec->hooks->poststop[0]->path, "/home/hooks/stop1.bash");
    ASSERT_EQ(oci_spec->hooks->poststop[0]->args_len, 3);
    ASSERT_STREQ(oci_spec->hooks->poststop[0]->args[0], "arg11");
    ASSERT_STREQ(oci_spec->hooks->poststop[0]->args[1], "arg12");
    ASSERT_STREQ(oci_spec->hooks->poststop[0]->args[2], "arg13");
    ASSERT_EQ(oci_spec->hooks->poststop[0]->env_len, 1);
    ASSERT_STREQ(oci_spec->hooks->poststop[0]->env[0], "key2=value221");
    ASSERT_EQ(oci_spec->hooks->poststop[0]->timeout, 60);

    ASSERT_STREQ(oci_spec->hooks->poststop[1]->path, "/home/hooks/stop2.bash");
    ASSERT_EQ(oci_spec->hooks->poststop[1]->args_len, 3);
    ASSERT_STREQ(oci_spec->hooks->poststop[1]->args[0], "arg52");
    ASSERT_STREQ(oci_spec->hooks->poststop[1]->args[1], "arg62");
    ASSERT_STREQ(oci_spec->hooks->poststop[1]->args[2], "arg72");
    ASSERT_EQ(oci_spec->hooks->poststop[1]->env_len, 1);
    ASSERT_STREQ(oci_spec->hooks->poststop[1]->env[0], "key4=value4");
    ASSERT_EQ(oci_spec->hooks->poststop[1]->timeout, 62);

    free_oci_runtime_spec_hooks(hooks_spec);
    hooks_spec = NULL;
    free_oci_runtime_spec(oci_spec);
    oci_spec = NULL;
}
