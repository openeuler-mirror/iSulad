/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: oci_config_merge unit test
 * Author: wangfengtu
 * Create: 2019-08-20
 */

#include <stdlib.h>
#include <stdio.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "oci_config_merge.h"
#include "isula_libutils/imagetool_image.h"
#include "isula_libutils/container_config.h"
#include "oci_ut_common.h"

#define IMAGETOOL_IMAGE_FILE "../../../../../test/image/oci/oci_config_merge/imagetool_image.json"
#define OCI_RUNTIME_SPEC_FILE "../../../../../test/image/oci/oci_config_merge/oci_runtime_spec.json"
#define MALLOC_COUNT 5

static int g_malloc_count = 0;
static int g_malloc_match = 1;

extern "C" {
    DECLARE_WRAPPER_V(util_common_calloc_s, void *, (size_t size));
    DEFINE_WRAPPER_V(util_common_calloc_s, void *, (size_t size), (size));

    DECLARE_WRAPPER_V(util_smart_calloc_s, void *, (size_t size, size_t len));
    DEFINE_WRAPPER_V(util_smart_calloc_s, void *, (size_t size, size_t len), (size, len));

    DECLARE_WRAPPER(merge_env, int, (oci_runtime_spec * oci_spec, const char **env, size_t env_len));
    DEFINE_WRAPPER(merge_env, int, (oci_runtime_spec * oci_spec, const char **env, size_t env_len),
                   (oci_spec, env, env_len));
}

void *util_common_calloc_s_fail(size_t size)
{
    g_malloc_count++;

    if (g_malloc_count == g_malloc_match) {
        g_malloc_match++;
        g_malloc_count = 0;
        return nullptr;
    } else {
        return __real_util_common_calloc_s(size);
    }
}

void *util_smart_calloc_s_fail(size_t size, size_t len)
{
    g_malloc_count++;

    if (g_malloc_count == g_malloc_match) {
        g_malloc_match++;
        g_malloc_count = 0;
        return nullptr;
    } else {
        return __real_util_smart_calloc_s(size, len);
    }
}

TEST(oci_config_merge_ut, test_oci_image_merge_config)
{
    char *imagetool_image_file = nullptr;
    imagetool_image *tool_image = nullptr;
    container_config *custom_config = nullptr;
    char *err = nullptr;
    int i = 0;

    // All parameter nullptr
    ASSERT_NE(oci_image_merge_config(nullptr, nullptr), 0);

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    ASSERT_NE(oci_image_merge_config(nullptr, custom_config), 0);

    free_container_config(custom_config);
    custom_config = nullptr;

    // Parameter oci_spec is nullptr
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    ASSERT_EQ(oci_image_merge_config(tool_image, custom_config), 0);

    free_imagetool_image(tool_image);
    tool_image = nullptr;
    free_container_config(custom_config);
    custom_config = nullptr;

    // Parameter custom_spec is nullptr
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;

    ASSERT_NE(oci_image_merge_config(tool_image, nullptr), 0);

    free_imagetool_image(tool_image);
    tool_image = nullptr;

    // All parameter collect
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    ASSERT_EQ(oci_image_merge_config(tool_image, custom_config), 0);

    free_imagetool_image(tool_image);
    tool_image = nullptr;
    free_container_config(custom_config);
    custom_config = nullptr;

    // image_config's volumes not nullptr
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    ASSERT_TRUE(tool_image->spec->config != nullptr);
    ASSERT_TRUE(tool_image->spec->config->volumes == nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;
    tool_image->spec->config->volumes = (defs_map_string_object *)util_common_calloc_s(sizeof(defs_map_string_object));
    ASSERT_TRUE(tool_image->spec->config->volumes != nullptr);
    tool_image->spec->config->volumes->keys = single_array_from_string("/data");
    ASSERT_TRUE(tool_image->spec->config->volumes->keys != nullptr);
    tool_image->spec->config->volumes->values =
        (defs_map_string_object_element **)util_common_calloc_s(sizeof(defs_map_string_object_element *));
    ASSERT_TRUE(tool_image->spec->config->volumes->values != nullptr);
    tool_image->spec->config->volumes->len = 1;

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    ASSERT_EQ(oci_image_merge_config(tool_image, custom_config), 0);

    free_imagetool_image(tool_image);
    tool_image = nullptr;
    free_container_config(custom_config);
    custom_config = nullptr;

    // Config merge condition 1
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;
    ASSERT_TRUE(tool_image->spec->config != nullptr);

    free(tool_image->spec->config->working_dir);
    tool_image->spec->config->working_dir = util_strdup_s("/root");
    ASSERT_TRUE(tool_image->spec->config->working_dir != nullptr);

    util_free_array(tool_image->spec->config->env);
    tool_image->spec->config->env = single_array_from_string("A=a");
    ASSERT_TRUE(tool_image->spec->config->env != nullptr);
    tool_image->spec->config->env_len = 1;

    util_free_array(tool_image->spec->config->cmd);
    tool_image->spec->config->cmd = single_array_from_string("/bin/echo");
    ASSERT_TRUE(tool_image->spec->config->cmd != nullptr);
    tool_image->spec->config->cmd_len = 1;

    util_free_array(tool_image->spec->config->entrypoint);
    tool_image->spec->config->entrypoint = single_array_from_string("/bin/ls");
    ASSERT_TRUE(tool_image->spec->config->entrypoint != nullptr);
    tool_image->spec->config->entrypoint_len = 1;

    free(tool_image->spec->config->user);
    tool_image->spec->config->user = util_strdup_s("mail");
    ASSERT_TRUE(tool_image->spec->config->user != nullptr);

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    util_free_array(custom_config->cmd);
    custom_config->cmd = single_array_from_string("/bin/mkdir");
    ASSERT_TRUE(custom_config->cmd != nullptr);
    custom_config->cmd_len = 1;

    util_free_array(custom_config->entrypoint);
    custom_config->entrypoint = single_array_from_string("/bin/rmdir");
    ASSERT_TRUE(custom_config->entrypoint != nullptr);
    custom_config->entrypoint_len = 1;

    free(custom_config->user);
    custom_config->user = util_strdup_s("daemon");
    ASSERT_TRUE(custom_config->user != nullptr);

    custom_config->healthcheck = (defs_health_check *)util_common_calloc_s(sizeof(defs_health_check));
    ASSERT_TRUE(custom_config->healthcheck != nullptr);

    ASSERT_EQ(oci_image_merge_config(tool_image, custom_config), 0);

    ASSERT_STREQ(custom_config->working_dir, "/root");

    ASSERT_TRUE(custom_config->env != nullptr);
    ASSERT_STREQ(custom_config->env[0], "A=a");
    ASSERT_EQ(custom_config->env_len, 1);

    ASSERT_TRUE(custom_config->cmd != nullptr);
    ASSERT_STREQ(custom_config->cmd[0], "/bin/mkdir");
    ASSERT_EQ(custom_config->cmd_len, 1);

    ASSERT_TRUE(custom_config->entrypoint != nullptr);
    ASSERT_STREQ(custom_config->entrypoint[0], "/bin/rmdir");
    ASSERT_EQ(custom_config->entrypoint_len, 1);

    ASSERT_STREQ(custom_config->user, "daemon");

    free_imagetool_image(tool_image);
    tool_image = nullptr;
    free_container_config(custom_config);
    custom_config = nullptr;

    // Config merge condition 2
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;
    ASSERT_TRUE(tool_image->spec->config != nullptr);

    free(tool_image->spec->config->working_dir);
    tool_image->spec->config->working_dir = nullptr;

    util_free_array(tool_image->spec->config->env);
    tool_image->spec->config->env = nullptr;
    tool_image->spec->config->env_len = 0;

    util_free_array(tool_image->spec->config->cmd);
    tool_image->spec->config->cmd = single_array_from_string("/bin/echo");
    ASSERT_TRUE(tool_image->spec->config->cmd != nullptr);
    tool_image->spec->config->cmd_len = 1;

    util_free_array(tool_image->spec->config->entrypoint);
    tool_image->spec->config->entrypoint = single_array_from_string("/bin/ls");
    ASSERT_TRUE(tool_image->spec->config->entrypoint != nullptr);
    tool_image->spec->config->entrypoint_len = 1;

    free(tool_image->spec->config->user);
    tool_image->spec->config->user = util_strdup_s("mail");
    ASSERT_TRUE(tool_image->spec->config->user != nullptr);

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    util_free_array(custom_config->cmd);
    custom_config->cmd = nullptr;
    custom_config->cmd_len = 0;

    util_free_array(custom_config->entrypoint);
    custom_config->entrypoint = nullptr;
    custom_config->entrypoint_len = 0;

    free(custom_config->user);
    custom_config->user = nullptr;

    ASSERT_EQ(oci_image_merge_config(tool_image, custom_config), 0);

    ASSERT_STREQ(custom_config->working_dir, nullptr);

    ASSERT_EQ(custom_config->env_len, 0);

    ASSERT_TRUE(custom_config->cmd != nullptr);
    ASSERT_STREQ(custom_config->cmd[0], "/bin/echo");
    ASSERT_EQ(custom_config->cmd_len, 1);

    ASSERT_TRUE(custom_config->entrypoint != nullptr);
    ASSERT_STREQ(custom_config->entrypoint[0], "/bin/ls");
    ASSERT_EQ(custom_config->entrypoint_len, 1);

    ASSERT_STREQ(custom_config->user, "mail");

    free_imagetool_image(tool_image);
    tool_image = nullptr;
    free_container_config(custom_config);
    custom_config = nullptr;

    // Test malloc failed
    for (i = 0; i < MALLOC_COUNT; i++) {
        imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
        ASSERT_TRUE(imagetool_image_file != nullptr);
        tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
        ASSERT_TRUE(tool_image != nullptr);
        ASSERT_TRUE(tool_image->spec != nullptr);
        free(err);
        err = nullptr;
        free(imagetool_image_file);
        imagetool_image_file = nullptr;

        custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
        ASSERT_TRUE(custom_config != nullptr);

        g_malloc_match = 1;
        // Test update_health_check_from_image executed failed caused by malloc failed.
        if (i == 3) {
            g_malloc_match = 2;
            custom_config->healthcheck = (defs_health_check *)util_common_calloc_s(sizeof(defs_health_check));
            ASSERT_TRUE(custom_config->healthcheck != nullptr);
        }
        // Test do_duplicate_entrypoints executed failed caused by malloc failed.
        if (i == 4) {
            g_malloc_match = 2;
            util_free_array(tool_image->spec->config->entrypoint);
            tool_image->spec->config->entrypoint = single_array_from_string("/bin/ls");
            ASSERT_TRUE(tool_image->spec->config->entrypoint != nullptr);
            tool_image->spec->config->entrypoint_len = 1;
        }

        MOCK_SET_V(util_smart_calloc_s, util_smart_calloc_s_fail);
        ASSERT_EQ(oci_image_merge_config(tool_image, custom_config), 0);
        MOCK_CLEAR(util_smart_calloc_s);

        free_imagetool_image(tool_image);
        tool_image = nullptr;
        free_container_config(custom_config);
        custom_config = nullptr;
    }

    // Test merge_env fail
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    free_imagetool_image(tool_image);
    tool_image = nullptr;
    free_container_config(custom_config);
    custom_config = nullptr;

    // Test test_len == nullptr
    imagetool_image_file = json_path(IMAGETOOL_IMAGE_FILE);
    ASSERT_TRUE(imagetool_image_file != nullptr);
    tool_image = imagetool_image_parse_file(imagetool_image_file, nullptr, &err);
    ASSERT_TRUE(tool_image != nullptr);
    ASSERT_TRUE(tool_image->spec != nullptr);
    free(err);
    err = nullptr;
    free(imagetool_image_file);
    imagetool_image_file = nullptr;

    util_free_array(tool_image->healthcheck->test);
    tool_image->healthcheck->test = nullptr;
    tool_image->healthcheck->test_len = 0;

    custom_config = (container_config *)util_common_calloc_s(sizeof(container_config));
    ASSERT_TRUE(custom_config != nullptr);

    ASSERT_EQ(oci_image_merge_config(tool_image, custom_config), 0);

    free_imagetool_image(tool_image);
    tool_image = nullptr;
    free_container_config(custom_config);
    custom_config = nullptr;
}
