/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Description: oci_rootfs_prepare llt
 * Author: wangfengtu
 * Create: 2019-08-26
 */

#include <stdlib.h>
#include <stdio.h>
#include <limits.h>
#include <securec.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "utils.h"
#include "oci_rootfs_prepare.h"
#include "oci_llt_common.h"

static int g_exec_cmd_count = 0;

DECLARE_OCI_LLT_COMMON_WRAPPER

extern "C" {
    DECLARE_WRAPPER_V(util_exec_cmd, bool, \
                      (exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg, char **stderr_msg));
    DEFINE_WRAPPER_V(util_exec_cmd, bool, \
                     (exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg, char **stderr_msg), \
                     (cb_func, args, stdin_msg, stdout_msg, stderr_msg));
}

static bool util_exec_cmd_fail(exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg,
                               char **stderr_msg)
{
    g_exec_cmd_count++;
    if (g_exec_cmd_count == 1) {
        *stderr_msg = util_strdup_s("Device or Resource Busy");
        return false;
    }

    if (g_exec_cmd_count == 2) {
        *stderr_msg = NULL;
        return false;
    }

    if (g_exec_cmd_count == 3) {
        *stdout_msg = NULL;
        return true;
    }

    if (g_exec_cmd_count == 4) {
        *stdout_msg = util_strdup_s("invalid");
        return true;
    }

    return 0;
}

#define OCI_IMAGE_SPEC_FILE "image/oci/oci_rootfs_prepare/prepare_response.json"

static imagetool_prepare_response *prepare_response_from_json()
{
    imagetool_prepare_response *response = NULL;
    parser_error err = NULL;
    char *json_file = NULL;

    json_file = json_path(OCI_IMAGE_SPEC_FILE);
    if (json_file == NULL) {
        return NULL;
    }

    response = imagetool_prepare_response_parse_file(json_file, NULL, &err);
    if (response == NULL) {
        goto out;
    }

out:
    free(json_file);
    json_file = NULL;

    free(err);
    err = NULL;

    return response;
}

static int execvp_prepare_success(const char *file, char * const argv[])
{
    char *json_file = NULL;

    json_file = json_path(OCI_IMAGE_SPEC_FILE);
    if (json_file == NULL) {
        return -1;
    }

    execlp("cat", "cat", json_file, NULL);

    free(json_file);
    json_file = NULL;

    return -1;
}

TEST(oci_rootfs_prepare_llt, test_prepare_rootfs_and_get_image_conf)
{
    // In order to skip codingstyle check. Error info "Lines should very rarely be longer than 120 characters"
#define RESP_MP "/var/lib/lcrd/storage/overlay/f50fdf298b3881051cbc383e3b293619dfb53c98805937784096353302d2b213/merged"
    rootfs_prepare_request *req = NULL;
    rootfs_prepare_and_get_image_conf_response *resp = NULL;
    int i = 0;

    // Test parameter NULL part1
    ASSERT_NE(prepare_rootfs_and_get_image_conf(NULL, NULL), 0);
    ASSERT_NE(prepare_rootfs_and_get_image_conf(NULL, &resp), 0);
    free_rootfs_prepare_and_get_image_conf_response(resp);
    resp = NULL;
    // Test parameter NULL part2
    req = (rootfs_prepare_request*)util_common_calloc_s(sizeof(rootfs_prepare_request));
    ASSERT_TRUE(req != NULL);
    ASSERT_NE(prepare_rootfs_and_get_image_conf(req, &resp), 0);
    free_rootfs_prepare_and_get_image_conf_response(resp);
    resp = NULL;
    // Test parameter NULL part3
    req = (rootfs_prepare_request*)util_common_calloc_s(sizeof(rootfs_prepare_request));
    ASSERT_TRUE(req != NULL);
    req->image = util_strdup_s("image_name");
    ASSERT_TRUE(req->image != NULL);
    ASSERT_NE(prepare_rootfs_and_get_image_conf(req, &resp), 0);
    free_rootfs_prepare_request(req);
    req = NULL;
    free_rootfs_prepare_and_get_image_conf_response(resp);
    resp = NULL;
    // Test parameter NULL part4
    req = (rootfs_prepare_request*)util_common_calloc_s(sizeof(rootfs_prepare_request));
    ASSERT_TRUE(req != NULL);
    req->name = util_strdup_s("name");
    ASSERT_TRUE(req->name != NULL);
    ASSERT_NE(prepare_rootfs_and_get_image_conf(req, &resp), 0);
    free_rootfs_prepare_request(req);
    req = NULL;
    free_rootfs_prepare_and_get_image_conf_response(resp);
    resp = NULL;

    // Test parameter collect
    req = (rootfs_prepare_request*)util_common_calloc_s(sizeof(rootfs_prepare_request));
    ASSERT_TRUE(req != NULL);
    req->image = util_strdup_s("image_name");
    ASSERT_TRUE(req->image != NULL);
    req->name = util_strdup_s("name");
    ASSERT_TRUE(req->name != NULL);
    req->id = util_strdup_s("0ac632258473464fa06a317e0347834ba652a00080506f5ea10e9ef8e7db5459");
    ASSERT_TRUE(req->id != NULL);
    req->storage_opts = conf_get_storage_opts_success();
    ASSERT_TRUE(req->storage_opts != NULL);
    req->storage_opts_len = 1;

    MOCK_SET_DEFAULT_ISULAD_KIT_OPTS
    MOCK_SET_V(execvp, execvp_prepare_success);
    ASSERT_EQ(prepare_rootfs_and_get_image_conf(req, &resp), 0);
    ASSERT_TRUE(resp != NULL);
    ASSERT_TRUE(resp->raw_response != NULL);
    ASSERT_STREQ(resp->raw_response->mount_point, RESP_MP);
    MOCK_CLEAR_DEFAULT_ISULAD_KIT_OPTS
    MOCK_CLEAR(execvp);

    free_rootfs_prepare_request(req);
    req = NULL;
    free_rootfs_prepare_and_get_image_conf_response(resp);
    resp = NULL;

    // Put MOCK_SET_V here to avoid warning "(style) Local variable MOCK_SET_V shadows outer variable"
    MOCK_SET_V(util_exec_cmd, util_exec_cmd_fail);
    // 1. Test util_exec_cmd failed with stderr_buffer != NULL
    // 2. Test util_exec_cmd failed with stderr_buffer == NULL
    // 3. Test util_exec_cmd success with stdout_buffer == NULL
    // 4. Test util_exec_cmd success with stdout_buffer invalid
    for (i = 0; i < 4; i++) {
        req = (rootfs_prepare_request*)util_common_calloc_s(sizeof(rootfs_prepare_request));
        ASSERT_TRUE(req != NULL);
        req->image = util_strdup_s("image_name");
        ASSERT_TRUE(req->image != NULL);
        req->name = util_strdup_s("name");
        ASSERT_TRUE(req->name != NULL);
        req->id = util_strdup_s("0ac632258473464fa06a317e0347834ba652a00080506f5ea10e9ef8e7db5459");
        ASSERT_TRUE(req->id != NULL);
        req->storage_opts = conf_get_storage_opts_success();
        ASSERT_TRUE(req->storage_opts != NULL);
        req->storage_opts_len = 1;

        MOCK_SET_DEFAULT_ISULAD_KIT_OPTS
        ASSERT_NE(prepare_rootfs_and_get_image_conf(req, &resp), 0);
        MOCK_CLEAR_DEFAULT_ISULAD_KIT_OPTS

        free_rootfs_prepare_request(req);
        req = NULL;
        free_rootfs_prepare_and_get_image_conf_response(resp);
        resp = NULL;
    }
    MOCK_CLEAR(util_exec_cmd);
}

TEST(oci_rootfs_prepare_llt, test_free_rootfs_prepare_request)
{
    rootfs_prepare_request *req = NULL;

    // Test free NULL
    free_rootfs_prepare_request(NULL);

    // Test free content NULL
    req = (rootfs_prepare_request*)util_common_calloc_s(sizeof(rootfs_prepare_request));
    ASSERT_TRUE(req != NULL);

    free_rootfs_prepare_request(req);
    req = NULL;

    // Test free all Not NULL
    req = (rootfs_prepare_request*)util_common_calloc_s(sizeof(rootfs_prepare_request));
    ASSERT_TRUE(req != NULL);
    req->image = util_strdup_s("image_name");
    ASSERT_TRUE(req->image != NULL);
    req->name = util_strdup_s("name");
    ASSERT_TRUE(req->name != NULL);
    req->id = util_strdup_s("0ac632258473464fa06a317e0347834ba652a00080506f5ea10e9ef8e7db5459");
    ASSERT_TRUE(req->id != NULL);
    req->storage_opts = conf_get_storage_opts_success();
    ASSERT_TRUE(req->storage_opts != NULL);
    req->storage_opts_len = 1;

    free_rootfs_prepare_request(req);
    req = NULL;
}

TEST(oci_rootfs_prepare_llt, test_free_rootfs_prepare_and_get_image_conf_response)
{
    size_t size = 0;
    rootfs_prepare_and_get_image_conf_response *resp = NULL;

    // Test free NULL
    free_rootfs_prepare_and_get_image_conf_response(NULL);

    // Test free errmsg NULL
    size = sizeof(rootfs_prepare_and_get_image_conf_response);
    resp = (rootfs_prepare_and_get_image_conf_response*)util_common_calloc_s(size);
    ASSERT_TRUE(resp != NULL);

    free_rootfs_prepare_and_get_image_conf_response(resp);
    resp = NULL;

    // Test free all Not NULL
    size = sizeof(rootfs_prepare_and_get_image_conf_response);
    resp = (rootfs_prepare_and_get_image_conf_response*)util_common_calloc_s(size);
    ASSERT_TRUE(resp != NULL);

    resp->errmsg = util_strdup_s("This is error message");
    ASSERT_TRUE(resp->errmsg != NULL);

    resp->raw_response = prepare_response_from_json();
    ASSERT_TRUE(resp->raw_response != NULL);

    free_rootfs_prepare_and_get_image_conf_response(resp);
    resp = NULL;
}
