/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-10-18
 * Description: utils mount spec unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "utils_mount_spec.h"

TEST(utils_mount_spec, test_util_valid_mount_spec)
{
    char *base_valid = (char *)"type=bind,source=/home,target=/vol3,readonly=true,bind-selinux-opts=z,bind-propagation=rprivate";
    char *oci_valid = (char *)"type=tmpfs,dst=/tmpfs,tmpfs-size=1m,tmpfs-mode=1700";
    char *invalid1 = (char *)"type=volume,src=vol,dst=/vol,ro=true,red=false";
    char *invalid2 = (char *)"type,src,dst";
    char *errmsg = NULL;

    ASSERT_EQ(util_valid_mount_spec(base_valid, &errmsg), true);
    ASSERT_EQ(util_valid_mount_spec(oci_valid, &errmsg), true);

    ASSERT_EQ(util_valid_mount_spec(invalid1, &errmsg), false);
    ASSERT_EQ(util_valid_mount_spec(invalid2, &errmsg), false);
    ASSERT_EQ(util_valid_mount_spec(nullptr, &errmsg), false);
    ASSERT_EQ(util_valid_mount_spec(base_valid, nullptr), false);
}

TEST(utils_mount_spec, test_util_parse_mount_spec)
{
    char *base_valid = (char *)"type=bind,source=/home,target=/vol3,readonly=true,bind-selinux-opts=z,bind-propagation=rprivate";
    char *oci_valid = (char *)"type=tmpfs,dst=/tmpfs,tmpfs-size=1m,tmpfs-mode=1700";
    char *invalid1 = (char *)"type=volume,src=vol,dst=/vol,ro=true,red=false";
    char *invalid2 = (char *)"type,src,dst";
    mount_spec *m = NULL;
    char *errmsg = NULL;

    ASSERT_EQ(util_parse_mount_spec(base_valid, &m, &errmsg), 0);
    ASSERT_STREQ(m->type, "bind");
    ASSERT_STREQ(m->source, "/home");
    ASSERT_STREQ(m->target, "/vol3");
    ASSERT_EQ(m->readonly, true);
    ASSERT_STREQ(m->bind_options->propagation, "rprivate");
    ASSERT_STREQ(m->bind_options->selinux_opts, "z");

    ASSERT_EQ(util_parse_mount_spec(oci_valid, &m, &errmsg), 0);
    ASSERT_STREQ(m->type, "tmpfs");
    ASSERT_STREQ(m->target, "/tmpfs");
    ASSERT_EQ(m->tmpfs_options->size_bytes, 1048576);
    ASSERT_EQ(m->tmpfs_options->mode, 960);

    ASSERT_NE(util_parse_mount_spec(invalid1, &m, &errmsg), 0);
    ASSERT_NE(util_parse_mount_spec(invalid2, &m, &errmsg), 0);
    ASSERT_NE(util_parse_mount_spec(nullptr, &m, &errmsg), 0);
    ASSERT_NE(util_parse_mount_spec(base_valid, nullptr, &errmsg), 0);
    ASSERT_NE(util_parse_mount_spec(base_valid, &m, nullptr), 0);
}
