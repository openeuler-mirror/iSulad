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
 * Create: 2022-10-19
 * Description: utils verify unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "utils_verify.h"
#include "utils_file.h"

TEST(utils_verify, test_util_valid_cmd_arg)
{
    ASSERT_EQ(util_valid_cmd_arg("isula ps"), true);

    ASSERT_EQ(util_valid_cmd_arg(nullptr), false);
    ASSERT_EQ(util_valid_cmd_arg("isula ps | grep"), false);
    ASSERT_EQ(util_valid_cmd_arg("isula`"), false);
    ASSERT_EQ(util_valid_cmd_arg("isula ps & grep`"), false);
    ASSERT_EQ(util_valid_cmd_arg("isula ps ; grep`"), false);
}

TEST(utils_verify, test_util_valid_signal)
{
    ASSERT_EQ(util_valid_signal(2), true);

    ASSERT_EQ(util_valid_signal(0), false);
    ASSERT_EQ(util_valid_signal(-1), false);

    ASSERT_EQ(util_valid_signal(64), true);
    ASSERT_EQ(util_valid_signal(65), false);
}

TEST(utils_verify, test_util_validate_absolute_path)
{
    ASSERT_EQ(util_validate_absolute_path("/etc/isulad"), 0);
    ASSERT_EQ(util_validate_absolute_path("/isulad/"), 0);

    ASSERT_EQ(util_validate_absolute_path(nullptr), -1);
    ASSERT_EQ(util_validate_absolute_path("./isulad"), -1);
    ASSERT_EQ(util_validate_absolute_path("isulad"), -1);
}

TEST(utils_verify, test_util_validate_unix_socket)
{
    ASSERT_EQ(util_validate_unix_socket("unix:///etc/isulad"), true);
    ASSERT_EQ(util_validate_unix_socket("unix:///isulad/"), true);

    ASSERT_EQ(util_validate_unix_socket(nullptr), false);
    ASSERT_EQ(util_validate_unix_socket("unix://"), false);
    ASSERT_EQ(util_validate_unix_socket("unix://./isulad"), false);
    ASSERT_EQ(util_validate_unix_socket("unix://isulad"), false);
}

TEST(utils_verify, test_util_validate_socket)
{
    ASSERT_EQ(util_validate_socket("unix:///etc/isulad"), true);
    ASSERT_EQ(util_validate_socket("unix:///isulad/"), true);

    ASSERT_EQ(util_validate_socket(nullptr), false);
    ASSERT_EQ(util_validate_socket("unix://"), false);
    ASSERT_EQ(util_validate_socket("unix://./isulad"), false);
    ASSERT_EQ(util_validate_socket("unix://isulad"), false);

    ASSERT_EQ(util_validate_socket("tcp://localhost:2375"), true);
    ASSERT_EQ(util_validate_socket("tcp://127.0.0.1:2375"), true);

    ASSERT_EQ(util_validate_socket("tcp://"), false);
    ASSERT_EQ(util_validate_socket("tcp://127.0.0.1"), false);
    ASSERT_EQ(util_validate_socket("tcp://127.0.0.1,2375"), false);
}

TEST(utils_verify, test_util_valid_device_mode)
{
    ASSERT_EQ(util_valid_device_mode("rwm"), true);

    ASSERT_EQ(util_valid_device_mode(nullptr), false);
    ASSERT_EQ(util_valid_device_mode(""), false);
    ASSERT_EQ(util_valid_device_mode("rrwm"), false);
    ASSERT_EQ(util_valid_device_mode("rwwm"), false);
    ASSERT_EQ(util_valid_device_mode("rwmm"), false);
    ASSERT_EQ(util_valid_device_mode("awm"), false);
}

TEST(utils_verify, test_util_valid_str)
{
    ASSERT_EQ(util_valid_str("str"), true);

    ASSERT_EQ(util_valid_str(""), false);
    ASSERT_EQ(util_valid_str(nullptr), false);
}

TEST(utils_verify, test_util_get_all_caps_len)
{
    ASSERT_NE(util_get_all_caps_len(), 0);
}

TEST(utils_verify, test_util_valid_cap)
{
    ASSERT_EQ(util_valid_cap("DAC_READ_SEARCH"), true);

    ASSERT_EQ(util_valid_cap(nullptr), false);
    ASSERT_EQ(util_valid_cap(""), false);
    ASSERT_EQ(util_valid_cap("DA_READ_SEARCH"), false);
}

TEST(utils_verify, test_util_valid_time_tz)
{
    ASSERT_EQ(util_valid_time_tz("2022-10-04T18:22:45.289257759Z"), true);

    ASSERT_EQ(util_valid_time_tz(nullptr), false);
    ASSERT_EQ(util_valid_time_tz("2016-01-02T15:04:01:03"), false);
}

TEST(utils_verify, test_util_valid_embedded_image_name)
{
    ASSERT_EQ(util_valid_embedded_image_name("busybox:latest"), true);

    ASSERT_EQ(util_valid_embedded_image_name(nullptr), false);
    ASSERT_EQ(util_valid_embedded_image_name("busybox:/latest"), false);
    ASSERT_EQ(util_valid_embedded_image_name("busybox"), false);
    ASSERT_EQ(util_valid_embedded_image_name("busybox:#latest"), false);
}

TEST(utils_verify, test_util_valid_image_name)
{
    ASSERT_EQ(util_valid_image_name("busybox:latest"), true);
    ASSERT_EQ(util_valid_image_name("busybox"), true);

    ASSERT_EQ(util_valid_image_name(nullptr), false);
    ASSERT_EQ(util_valid_image_name("busybox:/latest"), false);
    ASSERT_EQ(util_valid_image_name("busybox:#latest"), false);
}

TEST(utils_verify, test_util_tag_pos)
{
    ASSERT_STREQ(util_tag_pos("busybox:latest"), ":latest");

    ASSERT_EQ(util_tag_pos("busybox:/latest"), nullptr);
    ASSERT_EQ(util_tag_pos("busybox"), nullptr);
}

TEST(utils_verify, test_util_valid_file)
{
    std::string isulad_dir = "/tmp/test";
    ASSERT_EQ(util_mkdir_p(isulad_dir.c_str(), 0700), 0);

    ASSERT_EQ(util_valid_file(isulad_dir.c_str(), S_IFDIR), true);
    ASSERT_EQ(util_valid_file(isulad_dir.c_str(), S_IFBLK), false);
    ASSERT_EQ(util_valid_file(isulad_dir.c_str(), 0), false);

    ASSERT_EQ(util_path_remove(isulad_dir.c_str()), 0);

    ASSERT_EQ(util_valid_file(nullptr, S_IFDIR), false);
}

TEST(utils_verify, test_util_valid_digest)
{
    ASSERT_EQ(util_valid_digest("sha256:7bd0c945d7e4cc2ce5c21d449ba07eb89c8e6c28085edbcf6f5fa4bf90e7eedc"), true);

    ASSERT_EQ(util_valid_digest(nullptr), false);
    ASSERT_EQ(util_valid_digest("ha256:7bd0c945d7e4cc2ce5c21d449ba07eb89c8e6c28085edbcf6f5fa4bf90e7eedc"), false);
}

TEST(utils_verify, test_util_valid_tag)
{
    ASSERT_EQ(util_valid_tag("busybox:latest"), true);

    ASSERT_EQ(util_valid_tag(nullptr), false);
    ASSERT_EQ(util_valid_tag("sha256:latest"), false);
}

TEST(utils_verify, test_util_valid_key_type)
{
    ASSERT_EQ(util_valid_key_type("type"), true);

    ASSERT_EQ(util_valid_key_type(nullptr), false);
    ASSERT_EQ(util_valid_key_type("type:123"), false);
}

TEST(utils_verify, test_util_valid_key_src)
{
    ASSERT_EQ(util_valid_key_src("src"), true);
    ASSERT_EQ(util_valid_key_src("source"), true);

    ASSERT_EQ(util_valid_key_src(nullptr), false);
    ASSERT_EQ(util_valid_key_src("source:123"), false);
}

TEST(utils_verify, test_util_valid_key_dst)
{
    ASSERT_EQ(util_valid_key_dst("dst"), true);
    ASSERT_EQ(util_valid_key_dst("destination"), true);
    ASSERT_EQ(util_valid_key_dst("target"), true);

    ASSERT_EQ(util_valid_key_dst(nullptr), false);
    ASSERT_EQ(util_valid_key_dst("target:123"), false);
}

TEST(utils_verify, test_util_valid_key_ro)
{
    ASSERT_EQ(util_valid_key_ro("ro"), true);
    ASSERT_EQ(util_valid_key_ro("readonly"), true);

    ASSERT_EQ(util_valid_key_ro(nullptr), false);
    ASSERT_EQ(util_valid_key_ro("readonly:123"), false);
}

TEST(utils_verify, test_util_valid_key_propagation)
{
    ASSERT_EQ(util_valid_key_propagation("bind-propagation"), true);

    ASSERT_EQ(util_valid_key_propagation(nullptr), false);
    ASSERT_EQ(util_valid_key_propagation("bind-propagation:123"), false);
}

TEST(utils_verify, test_util_valid_key_selinux)
{
    ASSERT_EQ(util_valid_key_selinux("bind-selinux-opts"), true);
    ASSERT_EQ(util_valid_key_selinux("selinux-opts"), true);

    ASSERT_EQ(util_valid_key_selinux(nullptr), false);
    ASSERT_EQ(util_valid_key_selinux("bind-selinux-opts:123"), false);
}

TEST(utils_verify, test_util_valid_key_tmpfs_size)
{
    ASSERT_EQ(util_valid_key_tmpfs_size("tmpfs-size"), true);

    ASSERT_EQ(util_valid_key_tmpfs_size(nullptr), false);
    ASSERT_EQ(util_valid_key_tmpfs_size("tmpfs-size:123"), false);
}

TEST(utils_verify, test_util_valid_key_tmpfs_mode)
{
    ASSERT_EQ(util_valid_key_tmpfs_mode("tmpfs-mode"), true);

    ASSERT_EQ(util_valid_key_tmpfs_mode(nullptr), false);
    ASSERT_EQ(util_valid_key_tmpfs_mode("tmpfs-mode:123"), false);
}

TEST(utils_verify, test_util_valid_key_nocopy)
{
    ASSERT_EQ(util_valid_key_nocopy("volume-nocopy"), true);

    ASSERT_EQ(util_valid_key_nocopy(nullptr), false);
    ASSERT_EQ(util_valid_key_nocopy("volume-nocopy:123"), false);
}

TEST(utils_verify, test_util_valid_value_true)
{
    ASSERT_EQ(util_valid_value_true("1"), true);
    ASSERT_EQ(util_valid_value_true("true"), true);

    ASSERT_EQ(util_valid_value_true(nullptr), false);
    ASSERT_EQ(util_valid_value_true("0"), false);
    ASSERT_EQ(util_valid_value_true("false"), false);
}

TEST(utils_verify, test_util_valid_value_false)
{
    ASSERT_EQ(util_valid_value_false("0"), true);
    ASSERT_EQ(util_valid_value_false("false"), true);

    ASSERT_EQ(util_valid_value_false(nullptr), false);
    ASSERT_EQ(util_valid_value_false("1"), false);
    ASSERT_EQ(util_valid_value_false("true"), false);
}

TEST(utils_verify, test_util_valid_rw_mode)
{
    ASSERT_EQ(util_valid_rw_mode("ro"), true);
    ASSERT_EQ(util_valid_rw_mode("rw"), true);

    ASSERT_EQ(util_valid_rw_mode(nullptr), false);
    ASSERT_EQ(util_valid_rw_mode("rwro"), false);
}

TEST(utils_verify, test_util_valid_label_mode)
{
    ASSERT_EQ(util_valid_label_mode("z"), true);
    ASSERT_EQ(util_valid_label_mode("Z"), true);

    ASSERT_EQ(util_valid_label_mode(nullptr), false);
    ASSERT_EQ(util_valid_label_mode("zZ"), false);
}

TEST(utils_verify, test_util_valid_copy_mode)
{
    ASSERT_EQ(util_valid_copy_mode("nocopy"), true);

    ASSERT_EQ(util_valid_copy_mode(nullptr), false);
    ASSERT_EQ(util_valid_copy_mode("nocopy:123"), false);
}

TEST(utils_verify, test_util_valid_propagation_mode)
{
    ASSERT_EQ(util_valid_propagation_mode("private"), true);
    ASSERT_EQ(util_valid_propagation_mode("rprivate"), true);
    ASSERT_EQ(util_valid_propagation_mode("slave"), true);
    ASSERT_EQ(util_valid_propagation_mode("rslave"), true);
    ASSERT_EQ(util_valid_propagation_mode("shared"), true);
    ASSERT_EQ(util_valid_propagation_mode("rshared"), true);

    ASSERT_EQ(util_valid_propagation_mode(nullptr), false);
    ASSERT_EQ(util_valid_propagation_mode("rrslave"), false);
}

TEST(utils_verify, test_util_valid_mount_mode)
{
    ASSERT_EQ(util_valid_mount_mode("ro,private,z,nocopy"), true);

    ASSERT_EQ(util_valid_mount_mode(nullptr), false);
    ASSERT_EQ(util_valid_mount_mode("ro,rw,private,z,nocopy"), false);
    ASSERT_EQ(util_valid_mount_mode("ri,private,z,nocopy"), false);
}

TEST(utils_verify, test_util_valid_container_id)
{
    ASSERT_EQ(util_valid_container_id("451f587884b04ef2a81a6d410f65083c906a865044ef5bef8af833aaab8c63aa"), true);

    ASSERT_EQ(util_valid_container_id(nullptr), false);
    ASSERT_EQ(util_valid_container_id("g51f587884b04ef2a81a6d410f65083c906a865044ef5bef8af833aaab8c63aa"), false);
    ASSERT_EQ(util_valid_container_id(""), false);
}

TEST(utils_verify, test_util_valid_container_name)
{
    ASSERT_EQ(util_valid_container_name("test"), true);

    ASSERT_EQ(util_valid_container_name(nullptr), false);
    ASSERT_EQ(util_valid_container_name(".test"), false);
}

TEST(utils_verify, test_util_valid_container_id_or_name)
{
    ASSERT_EQ(util_valid_container_id_or_name("test"), true);
    ASSERT_EQ(util_valid_container_id_or_name("451f587884b04ef2a81a6d410f65083c906a865044ef5bef8af833aaab8c63aa"), true);

    ASSERT_EQ(util_valid_container_id_or_name(nullptr), false);
    ASSERT_EQ(util_valid_container_id_or_name(".test"), false);
    ASSERT_EQ(util_valid_container_id_or_name(""), false);
}

TEST(utils_verify, test_util_valid_host_name)
{
    ASSERT_EQ(util_valid_host_name("LAPTOP-6O44CJ3O"), true);

    ASSERT_EQ(util_valid_host_name(nullptr), false);
    ASSERT_EQ(util_valid_host_name(".LAPTOP-6O44CJ3O"), false);
}

TEST(utils_verify, test_util_valid_runtime_name)
{
    ASSERT_EQ(util_valid_runtime_name("runc"), true);

    ASSERT_EQ(util_valid_runtime_name(nullptr), false);
}

TEST(utils_verify, test_util_valid_short_sha256_id)
{
    ASSERT_EQ(util_valid_short_sha256_id("ff4a8eb070e12018233797e865841d877a7835c4c6d5cfc52e5481995da6b2f7"), true);
    ASSERT_EQ(util_valid_short_sha256_id("ff4"), true);

    ASSERT_EQ(util_valid_short_sha256_id(nullptr), false);
    ASSERT_EQ(util_valid_short_sha256_id("ff"), false);
}

TEST(utils_verify, test_util_valid_exec_suffix)
{
    ASSERT_EQ(util_valid_exec_suffix("ff4a8eb070e12018233797e865841d877a7835c4c6d5cfc52e5481995da6b2f7"), true);

    ASSERT_EQ(util_valid_exec_suffix(nullptr), false);
    ASSERT_EQ(util_valid_exec_suffix("gf4a8eb070e12018233797e865841d877a7835c4c6d5cfc52e5481995da6b2f7"), false);
}

TEST(utils_verify, test_util_valid_positive_interger)
{
    ASSERT_EQ(util_valid_positive_interger("123456789"), true);
    ASSERT_EQ(util_valid_positive_interger("0"), true);

    ASSERT_EQ(util_valid_positive_interger(nullptr), false);
    ASSERT_EQ(util_valid_positive_interger("-123456789"), false);
    ASSERT_EQ(util_valid_positive_interger(""), false);
}

TEST(utils_verify, test_util_valid_device_cgroup_rule)
{
    ASSERT_EQ(util_valid_device_cgroup_rule("b 8:* rmw"), true);

    ASSERT_EQ(util_valid_device_cgroup_rule(nullptr), false);
    ASSERT_EQ(util_valid_device_cgroup_rule("d 8:* rmw"), false);
}

TEST(utils_verify, test_util_valid_env)
{
    char *env = (char *)"USER=root";
    char *dst = nullptr;

    ASSERT_EQ(util_valid_env(env, &dst), 0);
    ASSERT_STREQ(dst, "USER=root");

    ASSERT_EQ(util_valid_env(nullptr, &dst), -1);
    ASSERT_EQ(util_valid_env(env, nullptr), -1);
}

TEST(utils_verify, test_util_valid_sysctl)
{
    ASSERT_EQ(util_valid_sysctl("kernel.msgmax"), true);
    ASSERT_EQ(util_valid_sysctl("net.abc"), true);

    ASSERT_EQ(util_valid_sysctl(nullptr), false);
    ASSERT_EQ(util_valid_sysctl("kernel.shmal"), false);
}

TEST(utils_verify, test_util_valid_volume_name)
{
    ASSERT_EQ(util_valid_volume_name("f6391b735a917ffbaff138970dc45290508574e6ab92e06a1e9dd290f31592ca"), true);
    ASSERT_EQ(util_valid_volume_name("aa"), true);

    ASSERT_EQ(util_valid_volume_name(nullptr), false);
    ASSERT_EQ(util_valid_volume_name(""), false);
    ASSERT_EQ(util_valid_volume_name("a"), false);
}