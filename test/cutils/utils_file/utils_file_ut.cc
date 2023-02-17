/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: utils_file unit test
 * Author: huangsong
 * Create: 2022-10-26
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "utils_file.h"
#include "constants.h"
#include "map.h"

#define FILE_PERMISSION_TEST 0755

TEST(utils_file, test_util_dir_exists)
{
    ASSERT_EQ(util_dir_exists(nullptr), false);

    const char *path = "/tmp/test";
    ASSERT_EQ(util_dir_exists(path), false);
    ASSERT_EQ(util_mkdir_p(path, FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_dir_exists(path), true);
    ASSERT_EQ(util_path_remove(path), 0);

}

TEST(utils_file, test_util_fileself_exists)
{
    ASSERT_EQ(util_fileself_exists(nullptr), false);

    std::string path = "/tmp/test";
    std::string path_link = "/tmp/test/link";
    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_fileself_exists(path_link.c_str()), false);
    ASSERT_EQ(symlink(path.c_str(), path_link.c_str()), 0);
    ASSERT_EQ(util_fileself_exists(path_link.c_str()), true);
    ASSERT_EQ(util_path_remove(path_link.c_str()), 0);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

TEST(utils_file, test_util_file_exists)
{
    ASSERT_EQ(util_file_exists(nullptr), false);

    std::string path = "/tmp/test";
    ASSERT_EQ(util_file_exists(path.c_str()), false);
    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_file_exists(path.c_str()), true);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}


TEST(utils_file, test_util_recursive_rmdir)
{
    ASSERT_EQ(util_recursive_rmdir(nullptr, 0), -1);

    std::string path = "/tmp/test";
    std::string path_link = "/tmp/test/link";
    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_mkdir_p(path_link.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_recursive_rmdir(path.c_str(), 1), 0);
    ASSERT_EQ(util_file_exists(path.c_str()), false);
    ASSERT_EQ(util_file_exists(path_link.c_str()), false);
}

TEST(utils_file, test_util_ensure_path)
{
    char *rpath = NULL;
    std::string path = "/tmp/test";
    ASSERT_EQ(util_ensure_path(nullptr, path.c_str()), -1);
    ASSERT_EQ(util_ensure_path(&rpath, nullptr), -1);

    ASSERT_EQ(util_file_exists(path.c_str()), false);
    ASSERT_EQ(util_ensure_path(&rpath, path.c_str()), 0);
    ASSERT_EQ(util_file_exists(rpath), true);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

TEST(utils_file, test_util_build_dir)
{
    ASSERT_EQ(util_build_dir(nullptr), -1);

    std::string path = "/tmp/test/file";
    ASSERT_EQ(util_build_dir(path.c_str()), 0);
    ASSERT_EQ(util_file_exists("/tmp"), true);
    ASSERT_EQ(util_file_exists("/tmp/test"), true);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

TEST(utils_file, test_util_human_size)
{
    uint64_t b = 1;
    uint64_t kb = 1024;
    uint64_t mb = 1024 * 1024;
    uint64_t gb = 1024 * 1024 * 1024;
    ASSERT_STREQ(util_human_size(b), "1B");
    ASSERT_STREQ(util_human_size(kb), "1KB");
    ASSERT_STREQ(util_human_size(mb), "1MB");
    ASSERT_STREQ(util_human_size(gb), "1GB");

    ASSERT_STREQ(util_human_size_decimal(b), "1B");
    ASSERT_STREQ(util_human_size_decimal(kb), "1.000KB");
    ASSERT_STREQ(util_human_size_decimal(mb), "1.000MB");
    ASSERT_STREQ(util_human_size_decimal(gb), "1.000GB");
}

TEST(utils_file, test_util_open)
{
    std::string path = "/tmp/test";
    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_NE(util_open(path.c_str(), O_RDONLY, 0), -1);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

TEST(utils_file, test_util_add_path)
{
    std::string path = "/tmp/test/";
    std::string add_path = "add";
    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_STREQ(util_add_path(path.c_str(), add_path.c_str()), "/tmp/test/add");
    ASSERT_EQ(util_path_remove(path.c_str()), 0);

    std::string path1 = "/tmp/test";
    ASSERT_EQ(util_mkdir_p(path1.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_STREQ(util_add_path(path1.c_str(), add_path.c_str()), "/tmp/add");
    ASSERT_EQ(util_path_remove(path1.c_str()), 0);
}

TEST(utils_file, test_verify_file_and_get_real_path)
{
    std::string path = "/tmp/test";
    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_STREQ(verify_file_and_get_real_path(path.c_str()), "/tmp/test");
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

TEST(utils_file, test_look_path)
{
    std::string path = "/usr/bin/nsenter";
    char *err = NULL;
    ASSERT_STREQ(look_path("nsenter", &err), path.c_str());
}

TEST(utils_file, test_util_copy_file)
{
    std::string path = "/tmp/test";
    ASSERT_EQ(util_copy_file("/etc/hosts", path.c_str(), NETWORK_MOUNT_FILE_MODE), 0);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);

    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_copy_file("/etc/hosts", path.c_str(), NETWORK_MOUNT_FILE_MODE), -1);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

TEST(utils_file, test_utils_calculate_dir_size_without_hardlink)
{
    std::string path = "/tmp/test";
    std::string hosts = "/etc/hosts";
    ASSERT_EQ(util_copy_file(hosts.c_str(), path.c_str(), NETWORK_MOUNT_FILE_MODE), 0);
    int64_t total_size = 0;
    int64_t total_inodes = 0;
    utils_calculate_dir_size_without_hardlink("/tmp/", &total_size, &total_inodes);
    ASSERT_NE(total_size, 0);
    ASSERT_NE(total_inodes, 0);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

static bool parse_checked_layer_cb(const char *line, void *context)
{
    printf("this is stdout\n");
    fprintf(stderr, "this is stderr\n");
    return true;
}

TEST(utils_file, test_util_proc_file_line_by_line)
{
    std::string path = "/tmp/test";
    std::string content = "hello world";
    int fd;
    fd = util_open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, DEFAULT_SECURE_FILE_MODE);
    ASSERT_EQ(util_write_nointr_in_total(fd, content.c_str(), strlen(content.c_str())), 11);
    FILE *fp = NULL;
    map_t *checked_layers = NULL;
    fp = util_fopen(path.c_str(), "r");
    checked_layers = map_new(MAP_STR_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    ASSERT_EQ(util_proc_file_line_by_line(fp, parse_checked_layer_cb, (void *)checked_layers), 0);
    fclose(fp);
    ASSERT_EQ(util_path_remove(path.c_str()), 0);
}

TEST(utils_file, test_util_recursive_remove_path)
{
    ASSERT_EQ(util_recursive_remove_path(nullptr), -1);

    std::string path = "/tmp/test";
    std::string path_link = "/tmp/test/link";
    ASSERT_EQ(util_mkdir_p(path.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_mkdir_p(path_link.c_str(), FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_recursive_remove_path(path.c_str()), 0);
    ASSERT_EQ(util_file_exists(path.c_str()), false);
    ASSERT_EQ(util_file_exists(path_link.c_str()), false);

}

TEST(utils_file, test_util_copy_dir_recursive)
{
    char *path = (char*)"/tmp/test1/";
    char *src = (char*)"/tmp/test/";
    ASSERT_EQ(util_mkdir_p(path, FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_mkdir_p(src, FILE_PERMISSION_TEST), 0);
    ASSERT_EQ(util_copy_dir_recursive(path, src), 0);
    ASSERT_EQ(util_recursive_remove_path(path), 0);
    ASSERT_EQ(util_recursive_remove_path(src), 0);
}


