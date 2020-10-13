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
 * Description: path unit test
 * Author: jikui
 * Create: 2019-08-22
 */

#include <limits.h>
#include <unistd.h>
#include <sys/stat.h>
#include <gtest/gtest.h>
#include "mock.h"
#include "utils.h"
#include "utils_file.h"
#include "path.h"

#define PATH_LENGTH_TEST 100
#define FILE_PERMISSION_TEST 0755

extern "C" {
    DECLARE_WRAPPER_V(getcwd, char *, (char *str, size_t size));
    DEFINE_WRAPPER_V(getcwd, char *, (char *str, size_t size), (str, size));

    DECLARE_WRAPPER_V(readlink, ssize_t, (const char *path, char *buf, size_t bufsize));
    DEFINE_WRAPPER_V(readlink, ssize_t, (const char *path, char *buf, size_t bufsize), (path, buf, bufsize));
}

static char *getcwd_specify(char *str, size_t size)
{
    const char *dst = "/home";
    if (str == nullptr) {
        return nullptr;
    }

    if (size <= strlen(dst)) {
        return nullptr;
    }
    (void)strcpy(str, dst);

    return str;
}

static int create_tmp_symbolic_link(const char *path, const char *path_file, const char *path_link)
{
    if (path == nullptr || path_file == nullptr || path_link == nullptr) {
        return -1;
    }

    if (util_mkdir_p(path, FILE_PERMISSION_TEST) != 0) {
        return -1;
    }

    if (symlink(path_file, path_link) != 0) {
        return -1;
    }
    return 0;
}

static ssize_t readlink_specify(const char *path, char *buf, size_t bufsize)
{
    const char *linkpath = "./dir/test/../file";
    size_t linkpath_length;
    linkpath_length = strlen(linkpath);

    if (path == nullptr || buf == nullptr) {
        return -1;
    }

    if (bufsize <= linkpath_length) {
        return -1;
    }
    (void)strcpy(buf, linkpath);

    if (linkpath_length > bufsize) {
        return bufsize;
    }
    return linkpath_length;
}

TEST(path_ut, test_cleanpath)
{
    char *result = nullptr;
    std::string str;
    char realpath[PATH_MAX];

    result = util_clean_path(nullptr, realpath, sizeof(realpath));
    ASSERT_STREQ(result, nullptr);

    str = "";
    result = util_clean_path(str.c_str(), realpath, sizeof(realpath));
    ASSERT_STREQ(result, nullptr);

    str = "/home/dir/../file";
    result = util_clean_path(str.c_str(), realpath, sizeof(realpath));
    ASSERT_STREQ(result, "/home/file");

    str = "/home/dir/./file";
    result = util_clean_path(str.c_str(), realpath, sizeof(realpath));
    ASSERT_STREQ(result, "/home/dir/file");

    str = "./dir/file";
    MOCK_SET_V(getcwd, getcwd_specify);
    result = util_clean_path(str.c_str(), realpath, sizeof(realpath));
    ASSERT_STREQ(result, "/home/dir/file");
    MOCK_CLEAR(getcwd);

    str = "/home/file";
    result = util_clean_path(str.c_str(), realpath, PATH_LENGTH_TEST);
    ASSERT_STREQ(result, nullptr);

    str = "/home/file";
    result = util_clean_path(str.c_str(), nullptr, 0);
    ASSERT_STREQ(result, nullptr);
}

TEST(path_ut, test_specify_current_dir)
{
    ASSERT_FALSE(util_specify_current_dir(nullptr));
    ASSERT_TRUE(util_specify_current_dir(""));
    ASSERT_TRUE(util_specify_current_dir("/home/."));
    ASSERT_TRUE(util_specify_current_dir("."));
    ASSERT_FALSE(util_specify_current_dir("/home/file"));
    ASSERT_FALSE(util_specify_current_dir("/home/.."));
    ASSERT_FALSE(util_specify_current_dir("/home"));
    ASSERT_FALSE(util_specify_current_dir("home"));
}

TEST(path_ut, test_follow_symlink_in_scope)
{
    std::string fullpath, rootpath;
    char *res = nullptr;

    res = util_follow_symlink_in_scope(nullptr, nullptr);
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    fullpath = "";
    rootpath = "";
    res = util_follow_symlink_in_scope(fullpath.c_str(), rootpath.c_str());
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    fullpath = "/home/dir/file";
    rootpath = "/home";
    res = util_follow_symlink_in_scope(fullpath.c_str(), rootpath.c_str());
    ASSERT_STREQ(res, "/home/dir/file");
    free(res);
    res = nullptr;

    fullpath = "/home/dir/file";
    rootpath = "/home/dir/../file";
    res = util_follow_symlink_in_scope(fullpath.c_str(), rootpath.c_str());
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    fullpath = "/home/dir/file";
    rootpath = "/home/dir/../";
    res = util_follow_symlink_in_scope(fullpath.c_str(), rootpath.c_str());
    ASSERT_STREQ(res, "/home/dir/file");
    free(res);
    res = nullptr;

    fullpath = "/tmp/just_for_ut/link";
    rootpath = "/tmp";
    const char *path = "/tmp/just_for_ut";
    const char *path_file = "./testdir/test/../file";
    const char *path_link = "/tmp/just_for_ut/link";
    ASSERT_EQ(create_tmp_symbolic_link(path, path_file, path_link), 0);
    MOCK_SET_V(readlink, readlink_specify);
    res = util_follow_symlink_in_scope(fullpath.c_str(), rootpath.c_str());
    ASSERT_STREQ(res, "/tmp/just_for_ut/dir/file");
    MOCK_CLEAR(readlink);
    ASSERT_EQ(util_recursive_rmdir("/tmp/just_for_ut", 0), 0);
    free(res);
    res = nullptr;
}

TEST(path_ut, test_split_dir_and_base_name)
{
    char *dir = nullptr;
    char *base = nullptr;

    ASSERT_EQ(util_split_dir_and_base_name(nullptr, &dir, &base), -1);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    ASSERT_EQ(util_split_dir_and_base_name("", &dir, &base), 0);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    ASSERT_EQ(util_split_dir_and_base_name("/home/file", &dir, &base), 0);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    ASSERT_EQ(util_split_dir_and_base_name("/home/file", nullptr, nullptr), 0);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    util_split_dir_and_base_name("/home/file", &dir, &base);
    ASSERT_STREQ(dir, "/home");
    ASSERT_STREQ(base, "file");
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;
}

TEST(path_ut, test_filepath_split)
{
    char *dir = nullptr;
    char *base = nullptr;

    ASSERT_EQ(util_filepath_split(nullptr, &dir, &base), -1);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    ASSERT_EQ(util_filepath_split("", &dir, &base), 0);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    ASSERT_EQ(util_filepath_split("/home/file", &dir, &base), 0);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    ASSERT_EQ(util_filepath_split("/home/file", nullptr, nullptr), 0);
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    util_filepath_split("/home/file", &dir, &base);
    ASSERT_STREQ(dir, "/home/");
    ASSERT_STREQ(base, "file");
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;

    util_filepath_split("/home/", &dir, &base);
    ASSERT_STREQ(dir, "/home/");
    ASSERT_STREQ(base, "");
    free(dir);
    dir = nullptr;
    free(base);
    base = nullptr;
}

TEST(path_ut, test_get_resource_path)
{
    char *res = nullptr;

    res = util_get_resource_path(nullptr, "./test");
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    res = util_get_resource_path("", "");
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    res = util_get_resource_path("/home", "./test");
    ASSERT_STREQ(res, "/home/test");
    free(res);
    res = nullptr;

    res = util_get_resource_path("/home/dir", "tmp/.././test");
    ASSERT_STREQ(res, "/home/dir/test");
    free(res);
    res = nullptr;

    res = util_get_resource_path("/home/dir", ".././test");
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    res = util_get_resource_path("/home////dir", ".///./././test/file");
    ASSERT_STREQ(res, "/home/dir/test/file");
    free(res);
    res = nullptr;
}

TEST(path_ut, test_resolve_path)
{
    std::string rootpath, path;
    char *resolvedpath = nullptr;
    char *abspath = nullptr;

    ASSERT_EQ(util_resolve_path(nullptr, nullptr, &resolvedpath, &abspath), -1);
    free(resolvedpath);
    resolvedpath = nullptr;
    free(abspath);
    abspath = nullptr;

    rootpath = "";
    path = "";
    ASSERT_EQ(util_resolve_path(rootpath.c_str(), path.c_str(), &resolvedpath, &abspath), -1);
    free(resolvedpath);
    resolvedpath = nullptr;
    free(abspath);
    abspath = nullptr;

    rootpath = "/home";
    path = "/home/dir/test";
    ASSERT_EQ(util_resolve_path(rootpath.c_str(), path.c_str(), &resolvedpath, &abspath), 0);
    free(resolvedpath);
    resolvedpath = nullptr;
    free(abspath);
    abspath = nullptr;
}

TEST(path_ut, test_has_trailing_path_separator)
{
    ASSERT_FALSE(util_has_trailing_path_separator(nullptr));
    ASSERT_FALSE(util_has_trailing_path_separator(""));
    ASSERT_TRUE(util_has_trailing_path_separator("/home/"));
    ASSERT_FALSE(util_has_trailing_path_separator("/home"));
}

TEST(path_ut, test_preserve_trailing_dot_or_separator)
{
    std::string cleanedpath, originalpath;
    char *res = nullptr;

    res = util_preserve_trailing_dot_or_separator(nullptr, nullptr);
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    res = util_preserve_trailing_dot_or_separator("", "");
    ASSERT_STREQ(res, nullptr);
    free(res);
    res = nullptr;

    cleanedpath = "/home/test";
    originalpath = "/home/test/.";
    res = util_preserve_trailing_dot_or_separator(cleanedpath.c_str(), originalpath.c_str());
    ASSERT_STREQ(res, "/home/test/.");
    free(res);
    res = nullptr;

    cleanedpath = "/home/test";
    originalpath = "/home/test/";
    res = util_preserve_trailing_dot_or_separator(cleanedpath.c_str(), originalpath.c_str());
    ASSERT_STREQ(res, "/home/test/");
    free(res);
    res = nullptr;
}
