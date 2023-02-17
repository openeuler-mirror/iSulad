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
 * Description: sha256 unit test
 * Author: chengzeruizhi
 * Create: 2022-11-22
 */

#include <gtest/gtest.h>

#include "constants.h"
#include "util_gzip.h"
#include "utils.h"
#include "utils_file.h"
#include "sha256.h"

TEST(sha256, test_sha256_digest_file)
{
    int get_err;
    char *digest = sha256_digest_file(NULL, false);
    EXPECT_EQ(digest, nullptr);

    digest = sha256_digest_file(NULL, true);
    EXPECT_EQ(digest, nullptr);

    int fd = util_open("/tmp/sha256_empty_file", O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    ASSERT_GE(fd, 0);
    digest = sha256_digest_file("/tmp/sha256_empty_file", false);
    EXPECT_STREQ(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    int emptyfile_ret = util_gzip_z("/tmp/sha256_empty_file", "/tmp/sha256_empty_file.gz", DEFAULT_SECURE_FILE_MODE);
    digest = sha256_digest_file("/tmp/sha256_empty_file.gz", true);
    EXPECT_STREQ(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    close(fd);
    util_force_remove_file("/tmp/sha256_empty_file", &get_err);
    if (emptyfile_ret == 0) {
        util_force_remove_file("/tmp/sha256_empty_file.gz", &get_err);
    }

    int fd2 = util_open("/tmp/sha256_test_file", O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    ASSERT_GE(fd2, 0);
    util_write_nointr(fd2, "asdjfljsad", 10);
    digest = sha256_digest_file("/tmp/sha256_test_file", false);
    EXPECT_STREQ(digest, "fe2d2648f9221659cf67068096ba561211d06d37dbfaf2d61b0b3bc34f43d3e1");
    int testfile_ret = util_gzip_z("/tmp/sha256_test_file", "/tmp/sha256_test_file.gz", DEFAULT_SECURE_FILE_MODE);
    digest = sha256_digest_file("/tmp/sha256_test_file.gz", true);
    EXPECT_STREQ(digest, "fe2d2648f9221659cf67068096ba561211d06d37dbfaf2d61b0b3bc34f43d3e1");
    close(fd2);
    util_force_remove_file("/tmp/sha256_test_file", &get_err);
    if (testfile_ret == 0) {
        util_force_remove_file("/tmp/sha256_test_file.gz", &get_err);
    }
}

TEST(sha256, test_sha256_digest_str)
{
    char *digest = sha256_digest_str(NULL);
    EXPECT_EQ(digest, nullptr);

    digest = sha256_digest_str("");
    EXPECT_STREQ(digest, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");

    digest = sha256_digest_str(
                 "^cvdgfdgghaswere3575676y&*`~cx,xfdgdvcvdfd][';./?.,<>|\\!@#$%^&*()_+=-090wvvs3sdfel33cxvdf***$");
    EXPECT_STREQ(digest, "899a57a99c14c047eab26f8d6719da256a0737f6c28728ba5777b4fc5398c657");
}

TEST(sha256, test_sha256_full_gzip_digest)
{
    int get_err;
    char *digest = sha256_full_gzip_digest(NULL);
    EXPECT_EQ(digest, nullptr);

    int fd = util_open("/tmp/sha256_empty_file", O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    ASSERT_GE(fd, 0);
    digest = sha256_full_gzip_digest("/tmp/sha256_empty_file");
    EXPECT_EQ(digest, nullptr);

    int emptyfile_ret = util_gzip_z("/tmp/sha256_empty_file", "/tmp/sha256_empty_file.gz", DEFAULT_SECURE_FILE_MODE);
    digest = sha256_full_gzip_digest("/tmp/sha256_empty_file.gz");
    EXPECT_STREQ(digest, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    close(fd);
    util_force_remove_file("/tmp/sha256_empty_file", &get_err);
    if (emptyfile_ret == 0) {
        util_force_remove_file("/tmp/sha256_empty_file.gz", &get_err);
    }

    int fd2 = util_open("/tmp/sha256_test_file", O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    ASSERT_GE(fd2, 0);
    util_write_nointr(fd2, "asdjfljsad", 10);
    digest = sha256_full_gzip_digest("/tmp/sha256_test_file");
    EXPECT_EQ(digest, nullptr);
    int testfile_ret = util_gzip_z("/tmp/sha256_test_file", "/tmp/sha256_test_file.gz", DEFAULT_SECURE_FILE_MODE);
    digest = sha256_full_gzip_digest("/tmp/sha256_test_file.gz");
    EXPECT_STREQ(digest, "sha256:fe2d2648f9221659cf67068096ba561211d06d37dbfaf2d61b0b3bc34f43d3e1");
    close(fd2);
    util_force_remove_file("/tmp/sha256_test_file", &get_err);
    if (testfile_ret == 0) {
        util_force_remove_file("/tmp/sha256_test_file.gz", &get_err);
    }
}

TEST(sha256, test_sha256_full_file_digest)
{
    int get_err;
    char *digest = sha256_full_file_digest(NULL);
    EXPECT_EQ(digest, nullptr);

    int fd = util_open("/tmp/sha256_empty_file", O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    ASSERT_GE(fd, 0);
    digest = sha256_full_file_digest("/tmp/sha256_empty_file");
    EXPECT_STREQ(digest, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    close(fd);
    util_force_remove_file("/tmp/sha256_empty_file", &get_err);

    int fd2 = util_open("/tmp/sha256_test_file", O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    ASSERT_GE(fd2, 0);
    util_write_nointr(fd2, "asdjfljsad", 10);
    digest = sha256_full_file_digest("/tmp/sha256_test_file");
    EXPECT_STREQ(digest, "sha256:fe2d2648f9221659cf67068096ba561211d06d37dbfaf2d61b0b3bc34f43d3e1");
    close(fd2);
    util_force_remove_file("/tmp/sha256_test_file", &get_err);
}

TEST(sha256, test_sha256_valid_digest_file)
{
    int get_err;

    ASSERT_FALSE(sha256_valid_digest_file(NULL, NULL));
    int fd = util_open("/tmp/sha256_test_file", O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    ASSERT_GE(fd, 0);
    util_write_nointr(fd, "asdjfljsad", 10);
    EXPECT_TRUE(sha256_valid_digest_file("/tmp/sha256_test_file",
                                         "sha256:fe2d2648f9221659cf67068096ba561211d06d37dbfaf2d61b0b3bc34f43d3e1"));
    util_force_remove_file("/tmp/sha256_test_file", &get_err);
}

TEST(sha256, test_sha256_full_digest_str)
{
    char *full_digest = sha256_full_digest_str(NULL);
    EXPECT_EQ(full_digest, nullptr);
    full_digest = sha256_full_digest_str(util_strdup_s(""));
    EXPECT_STREQ(full_digest, "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
}

TEST(sha256, test_util_without_sha256_prefix)
{
    char *digest = util_without_sha256_prefix(NULL);
    EXPECT_EQ(digest, nullptr);
    digest = util_without_sha256_prefix(util_strdup_s("sha246:"));
    EXPECT_EQ(digest, nullptr);
    digest = util_without_sha256_prefix(util_strdup_s("sha256:"));
    EXPECT_STREQ(digest, "");
    digest = util_without_sha256_prefix(util_strdup_s("sha256:asdfawf2q3rqrg234rewfd]\a]sd;v.z/xc"));
    EXPECT_STREQ(digest, "asdfawf2q3rqrg234rewfd]\a]sd;v.z/xc");
}