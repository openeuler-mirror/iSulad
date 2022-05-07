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
 * Author: hejunjie
 * Create: 2022-04-08
 * Description: utils_pwgr unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "utils_pwgr.h"

TEST(utils_pwgr, test_getpwent_r)
{
    std::string path = "../../../../test/cutils/utils_pwgr/passwd_sample";
    FILE *f_pw = fopen(path.c_str(), "r");
    ASSERT_NE(f_pw, nullptr);

    struct passwd pw;
    struct passwd *ppw = nullptr;
    char buf[BUFSIZ];

    std::vector<std::tuple<std::string, std::string, int, int, std::string, std::string, std::string>> testcase = {
        std::make_tuple("root", "x", 0, 0, "root", "/root", "/bin/bash"),
        std::make_tuple("bin", "x", 1, 1, "bin", "/bin", "/sbin/nologin"),
        std::make_tuple("uidonly", "x", 1, 0, "bin", "/bin", "/sbin/nologin"),
        std::make_tuple("npt", "*", 66, 77, "", "/etc/ntp", "/sbin/nologin"),
        std::make_tuple("npt", "*", 66, 77, "", "/etc/ntp", "/sbin/nologin"),
        std::make_tuple("+npt", "*", 0, 0, "", "/etc/ntp", "/sbin/nologin"),
        std::make_tuple("-npt", "*", 0, 0, "", "/etc/ntp", "/sbin/nologin")
    };

    for (const auto &elem : testcase) {
        ASSERT_EQ(util_getpwent_r(f_pw, &pw, buf, sizeof(buf), &ppw), 0);
        ASSERT_STREQ(pw.pw_name, std::get<0>(elem).c_str());
        ASSERT_STREQ(pw.pw_passwd, std::get<1>(elem).c_str());
        ASSERT_EQ(pw.pw_uid, std::get<2>(elem));
        ASSERT_EQ(pw.pw_gid, std::get<3>(elem));
        ASSERT_STREQ(pw.pw_gecos, std::get<4>(elem).c_str());
        ASSERT_STREQ(pw.pw_dir, std::get<5>(elem).c_str());
        ASSERT_STREQ(pw.pw_shell, std::get<6>(elem).c_str());
        EXPECT_TRUE(ppw == &pw);
        ppw = nullptr;
        pw = {0};
    }

    fclose(f_pw);
}

TEST(utils_pwgr, test_getgrent_r)
{
    std::string path = "../../../../test/cutils/utils_pwgr/group_sample";
    FILE *f_gr = fopen(path.c_str(), "r");
    ASSERT_NE(f_gr, nullptr);

    struct group gr{0};
    struct group *pgr = nullptr;
    char buf[BUFSIZ];
    size_t i = 0;
    size_t j = 0;
    std::vector<std::vector<std::string>> string_list{
        {}, {}, {},
        {"a", "list", "of", "users"},
        {"are", "split", "by", "comma"},
        {"root", "john", "boob", "jason"}
    };

    std::vector<std::tuple<std::string, std::string, int>> testcase = {
        std::make_tuple("root", "x", 0),
        std::make_tuple("-adm", "x", 4),
        std::make_tuple("+adm", "x", 4),
        std::make_tuple("adm", "x", 4),
        std::make_tuple("adm", "x", 4),
        std::make_tuple("adm", "x", 4),
    };

    for (; i < string_list.size(); ++i) {
        ASSERT_EQ(util_getgrent_r(f_gr, &gr, buf, sizeof(buf), &pgr), 0);
        ASSERT_STREQ(gr.gr_name, std::get<0>(testcase[i]).c_str());
        ASSERT_STREQ(gr.gr_passwd, std::get<1>(testcase[i]).c_str());
        ASSERT_EQ(gr.gr_gid, std::get<2>(testcase[i]));
        if (string_list[i].size()) {
            for (j = 0; j < string_list[i].size(); ++j) {
                EXPECT_TRUE(strcmp(gr.gr_mem[j], string_list[i][j].c_str()) == 0);
            }
        } else {
            EXPECT_TRUE(gr.gr_mem == nullptr);
        }
        EXPECT_TRUE(pgr == &gr);
        gr = {0};
        pgr = nullptr;
    }

    fclose(f_gr);
}