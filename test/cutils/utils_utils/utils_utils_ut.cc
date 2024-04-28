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
 * Author: haozi007
 * Create: 2022-10-18
 * Description: utils unit test
 *******************************************************************************/

#include <gtest/gtest.h>
#include "utils.h"
#include "mock.h"

static pid_t test_pid = -1;

extern "C" {
    DECLARE_WRAPPER_V(waitpid, pid_t, (__pid_t pid, int *stat_loc, int options));
    DEFINE_WRAPPER_V(waitpid, pid_t, (__pid_t pid, int *stat_loc, int options), (pid, stat_loc, options));
}

static pid_t waitpid_none_zero(__pid_t pid, int *stat_loc, int options)
{
    *stat_loc = 256;
    return test_pid;
}

static pid_t waitpid_zero(__pid_t pid, int *stat_loc, int options)
{
    *stat_loc = 0;
    return test_pid;
}

#define ExitSignalOffset 128
static int status_to_exit_code(int status)
{
    int exit_code = 0;

    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else {
        exit_code = -1;
    }
    if (WIFSIGNALED(status)) {
        int signal;
        signal = WTERMSIG(status);
        exit_code = ExitSignalOffset + signal;
    }
    return exit_code;
}

TEST(utils_utils, test_util_swap_ptr)
{
    int val1 = 1;
    int val2 = 2;
    int *ptr1 = &val1;
    int *ptr2 = &val2;

    util_swap_ptr((void **)&ptr1, (void **)&ptr2);
    ASSERT_EQ(*ptr1, val2);
    ASSERT_EQ(*ptr2, val1);
}

TEST(utils_utils, test_util_mem_realloc)
{
    char *old = nullptr;
    ASSERT_EQ(util_mem_realloc(nullptr, 0, old, 0), -1);
}

TEST(utils_utils, test_util_sig_parse)
{
    std::string num_str = "9";
    std::string sig_str = "SIGSEGV";
    std::string sig_only = "SEGV";

    ASSERT_EQ(util_sig_parse(nullptr), -1);
    ASSERT_EQ(util_sig_parse(num_str.c_str()), 9);
    ASSERT_EQ(util_sig_parse(sig_str.c_str()), 11);
    ASSERT_EQ(util_sig_parse(sig_str.c_str()), 11);
}

TEST(utils_utils, test_util_contain_errmsg)
{
    int exit_code = 0;
    std::string teststr = "hello world";
    std::vector<std::tuple<std::string, int>> cases = {
        std::make_tuple("executable file not found", 127),
        std::make_tuple("no such file or directory", 127),
        std::make_tuple("system cannot find the file specified", 127),
        std::make_tuple("permission denied", 126),
        std::make_tuple("not a directory", 127),
    };

    for (const auto &elem : cases) {
        util_contain_errmsg(std::get<0>(elem).c_str(), &exit_code);
        ASSERT_EQ(exit_code, std::get<1>(elem));
    }

    // invalid cases
    util_contain_errmsg(nullptr, &exit_code);
    util_contain_errmsg(teststr.c_str(), &exit_code);
    util_contain_errmsg(teststr.c_str(), nullptr);
}

TEST(utils_utils, test_util_digest)
{
    std::string valid_dg = "sha256:729ce43e2c915c3463b620f3fba201a4a641ca5a282387e233db799208342a08";
    std::string invalid_dg = "xxxx";

    ASSERT_STREQ(util_short_digest(valid_dg.c_str()), "729ce43e2c91");
    ASSERT_STREQ(util_short_digest(invalid_dg.c_str()), nullptr);
    ASSERT_STREQ(util_short_digest(nullptr), nullptr);
    ASSERT_STREQ(util_full_digest(nullptr), nullptr);
}

TEST(utils_utils, test_util_proc_info)
{
    char buf[1024] = {0};
    pid_t cpid = getpid();
    proc_t *pt = nullptr;

    ASSERT_EQ(util_stat2proc(nullptr, 10), nullptr);
    ASSERT_EQ(util_stat2proc(buf, 0), nullptr);

    ASSERT_EQ(util_process_alive(0, 10000), false);
    // maybe return true
    ASSERT_EQ(util_process_alive(10000000, 10000), false);

    pt = util_get_process_proc_info(cpid);
    ASSERT_NE(pt, nullptr);
    ASSERT_EQ(util_process_alive(cpid, pt->start_time), true);
    ASSERT_EQ(util_process_alive(cpid, 11), false);

}

void top_cb(char **args, const char *pid_args, size_t args_len)
{
    printf("this is stdout\n");
    fprintf(stderr, "this is stderr\n");
    exit(0);
}

TEST(utils_utils, test_util_exec_top_cmd)
{
    char *out_str = nullptr;
    char *err_str = nullptr;

    ASSERT_EQ(util_exec_top_cmd(top_cb, nullptr, nullptr, 0, &out_str, &err_str), true);
    ASSERT_NE(out_str, nullptr);
    free(out_str);
    ASSERT_NE(err_str, nullptr);
    free(err_str);
}

TEST(utils_utils, test_util_get_backtrace)
{
    char **ret = util_get_backtrace();

    ASSERT_NE(ret, nullptr);
    free(ret);
}

TEST(utils_utils, test_util_env_ops)
{
    char **ret = nullptr;
    size_t ret_len = 0;
    std::string first_val = "hello=world";
    std::string second_val = "todo=test";
    std::string new_val = "hello=test";
    std::string key1 = "hello";
    std::string key2 = "todo";
    char *got = nullptr;

    ASSERT_EQ(util_env_insert(&ret, &ret_len, key1.c_str(), key1.size(), first_val.c_str()), 0);
    ASSERT_EQ(ret_len, 1);
    ASSERT_STREQ(ret[0], first_val.c_str());

    ASSERT_EQ(util_env_insert(&ret, &ret_len, key2.c_str(), key2.size(), second_val.c_str()), 0);
    ASSERT_EQ(ret_len, 2);
    ASSERT_STREQ(ret[1], second_val.c_str());


    got = util_env_get_val(ret, ret_len, key1.c_str(), key1.size());
    ASSERT_STREQ(got, "world");
    free(got);

    ASSERT_EQ(util_env_insert(&ret, &ret_len, key1.c_str(), key1.size(), new_val.c_str()), 0);
    ASSERT_EQ(ret_len, 2);
    ASSERT_STREQ(ret[0], new_val.c_str());

    got = util_env_get_val(ret, ret_len, key2.c_str(), key2.size());
    ASSERT_STREQ(got, "test");
    free(got);

    util_free_array_by_len(ret, ret_len);
}

TEST(utils_utils, test_util_parse_user_remap)
{
    unsigned int uid, gid, offset;
    std::string valid_str = "1000:1000:65535";
    std::string invalid_str = "1000:1000:65536";

    ASSERT_EQ(util_parse_user_remap(valid_str.c_str(), &uid, &gid, &offset), 0);
    ASSERT_EQ(uid, 1000);
    ASSERT_EQ(gid, 1000);
    ASSERT_EQ(offset, 65535);

    ASSERT_EQ(util_parse_user_remap(nullptr, &uid, &gid, &offset), -1);
    ASSERT_EQ(util_parse_user_remap(invalid_str.c_str(), &uid, &gid, &offset), -1);
}

TEST(utils_utils, test_util_check_pid_max_kernel_namespaced)
{
    int ret = system("cat /proc/kallsyms | grep proc_dointvec_pidmax");
    ASSERT_EQ(util_check_pid_max_kernel_namespaced(), ret == 0 ? true : false);
}

TEST(utils_utils, test_util_memset_sensitive_string)
{
    char buff[32] = "hello";

    util_memset_sensitive_string(buff);
    ASSERT_EQ(strlen(buff), 0);
    util_memset_sensitive_string(nullptr);
}

void exec_cb(void *args)
{
    char buff[8] = { 0 };
    int ret;

    ret = util_input_readall(buff, 7);

    if (ret < 0) {
        exit(-1);
    }
    exit(0);
}

void exec_echo_cb(void *args)
{
    char buff[8] = { 0 };
    int ret;
    bool *is_echo = (bool *)args;

    if (*is_echo) {
        ret = util_input_noecho(buff, 7);
    } else {
        ret = util_input_echo(buff, 7);
    }

    if (ret < 0) {
        exit(-1);
    }
    exit(0);
}

TEST(utils_utils, test_util_input)
{
    std::string test = "hello";
    bool is_echo = true;

    ASSERT_EQ(util_exec_cmd(exec_cb, nullptr, test.c_str(), nullptr, nullptr), true);

    ASSERT_EQ(util_exec_cmd(exec_echo_cb, &is_echo, test.c_str(), nullptr, nullptr), false);
    is_echo = false;
    ASSERT_EQ(util_exec_cmd(exec_echo_cb, &is_echo, test.c_str(), nullptr, nullptr), false);
}

TEST(utils_utils, test_util_normalized_host_os_arch)
{
    ASSERT_EQ(util_normalized_host_os_arch(nullptr, nullptr, nullptr), -1);
}

TEST(utils_utils, test_util_read_pid_ppid_info)
{
    pid_t pid = getpid();
    pid_t ppid = getppid();
    pid_ppid_info_t pid_info = { 0 };

    ASSERT_EQ(util_read_pid_ppid_info((uint32_t)pid, &pid_info), 0);
    ASSERT_EQ(pid_info.ppid, (int)ppid);

    ASSERT_EQ(util_read_pid_ppid_info(0, nullptr), -1);
}

TEST(utils_utils, test_util_parse_user_group)
{
    std::string uandg = "user:group";
    char *user = nullptr;
    char *group = nullptr;
    char *tmp = nullptr;

    util_parse_user_group(uandg.c_str(), &user, &group, &tmp);
    ASSERT_STREQ(user, "user");
    ASSERT_STREQ(group, "group");
    free(tmp);
}

TEST(utils_utils, test_dup_map_string_empty_object)
{
    ASSERT_EQ(dup_map_string_empty_object(nullptr), nullptr);
}

int global_total = 0;
int retry_call_test(int success_idx)
{
    if (global_total == success_idx) {
        return 0;
    }
    global_total++;
    return -1;
}

TEST(utils_utils, test_do_retry_call)
{
    int nret;

    global_total = 0;
    DO_RETRY_CALL(10, 100, nret, retry_call_test, 0);
    ASSERT_EQ(nret, 0);
    ASSERT_EQ(global_total, 0);
    global_total = 0;
    DO_RETRY_CALL(10, 100, nret, retry_call_test, 5);
    ASSERT_EQ(nret, 0);
    ASSERT_EQ(global_total, 5);
    global_total = 0;
    DO_RETRY_CALL(10, 100, nret, retry_call_test, 11);
    ASSERT_EQ(global_total, 10);
    ASSERT_EQ(nret, -1);
}

TEST(utils_utils, test_util_waitpid_with_timeout)
{
    int64_t timeout = 2;
    pid_t pid = getpid();
    int status = 0;

    test_pid = pid;
    MOCK_SET_V(waitpid, waitpid_none_zero);
    status = util_waitpid_with_timeout(test_pid, timeout, nullptr);
    ASSERT_EQ(status, 256);
    ASSERT_EQ(status_to_exit_code(status), 1);
    MOCK_CLEAR(waitpid);

    MOCK_SET_V(waitpid, waitpid_zero);
    status = util_waitpid_with_timeout(test_pid, timeout, nullptr);
    ASSERT_EQ(status, 0);
    ASSERT_EQ(status_to_exit_code(status), 0);
    MOCK_CLEAR(waitpid);

    ASSERT_EQ(util_waitpid_with_timeout(pid, timeout, nullptr), -1);

}