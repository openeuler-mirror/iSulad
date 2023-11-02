/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Description: cni operate unit test
 * Author: liuxu
 * Create: 2023-10-28
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "mock.h"
#include "map.h"

#include <isula_libutils/utils_memory.h>
#include <isula_libutils/cni_cached_info.h>
#include <isula_libutils/cni_net_conf_list.h>
#include <isula_libutils/cni_array_of_strings.h>

#include "libcni_cached.h"
#include "cni_operate.h"
#include "network_mock.h"
#include "common.h"

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

extern "C" {
    DECLARE_WRAPPER(cni_cache_read, cni_cached_info *,
        (const char *cache_dir, const char *net_name, const struct runtime_conf *rc));
    DEFINE_WRAPPER(cni_cache_read, cni_cached_info *,
        (const char *cache_dir, const char *net_name, const struct runtime_conf *rc),
        (cache_dir, net_name, rc));

    DECLARE_WRAPPER(cni_check_network_list, int, 
        (const struct cni_network_list_conf *list, const struct runtime_conf *rc, struct cni_opt_result **p_result));
    DEFINE_WRAPPER(cni_check_network_list, int,
        (const struct cni_network_list_conf *list, const struct runtime_conf *rc, struct cni_opt_result **p_result),
        (list, rc, p_result));

    DECLARE_WRAPPER(util_atomic_write_file, int, 
        (const char *fname, const char *content, size_t content_len, mode_t mode, bool sync));
    DEFINE_WRAPPER(util_atomic_write_file, int,
        (const char *fname, const char *content, size_t content_len, mode_t mode, bool sync),
        (fname, content, content_len, mode, sync));
    
    DECLARE_WRAPPER(cni_del_network_list, int, 
        (const struct cni_network_list_conf *list, const struct runtime_conf *rc, struct cni_opt_result **p_result));
    DEFINE_WRAPPER(cni_del_network_list, int,
        (const struct cni_network_list_conf *list, const struct runtime_conf *rc, struct cni_opt_result **p_result),
        (list, rc, p_result));

    DECLARE_WRAPPER(calloc, void *, (size_t nmemb, size_t size));
    DEFINE_WRAPPER(calloc, void *, (size_t nmemb, size_t size), (nmemb, size));
}

#define CNI_CACHE_INFO "../../../../test/network/cni_cache_info.json"

class CniOperateUnitTest : public testing::Test {
public:
    CniOperateUnitTest()
    {
        char *aliases_json = nullptr;
        char *aliases_str = (char *)"aliases";
        parser_error jerr = NULL;
        struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };

        m_info = invoke_network_get_cached_info((char *)CNI_CACHE_INFO);
        m_list.list = invoke_network_get_cni_net_conf_list_from_cached_info(m_info);
        m_list.bytes = cni_net_conf_list_generate_json(m_list.list, &ctx, &jerr);
        m_aliases_array = invoke_network_get_aliases_from_cached_info(m_info);
        m_manager = {
            .id = (char *)"827bdd4b0b4e28d24dbaf3c563687ff6ffd23cd8fda38cadf818ac324fe5de3e", 
            .netns_path = (char *)"/var/run/netns/isulacni-7dbc2c7d85279d5a",
            .ifname = (char *)"eth0"
        };
        m_manager.annotations = map_new(MAP_STR_STR, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
        
        ctx = { OPT_PARSE_STRICT, 0 };
        aliases_json = cni_array_of_strings_container_generate_json(m_aliases_array, &ctx, &jerr);
        if (aliases_json == nullptr) {
            printf("Parse aliases_json failed: %s", jerr);
        }
        (void)map_replace(m_manager.annotations, (void *)aliases_str, (void *)aliases_json);
    
        free(aliases_json);
    }

    ~CniOperateUnitTest()
    {
        free_cni_array_of_strings_container(m_aliases_array);
        free_cni_net_conf_list(m_list.list);
        free(m_list.bytes);
        free_cni_cached_info(m_info);
    }

    void SetUp() override
    {
    }
    void TearDown() override
    {
    }

    cni_cached_info *m_info;
    cni_array_of_strings_container *m_aliases_array;
    struct cni_manager m_manager;
    struct cni_network_list_conf m_list;
};

TEST_F(CniOperateUnitTest, test_check_network_plane)
{
    struct cni_opt_result *result = nullptr;

    {
        EXPECT_EQ(check_network_plane(nullptr, &m_list, &result), -1);
        EXPECT_EQ(check_network_plane(&m_manager, nullptr, &result), -1);

        MOCK_SET(calloc, nullptr);
        EXPECT_EQ(check_network_plane(&m_manager, &m_list, &result), -1);
        MOCK_CLEAR(calloc);
    }

    {    
        // cached info will be free in check_network_plane
        MOCK_SET(cni_cache_read, invoke_network_get_cached_info((char *)CNI_CACHE_INFO));
        MOCK_SET(cni_check_network_list, 0);
        EXPECT_EQ(check_network_plane(&m_manager, &m_list, &result), 0);
        MOCK_CLEAR(cni_check_network_list);
        MOCK_CLEAR(cni_cache_read);
    }
}

TEST_F(CniOperateUnitTest, test_attach_network_plane)
{
    struct cni_opt_result result_val = { 0 }; // let (result != nullptr) to make sure call cni_cache_add
    result_val.cniversion = (char *)"1.0.0";
    struct cni_opt_result *result = &result_val;

    {
        EXPECT_EQ(attach_network_plane(nullptr, &m_list, &result), -1);
        EXPECT_EQ(attach_network_plane(&m_manager, nullptr, &result), -1);

        MOCK_SET(calloc, nullptr);
        EXPECT_EQ(attach_network_plane(&m_manager, &m_list, &result), -1);
        MOCK_CLEAR(calloc);
    }

    {
        m_list.list->plugins_len = 0; // to avoid call add_network
        MOCK_SET(util_atomic_write_file, 0);
        EXPECT_EQ(attach_network_plane(&m_manager, &m_list, &result), 0);
        MOCK_CLEAR(util_atomic_write_file);
    }
}

TEST_F(CniOperateUnitTest, test_detach_network_plane)
{
    struct cni_opt_result *result = nullptr;

    {
        EXPECT_EQ(detach_network_plane(nullptr, &m_list, &result), -1);
        EXPECT_EQ(detach_network_plane(&m_manager, nullptr, &result), -1);

        MOCK_SET(calloc, nullptr);
        EXPECT_EQ(detach_network_plane(&m_manager, &m_list, &result), -1);
        MOCK_CLEAR(calloc);
    }

    {
        // cached info will be free in detach_network_plane
        MOCK_SET(cni_cache_read, invoke_network_get_cached_info((char *)CNI_CACHE_INFO));
        MOCK_SET(cni_del_network_list, 0);
        EXPECT_EQ(detach_network_plane(&m_manager, &m_list, &result), 0);
        MOCK_CLEAR(cni_del_network_list);
        MOCK_CLEAR(cni_cache_read);
    }
}