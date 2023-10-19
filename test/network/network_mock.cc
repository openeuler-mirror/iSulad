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
 * Description: define network mock method
 * Author: liuxu
 * Create: 2023-10-30
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <ostream>

#include <isula_libutils/utils_memory.h>

#include "network_mock.h"
#include "oci_ut_common.h"

cni_cached_info *invoke_network_get_cached_info(char *cache_path)
{
    char *file_path = json_path(cache_path);
    struct parser_context ctx = { OPT_PARSE_STRICT, stderr };
    parser_error jerr = NULL;
    cni_cached_info *info = NULL;

    // check json to cache info
    info = cni_cached_info_parse_file(file_path, &ctx, &jerr);
    EXPECT_THAT(info, testing::NotNull()) << jerr << std::endl;
    free(file_path);

    return info;
}

cni_net_conf_list *invoke_network_get_cni_net_conf_list_from_cached_info(cni_cached_info *info)
{
    if (info == NULL) {
        return NULL;
    }
    parser_error jerr = NULL;
    cni_net_conf_list *list = NULL;
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };

    list = cni_net_conf_list_parse_data(info->config, &ctx, &jerr);
    EXPECT_THAT(list, testing::NotNull()) << jerr << std::endl;

    return list;
}

cni_array_of_strings_container *invoke_network_get_aliases_from_cached_info(cni_cached_info *info)
{
    if (info == NULL) {
        return NULL;
    }
    cni_array_of_strings_container *aliases_array = NULL;

    aliases_array = (cni_array_of_strings_container *)isula_common_calloc_s(sizeof(*aliases_array));
    EXPECT_THAT(aliases_array, testing::NotNull()) << "Out of memory" << std::endl;
    aliases_array->items = (char **)isula_smart_calloc_s(sizeof(char *), info->aliases_len);
    EXPECT_THAT(aliases_array->items, testing::NotNull()) << "Out of memory" << std::endl;
    for (size_t i = 0; i < info->aliases_len; i++) {
        aliases_array->items[i]= util_strdup_s(info->aliases[i]);
        aliases_array->len += 1;
    }

    return aliases_array;
}

