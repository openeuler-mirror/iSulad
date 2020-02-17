/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wujing
 * Create: 2020-02-14
 * Description: provide namespace mock
 ******************************************************************************/

#include "isulad_config_mock.h"

namespace {
MockIsuladConf *g_isulad_conf_mock = NULL;
}

void MockIsuladConf_SetMock(MockIsuladConf* mock)
{
    g_isulad_conf_mock = mock;
}

char *conf_get_routine_rootdir(const char *runtime)
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetRuntimeDir(runtime);
    }
    return nullptr;
}

int parse_log_opts(struct service_arguments *args, const char *key, const char *value)
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ParseLogopts(args, key, value);
    }
    return -1;
}