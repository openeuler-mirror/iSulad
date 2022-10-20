/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2022-10-15
 * Description: provide utils_network mock
 ******************************************************************************/

#include "utils_network_mock.h"

namespace {
MockUtilsNetwork *g_utils_network_mock = nullptr;
}

void UtilsNetwork_SetMock(MockUtilsNetwork* mock)
{
    g_utils_network_mock = mock;
}

int mount(const char *source, const char *target, const char *filesystemtype,
          unsigned long mountflags, const void *data)
{
    if (g_utils_network_mock != nullptr) {
        return g_utils_network_mock->Mount(source, target, filesystemtype, mountflags, data);
    }
    return 0;
}

int umount2(const char *target, int flags)
{
    if (g_utils_network_mock != nullptr) {
        return g_utils_network_mock->Umount2(target, flags);
    }
    return 0;
}

int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *),
                   void *arg)
{
    if (g_utils_network_mock != nullptr) {
        return g_utils_network_mock->PthreadCreate(thread, attr, start_routine, arg);
    }
    return 0;
}


int pthread_join(pthread_t thread, void **retval)
{
    if (g_utils_network_mock != nullptr) {
        return g_utils_network_mock->PthreadJoin(thread, retval);
    }
    return 0;
}
