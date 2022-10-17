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
 * Description: utils_network mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_UTILS_NETWORK_MOCK_H
#define _ISULAD_TEST_MOCKS_UTILS_NETWORK_MOCK_H

#include <gmock/gmock.h>
#include <sys/mount.h>
#include <pthread.h>

class MockUtilsNetwork {
public:
    virtual ~MockUtilsNetwork() = default;
    MOCK_METHOD5(Mount, int(const char *, const char *, const char *, unsigned long, const void *));
    MOCK_METHOD2(Umount2, int(const char *, int));
    MOCK_METHOD4(PthreadCreate, int(pthread_t *, const pthread_attr_t *, void *(*start_routine)(void *), void *));
    MOCK_METHOD2(PthreadJoin, int(pthread_t, void **));
};

void UtilsNetwork_SetMock(MockUtilsNetwork* mock);

#endif // _ISULAD_TEST_MOCKS_UTILS_NETWORK_MOCK_H
