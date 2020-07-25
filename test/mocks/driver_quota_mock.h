/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhangxiaoyu
 * Create: 2020-06-20
 * Description: provide driver quota mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_DRIVER_QUOTA_MOCK_H
#define _ISULAD_TEST_MOCKS_DRIVER_QUOTA_MOCK_H

#include <gmock/gmock.h>
#include "project_quota.h"

class MockDriverQuota {
public:
    virtual ~MockDriverQuota() = default;
    MOCK_METHOD0(GetPageSize, int());
    MOCK_METHOD2(IOCtl, int(int, unsigned long int));
    MOCK_METHOD4(QuotaCtl, int(int, const char*, int, caddr_t));

};

void MockDriverQuota_SetMock(MockDriverQuota* mock);

#endif // _ISULAD_TEST_MOCKS_DRIVER_QUOTA_MOCK_H
