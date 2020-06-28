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

#include "driver_quota_mock.h"

namespace {
MockDriverQuota *g_driver_quota_mock = NULL;
}

void MockDriverQuota_SetMock(MockDriverQuota* mock)
{
    g_driver_quota_mock = mock;
}

int getpagesize()
{
    if (g_driver_quota_mock != nullptr) {
        return g_driver_quota_mock->GetPageSize();
    }
    return 0;
}

int ioctl(int fd, unsigned long int cmd, ...)
{
    if (g_driver_quota_mock != nullptr) {
        return g_driver_quota_mock->IOCtl(fd, cmd);
    }
    return 0;
}

int quotactl(int cmd, const char* special, int id, caddr_t addr)
{
    if (g_driver_quota_mock != nullptr) {
        return g_driver_quota_mock->QuotaCtl(cmd, special, id, addr);
    }
    return 0;
}