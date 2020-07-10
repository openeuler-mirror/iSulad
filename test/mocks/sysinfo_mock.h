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
 * Author: jikui
 * Create: 2020-02-25
 * Description: provide sysinfo mock
 ******************************************************************************/

#ifndef _ISULAD_TEST_MOCKS_SYSINFO_MOCK_H
#define _ISULAD_TEST_MOCKS_SYSINFO_MOCK_H

#include <gmock/gmock.h>
#include "sysinfo.h"

class MockSysinfo {
public:
    MOCK_METHOD0(GetDefaultTotalMemSize, uint64_t(void));
    MOCK_METHOD2(FindMountInfo, mountinfo_t*(mountinfo_t **minfos, const char *dir));
    MOCK_METHOD1(FreeMountsInfo, void(mountinfo_t **minfos));
    MOCK_METHOD2(ValidateHugetlb, char*(const char *pagesize, uint64_t limit));
    MOCK_METHOD1(FreeSysinfo, void(sysinfo_t *sysinfo));
};

void MockSysinfo_SetMock(MockSysinfo* mock);

#endif
