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

#include "sysinfo_mock.h"

namespace {
MockSysinfo *g_sysinfo_mock = nullptr;
}

void MockSysinfo_SetMock(MockSysinfo *mock)
{
    g_sysinfo_mock = mock;
}

uint64_t get_default_total_mem_size(void)
{
    if (g_sysinfo_mock != nullptr) {
        return g_sysinfo_mock->GetDefaultTotalMemSize();
    }
    return 0;
}

mountinfo_t *find_mount_info(mountinfo_t **minfos, const char *dir)
{
    if (g_sysinfo_mock != nullptr) {
        return g_sysinfo_mock->FindMountInfo(minfos, dir);
    }
    return nullptr;
}

void free_mounts_info(mountinfo_t **minfos)
{
    if (g_sysinfo_mock != nullptr) {
        return g_sysinfo_mock->FreeMountsInfo(minfos);
    }
}

char *validate_hugetlb(const char *pagesize, uint64_t limit)
{
    if (g_sysinfo_mock != nullptr) {
        return g_sysinfo_mock->ValidateHugetlb(pagesize, limit);
    }
    return nullptr;
}

void free_sysinfo(sysinfo_t *sysinfo)
{
    if (g_sysinfo_mock != nullptr) {
        return g_sysinfo_mock->FreeSysinfo(sysinfo);
    }
}
