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
 * Author: wujing
 * Create: 2020-02-14
 * Description: provide isulad config mock
 ******************************************************************************/

#ifndef ISULAD_CONFIG_MOCK_H_
#define ISULAD_CONFIG_MOCK_H_

#include <gmock/gmock.h>
#include "isulad_config.h"

class MockIsuladConf {
public:
    virtual ~MockIsuladConf() = default;
    MOCK_METHOD1(GetRuntimeDir, char *(const char *name));
    MOCK_METHOD3(ParseLogopts, int(struct service_arguments *args, const char *key, const char *value));
    MOCK_METHOD0(GetMountrootfs, char *(void));
    MOCK_METHOD1(GetHooks, int(oci_runtime_spec_hooks **phooks));
    MOCK_METHOD1(GetUlimit, int(host_config_ulimits_element ***ulimit));
    MOCK_METHOD0(GetCgroupParent, char *(void));
    MOCK_METHOD0(GetUmask, char *(void));
    MOCK_METHOD0(ConfGetGraphRootpath, char *(void));
    MOCK_METHOD0(ConfGetIsuladStorageDriver, char *(void));
    MOCK_METHOD1(GetSystemCpuUsage, int(uint64_t *val));
    MOCK_METHOD0(ConfGetIsuladStorageDriverBackingFs, char *());
    MOCK_METHOD0(GetMonitordPath, char *(void));
};

void MockIsuladConf_SetMock(MockIsuladConf *mock);

#endif // ISULAD_CONFIG_MOCK_H_
