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
 * Description: provide specs mock
 ******************************************************************************/

#include "specs_mock.h"

namespace {
MockSpecs *g_specs_mock = nullptr;
}

void MockSpecs_SetMock(MockSpecs *mock)
{
    g_specs_mock = mock;
}

oci_runtime_spec *load_oci_config(const char *rootpath, const char *name)
{
    if (g_specs_mock != nullptr) {
        return g_specs_mock->LoadOciConfig(rootpath, name);
    }
    return nullptr;
}

int merge_conf_cgroup(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    if (g_specs_mock != nullptr) {
        return g_specs_mock->MergeConfCgroup(oci_spec, host_spec);
    }
    return 0;
}

int save_oci_config(const char *id, const char *rootpath, const oci_runtime_spec *oci_spec)
{
    if (g_specs_mock != nullptr) {
        return g_specs_mock->SaveOciConfig(id, rootpath, oci_spec);
    }
    return 0;
}
