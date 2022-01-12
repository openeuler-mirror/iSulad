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
 * Create: 2020-12-15
 * Description: provide cri pod sandbox manager service function definition
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_RUNTIME_MANAGER_H
#define DAEMON_ENTRY_CRI_RUNTIME_MANAGER_H
#include <memory>
#include <string>
#include <vector>

#include "api.pb.h"
#include "errors.h"
namespace CRI {
class RuntimeManagerService {
public:
    RuntimeManagerService() = default;
    virtual ~RuntimeManagerService() = default;

    virtual void UpdateRuntimeConfig(const runtime::v1alpha2::RuntimeConfig &config, Errors &error) = 0;

    virtual auto Status(Errors &error) -> std::unique_ptr<runtime::v1alpha2::RuntimeStatus> = 0;
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_RUNTIME_MANAGER_H