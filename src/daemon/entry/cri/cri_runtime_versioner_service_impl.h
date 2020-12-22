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
 * Description: provide cri runtime versioner service implementation function
 *********************************************************************************/

#ifndef DAEMON_ENTRY_CRI_RUNTIME_VERSIONER_IMPL_H
#define DAEMON_ENTRY_CRI_RUNTIME_VERSIONER_IMPL_H

#include "cri_runtime_versioner_service.h"
#include <string>
#include "api.pb.h"
#include "errors.h"
#include "isula_libutils/container_version_response.h"
#include "callback.h"

namespace CRI {
class RuntimeVersionerServiceImpl : public RuntimeVersionerService {
public:
    explicit RuntimeVersionerServiceImpl(service_executor_t *cb) : m_cb(cb) {};
    virtual ~RuntimeVersionerServiceImpl() = default;

    void Version(const std::string &apiVersion, runtime::v1alpha2::VersionResponse *versionResponse,
                 Errors &error) override;

private:
    void VersionResponseToGRPC(container_version_response *response,
                               runtime::v1alpha2::VersionResponse *gResponse);
private:
    service_executor_t *m_cb { nullptr };
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_RUNTIME_VERSIONER_IMPL_H