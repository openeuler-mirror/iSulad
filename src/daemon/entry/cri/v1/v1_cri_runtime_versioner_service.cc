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
#include "v1_cri_runtime_versioner_service.h"
#include "cri_constants.h"
#include "config.h"

namespace CRIV1 {
void RuntimeVersionerService::VersionResponseToGRPC(container_version_response *response,
                                                    runtime::v1::VersionResponse *gResponse)
{
    gResponse->set_version(CRI::Constants::kubeAPIVersion);
    gResponse->set_runtime_name(CRI::Constants::iSulaRuntimeName);
    gResponse->set_runtime_version(response->version != nullptr ? response->version : "");
    gResponse->set_runtime_api_version(VERSION);
}

void RuntimeVersionerService::Version(const std::string &apiVersion,
                                      runtime::v1::VersionResponse *versionResponse, Errors &error)
{
    (void)apiVersion;

    if (m_cb == nullptr || m_cb->container.version == nullptr) {
        error.SetError("Unimplemented callback");
        return;
    }

    container_version_response *response { nullptr };
    if (m_cb->container.version(nullptr, &response) != 0) {
        if (response != nullptr && (response->errmsg != nullptr)) {
            error.SetError(response->errmsg);
        } else {
            error.SetError("Failed to call version callback");
        }
    } else {
        VersionResponseToGRPC(response, versionResponse);
    }

    free_container_version_response(response);
}
} // namespace CRI
