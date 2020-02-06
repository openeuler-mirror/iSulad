/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide cri security context function definition
 *********************************************************************************/
#ifndef _CRI_SECURITY_CONTEXT_H_
#define _CRI_SECURITY_CONTEXT_H_

#include <string>
#include "api.pb.h"
#include "errors.h"
#include "host_config.h"
#include "container_config.h"

namespace CRISecurity {
void ApplySandboxSecurityContext(const runtime::v1alpha2::LinuxPodSandboxConfig &lc, container_config *config,
                                 host_config *hc, Errors &error);

void ApplyContainerSecurityContext(const runtime::v1alpha2::LinuxContainerConfig &lc, const std::string &podSandboxID,
                                   container_config *config, host_config *hc, Errors &errorr);

} // namespace CRISecurity

#endif /* _CRI_SECURITY_CONTEXT_H_ */
