/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide naming function definition
 *********************************************************************************/

#ifndef _CRI_NAMING_H_
#define _CRI_NAMING_H_

#include "cri_runtime_service.h"
#include <string>

namespace CRINaming {
std::string MakeSandboxName(const runtime::v1alpha2::PodSandboxMetadata &metadata);

std::string MakeContainerName(const runtime::v1alpha2::PodSandboxConfig &s,
                              const runtime::v1alpha2::ContainerConfig &c);

void ParseSandboxName(const std::string &name, runtime::v1alpha2::PodSandboxMetadata &metadata, Errors &err);

void ParseContainerName(const std::string &name, runtime::v1alpha2::ContainerMetadata *metadata, Errors &err);
} // namespace CRINaming

#endif /* _CRI_RUNTIME_SERVICES_IMPL_H_ */
