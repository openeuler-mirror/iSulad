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

#ifndef DAEMON_ENTRY_CRI_V1_NAMING_H
#define DAEMON_ENTRY_CRI_V1_NAMING_H

#include "api_v1.pb.h"
#include <string>
#include "errors.h"

namespace CRINamingV1 {
std::string MakeSandboxName(const runtime::v1::PodSandboxMetadata &metadata);

std::string MakeContainerName(const runtime::v1::PodSandboxConfig &s,
                              const runtime::v1::ContainerConfig &c);

void ParseSandboxName(const google::protobuf::Map<std::string, std::string> &annotations,
                      runtime::v1::PodSandboxMetadata &metadata, Errors &err);

void ParseContainerName(const google::protobuf::Map<std::string, std::string> &annotations,
                        runtime::v1::ContainerMetadata *metadata, Errors &err);
} // namespace CRINamingV1

#endif // DAEMON_ENTRY_CRI_V1_NAMING_H
