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
 * Description: provide naming functions
 *********************************************************************************/
#include "v1_naming.h"

#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <errno.h>

#include "cri_constants.h"
#include "cri_helpers.h"
#include "isula_libutils/log.h"
#include "utils.h"

namespace CRINamingV1 {
std::string MakeSandboxName(const runtime::v1::PodSandboxMetadata &metadata)
{
    std::string sname;
    sname.append(CRI::Constants::kubePrefix);
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(CRI::Constants::sandboxContainerName);
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(metadata.name());
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(metadata.namespace_());
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(metadata.uid());
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(std::to_string(metadata.attempt()));

    return sname;
}

void ParseSandboxName(const google::protobuf::Map<std::string, std::string> &annotations,
                      runtime::v1::PodSandboxMetadata &metadata, Errors &err)
{
    if (annotations.count(CRIHelpers::Constants::SANDBOX_NAME_ANNOTATION_KEY) == 0) {
        err.Errorf("annotation don't contains the sandbox name, failed to parse it");
        return;
    }

    if (annotations.count(CRIHelpers::Constants::SANDBOX_NAMESPACE_ANNOTATION_KEY) == 0) {
        err.Errorf("annotation don't contains the sandbox namespace, failed to parse it");
        return;
    }

    if (annotations.count(CRIHelpers::Constants::SANDBOX_UID_ANNOTATION_KEY) == 0) {
        err.Errorf("annotation don't contains the sandbox uid, failed to parse it");
        return;
    }

    if (annotations.count(CRIHelpers::Constants::SANDBOX_ATTEMPT_ANNOTATION_KEY) == 0) {
        err.Errorf("annotation don't contains the sandbox attempt, failed to parse it");
        return;
    }

    metadata.set_name(annotations.at(CRIHelpers::Constants::SANDBOX_NAME_ANNOTATION_KEY));
    metadata.set_namespace_(annotations.at(CRIHelpers::Constants::SANDBOX_NAMESPACE_ANNOTATION_KEY));
    metadata.set_uid(annotations.at(CRIHelpers::Constants::SANDBOX_UID_ANNOTATION_KEY));
    auto sandboxAttempt = annotations.at(CRIHelpers::Constants::SANDBOX_ATTEMPT_ANNOTATION_KEY);
    metadata.set_attempt(static_cast<google::protobuf::uint32>(std::stoul(sandboxAttempt)));
}

std::string MakeContainerName(const runtime::v1::PodSandboxConfig &s, const runtime::v1::ContainerConfig &c)
{
    std::string sname;

    sname.append(CRI::Constants::kubePrefix);
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(c.metadata().name());
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(s.metadata().name());
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(s.metadata().namespace_());
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(s.metadata().uid());
    sname.append(CRI::Constants::nameDelimiter);
    sname.append(std::to_string(c.metadata().attempt()));

    return sname;
}

void ParseContainerName(const google::protobuf::Map<std::string, std::string> &annotations,
                        runtime::v1::ContainerMetadata *metadata, Errors &err)
{
    if (annotations.count(CRIHelpers::Constants::CONTAINER_NAME_ANNOTATION_KEY) == 0) {
        err.Errorf("annotation don't contains the container name, failed to parse it");
        return;
    }
    metadata->set_name(annotations.at(CRIHelpers::Constants::CONTAINER_NAME_ANNOTATION_KEY));

    std::string containerAttempt = "0";
    if (annotations.count(CRIHelpers::Constants::CONTAINER_ATTEMPT_ANNOTATION_KEY) != 0) {
        containerAttempt = annotations.at(CRIHelpers::Constants::CONTAINER_ATTEMPT_ANNOTATION_KEY);
    }

    metadata->set_attempt(static_cast<google::protobuf::uint32>(std::stoul(containerAttempt)));
}

} // namespace CRINaming
