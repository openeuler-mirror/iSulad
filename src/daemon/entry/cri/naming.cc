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
#include "naming.h"

#include <iostream>
#include <vector>
#include <sstream>
#include <string>
#include <cerrno>

#include "cri_constants.h"
#include "cri_helpers.h"
#include "isula_libutils/log.h"
#include "utils.h"

namespace CRINaming {
static int parseName(const std::string &name, std::vector<std::string> &items, unsigned int &attempt, Errors &err)
{
    std::istringstream f(name);
    std::string part;

    while (getline(f, part, CRI::Constants::nameDelimiterChar)) {
        items.push_back(part);
    }

    if (items.size() != 6) {
        err.Errorf("failed to parse the sandbox name: %s", name.c_str());
        return -1;
    }

    if (items[0] != CRI::Constants::kubePrefix) {
        err.Errorf("container is not managed by kubernetes: %s", name.c_str());
        return -1;
    }

    if (util_safe_uint(items[5].c_str(), &attempt)) {
        SYSERROR("failed to parse the sandbox name %s.", name.c_str());
        err.Errorf("failed to parse the sandbox name %s.", name.c_str());
        return -1;
    }

    return 0;
}

std::string MakeSandboxName(const runtime::v1alpha2::PodSandboxMetadata &metadata)
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

void ParseSandboxName(const std::string &name, const google::protobuf::Map<std::string, std::string> &annotations,
                      runtime::v1alpha2::PodSandboxMetadata &metadata, Errors &err)
{
    // need check uid and attemp 2 items
    int needSetUidOrAttemp = 2;

    if (annotations.count(CRIHelpers::Constants::SANDBOX_NAME_ANNOTATION_KEY) == 0) {
        err.Errorf("annotation don't contains the sandbox name, failed to parse it");
        return;
    }

    if (annotations.count(CRIHelpers::Constants::SANDBOX_NAMESPACE_ANNOTATION_KEY) == 0) {
        err.Errorf("annotation don't contains the sandbox namespace, failed to parse it");
        return;
    }

    metadata.set_name(annotations.at(CRIHelpers::Constants::SANDBOX_NAME_ANNOTATION_KEY));
    metadata.set_namespace_(annotations.at(CRIHelpers::Constants::SANDBOX_NAMESPACE_ANNOTATION_KEY));

    if (annotations.count(CRIHelpers::Constants::SANDBOX_UID_ANNOTATION_KEY) != 0) {
        metadata.set_uid(annotations.at(CRIHelpers::Constants::SANDBOX_UID_ANNOTATION_KEY));
        needSetUidOrAttemp--;
    }

    if (annotations.count(CRIHelpers::Constants::SANDBOX_ATTEMPT_ANNOTATION_KEY) != 0) {
        auto sandboxAttempt = annotations.at(CRIHelpers::Constants::SANDBOX_ATTEMPT_ANNOTATION_KEY);
        metadata.set_attempt(static_cast<google::protobuf::uint32>(std::stoul(sandboxAttempt)));
        needSetUidOrAttemp--;
    }

    if (needSetUidOrAttemp == 0) {
        return;
    }

    // get uid and attempt from name,
    // compatibility to new iSulad manage pods created by old version iSulad
    // maybe should remove in next version of iSulad
    std::vector<std::string> items;
    unsigned int attempt;

    if (parseName(name, items, attempt, err) != 0) {
        return;
    }
    metadata.set_uid(items[4]);
    metadata.set_attempt(static_cast<google::protobuf::uint32>(attempt));
}

std::string MakeContainerName(const runtime::v1alpha2::PodSandboxConfig &s, const runtime::v1alpha2::ContainerConfig &c)
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
                        runtime::v1alpha2::ContainerMetadata *metadata, Errors &err)
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
