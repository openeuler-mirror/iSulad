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
#include <errno.h>

#include "cri_constants.h"
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
        err.Errorf("failed to parse the sandbox name %s: %s", name.c_str(), strerror(errno));
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

void ParseSandboxName(const std::string &name, runtime::v1alpha2::PodSandboxMetadata &metadata, Errors &err)
{
    int ret {};
    std::vector<std::string> items;
    unsigned int attempt;

    ret = parseName(name, items, attempt, err);
    if (ret != 0) {
        return;
    }

    metadata.set_name(items[2]);
    metadata.set_namespace_(items[3]);
    metadata.set_uid(items[4]);
    metadata.set_attempt(attempt);
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

void ParseContainerName(const std::string &name, runtime::v1alpha2::ContainerMetadata *metadata, Errors &err)
{
    int ret {};
    std::vector<std::string> items;
    unsigned int attempt;

    ret = parseName(name, items, attempt, err);
    if (ret != 0) {
        return;
    }

    metadata->set_name(items[1]);
    metadata->set_attempt(attempt);
}

} // namespace CRINaming
