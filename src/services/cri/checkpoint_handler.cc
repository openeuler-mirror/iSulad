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
 * Description: provide checkpoint handler functions
 *********************************************************************************/
#include "checkpoint_handler.h"

#include <cstring>
#include <memory>
#include <string>
#include <linux/limits.h>
#include <unistd.h>
#include <errno.h>

#include "constants.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "cri_helpers.h"
#include "isula_libutils/cri_checkpoint.h"

namespace cri {
PortMapping &PortMapping::operator=(const PortMapping &obj)
{
    if (&obj == this) {
        return *this;
    }
    delete m_protocol;
    if (obj.m_protocol != nullptr) {
        m_protocol = new std::string(*(obj.m_protocol));
    } else {
        m_protocol = nullptr;
    }
    delete m_containerPort;
    if (obj.m_containerPort != nullptr) {
        m_containerPort = new int32_t(*(obj.m_containerPort));
    } else {
        m_containerPort = nullptr;
    }
    delete m_hostPort;
    if (obj.m_hostPort != nullptr) {
        m_hostPort = new int32_t(*(obj.m_hostPort));
    } else {
        m_hostPort = nullptr;
    }
    return *this;
}

PortMapping::PortMapping(const PortMapping &obj)
{
    if (obj.m_protocol != nullptr) {
        m_protocol = new std::string(*(obj.m_protocol));
    }
    if (obj.m_containerPort != nullptr) {
        m_containerPort = new int32_t(*(obj.m_containerPort));
    }
    if (obj.m_hostPort != nullptr) {
        m_hostPort = new int32_t(*(obj.m_hostPort));
    }
}

PortMapping::~PortMapping()
{
    delete m_protocol;
    delete m_containerPort;
    delete m_hostPort;
}

const std::string *PortMapping::GetProtocol() const
{
    return m_protocol;
}
void PortMapping::SetProtocol(const std::string &protocol)
{
    if (m_protocol != nullptr) {
        *m_protocol = protocol;
    } else {
        m_protocol = new std::string(protocol);
    }
}

const int32_t *PortMapping::GetContainerPort() const
{
    return m_containerPort;
}

void PortMapping::SetContainerPort(int32_t containerPort)
{
    if (m_containerPort != nullptr) {
        *m_containerPort = containerPort;
    } else {
        m_containerPort = new int32_t(containerPort);
    }
}

const int32_t *PortMapping::GetHostPort() const
{
    return m_hostPort;
}

void PortMapping::SetHostPort(int32_t hostPort)
{
    if (m_hostPort != nullptr) {
        *m_hostPort = hostPort;
    } else {
        m_hostPort = new int32_t(hostPort);
    }
}

void PortMapping::PortMappingToCStruct(cri_port_mapping **pmapping, Errors &error)
{
    if (pmapping == nullptr) {
        return;
    }
    *pmapping = (cri_port_mapping *)util_common_calloc_s(sizeof(cri_port_mapping));
    if (*pmapping == nullptr) {
        error.SetError("Out of memory");
        goto out;
    }
    if (m_protocol != nullptr) {
        (*pmapping)->protocol = util_strdup_s(m_protocol->c_str());
    }
    if (m_containerPort != nullptr) {
        (*pmapping)->container_port = (int32_t *)util_common_calloc_s(sizeof(int32_t));
        if ((*pmapping)->container_port == nullptr) {
            error.SetError("Out of memory");
            goto out;
        }
        *((*pmapping)->container_port) = *m_containerPort;
    }
    if (m_hostPort != nullptr) {
        (*pmapping)->host_port = (int32_t *)util_common_calloc_s(sizeof(int32_t));
        if ((*pmapping)->host_port == nullptr) {
            error.SetError("Out of memory");
            goto out;
        }
        *((*pmapping)->host_port) = *m_hostPort;
    }

    return;
out:
    free_cri_port_mapping(*pmapping);
    *pmapping = nullptr;
}

void PortMapping::CStructToPortMapping(const cri_port_mapping *pmapping, Errors &error)
{
    (void)error;
    if (pmapping == nullptr) {
        return;
    }
    if (pmapping->protocol != nullptr) {
        m_protocol = new std::string(pmapping->protocol);
    }
    if (pmapping->container_port != nullptr) {
        m_containerPort = new int32_t(*(pmapping->container_port));
    }
    if (pmapping->host_port != nullptr) {
        m_hostPort = new int32_t(*(pmapping->host_port));
    }
}

const std::vector<PortMapping> &CheckpointData::GetPortMappings() const
{
    return m_portMappings;
}

void CheckpointData::InsertPortMapping(const PortMapping &portMapping)
{
    m_portMappings.push_back(portMapping);
}

bool CheckpointData::GetHostNetwork()
{
    return m_hostNetwork;
}

void CheckpointData::SetHostNetwork(bool hostNetwork)
{
    m_hostNetwork = hostNetwork;
}

void CheckpointData::CheckpointDataToCStruct(cri_checkpoint_data **data, Errors &error)
{
    size_t len = m_portMappings.size();

    if (data == nullptr) {
        return;
    }
    *data = (cri_checkpoint_data *)util_common_calloc_s(sizeof(cri_checkpoint_data));
    if (*data == nullptr) {
        error.SetError("Out of memory");
        goto out;
    }
    (*data)->host_network = m_hostNetwork;
    if (len > 0) {
        if (len > SIZE_MAX / sizeof(cri_port_mapping *)) {
            error.SetError("Invalid port mapping size");
            goto out;
        }
        (*data)->port_mappings = (cri_port_mapping **)util_common_calloc_s(sizeof(cri_port_mapping *) * len);
        if ((*data)->port_mappings == nullptr) {
            error.SetError("Out of memory");
            goto out;
        }
        for (size_t i = 0; i < len; i++) {
            cri_port_mapping *tmp = nullptr;
            m_portMappings[i].PortMappingToCStruct(&tmp, error);
            if (error.NotEmpty()) {
                goto out;
            }
            (*data)->port_mappings[i] = tmp;
            (*data)->port_mappings_len++;
        }
    }
    return;
out:
    free_cri_checkpoint_data(*data);
}

void CheckpointData::CStructToCheckpointData(const cri_checkpoint_data *data, Errors &error)
{
    if (data == nullptr) {
        return;
    }
    m_hostNetwork = data->host_network;
    if (data->port_mappings && data->port_mappings_len > 0) {
        for (size_t i = 0; i < data->port_mappings_len; i++) {
            PortMapping tmpPortMap;
            tmpPortMap.CStructToPortMapping(data->port_mappings[i], error);
            if (error.NotEmpty()) {
                goto out;
            }
            m_portMappings.push_back(tmpPortMap);
        }
    }
    return;
out:
    m_hostNetwork = false;
    m_portMappings.clear();
}

const std::string &PodSandboxCheckpoint::GetVersion() const
{
    return m_version;
}

void PodSandboxCheckpoint::SetVersion(const std::string &version)
{
    m_version = version;
}

const std::string &PodSandboxCheckpoint::GetName() const
{
    return m_name;
}

void PodSandboxCheckpoint::SetName(const std::string &name)
{
    m_name = name;
}

const std::string &PodSandboxCheckpoint::GetNamespace() const
{
    return m_namespace;
}

void PodSandboxCheckpoint::SetNamespace(const std::string &ns)
{
    m_namespace = ns;
}

std::shared_ptr<CheckpointData> PodSandboxCheckpoint::GetData()
{
    return m_data;
}

void PodSandboxCheckpoint::SetData(CheckpointData *data)
{
    m_data = std::shared_ptr<CheckpointData>(data);
}

const std::string &PodSandboxCheckpoint::GetCheckSum() const
{
    return m_checkSum;
}

void PodSandboxCheckpoint::SetCheckSum(const std::string &checkSum)
{
    m_checkSum = checkSum;
}

void PodSandboxCheckpoint::CheckpointToCStruct(cri_checkpoint **checkpoint, Errors &error)
{
    cri_checkpoint_data *cpData = nullptr;

    if (checkpoint == nullptr) {
        return;
    }
    *checkpoint = (cri_checkpoint *)util_common_calloc_s(sizeof(cri_checkpoint));
    if (*checkpoint == nullptr) {
        error.SetError("Out of memory");
        goto out;
    }

    if (m_data != nullptr) {
        m_data->CheckpointDataToCStruct(&cpData, error);
        if (error.NotEmpty()) {
            goto out;
        }
    }

    (*checkpoint)->data = cpData;
    (*checkpoint)->version = util_strdup_s(m_version.c_str());
    (*checkpoint)->name = util_strdup_s(m_name.c_str());
    (*checkpoint)->ns = util_strdup_s(m_namespace.c_str());
    (*checkpoint)->checksum = util_strdup_s(m_checkSum.c_str());

    return;
out:
    free_cri_checkpoint(*checkpoint);
    *checkpoint = nullptr;
}

void PodSandboxCheckpoint::CStructToCheckpoint(const cri_checkpoint *checkpoint, Errors &error)
{
    if (checkpoint == nullptr) {
        return;
    }

    if (checkpoint->data != nullptr) {
        m_data = std::make_shared<CheckpointData>();
        m_data->CStructToCheckpointData(checkpoint->data, error);
        if (error.NotEmpty()) {
            m_data = nullptr;
            return;
        }
    }

    if (checkpoint->version != nullptr) {
        m_version = checkpoint->version;
    }

    if (checkpoint->name != nullptr) {
        m_name = checkpoint->name;
    }

    if (checkpoint->ns != nullptr) {
        m_namespace = checkpoint->ns;
    }

    if (checkpoint->checksum != nullptr) {
        m_checkSum = checkpoint->checksum;
    }
}

} // namespace cri
