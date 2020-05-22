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
 * Description: provide checkpoint handler function definition
 *********************************************************************************/
#ifndef _CRI_CHECKPOINT_H
#define _CRI_CHECKPOINT_H
#include <string>
#include <vector>
#include <memory>

#include "errors.h"
#include "isula_libutils/cri_checkpoint.h"

namespace cri {
const std::string SANDBOX_CHECKPOINT_DIR { "sandbox" };

class PortMapping {
public:
    PortMapping() = default;
    PortMapping(const PortMapping &obj);
    PortMapping &operator=(const PortMapping &);
    ~PortMapping();
    void PortMappingToCStruct(cri_port_mapping **pmapping, Errors &error);
    void CStructToPortMapping(const cri_port_mapping *pmapping, Errors &error);

    const std::string *GetProtocol() const;
    void SetProtocol(const std::string &protocol);
    const int32_t *GetContainerPort() const;
    void SetContainerPort(int32_t containerPort);
    const int32_t *GetHostPort() const;
    void SetHostPort(int32_t hostPort);

private:
    std::string *m_protocol { nullptr };
    int32_t *m_containerPort { nullptr };
    int32_t *m_hostPort { nullptr };
};

class CheckpointData {
public:
    void CheckpointDataToCStruct(cri_checkpoint_data **data, Errors &error);
    void CStructToCheckpointData(const cri_checkpoint_data *data, Errors &error);

    const std::vector<PortMapping> &GetPortMappings() const;
    void InsertPortMapping(const PortMapping &portMapping);
    bool GetHostNetwork();
    void SetHostNetwork(bool hostNetwork);

private:
    std::vector<PortMapping> m_portMappings;
    bool m_hostNetwork { false };
};

class PodSandboxCheckpoint {
public:
    PodSandboxCheckpoint() = default;
    ~PodSandboxCheckpoint() = default;
    void CheckpointToCStruct(cri_checkpoint **checkpoint, Errors &error);
    void CStructToCheckpoint(const cri_checkpoint *checkpoint, Errors &error);

    const std::string &GetVersion() const;
    void SetVersion(const std::string &version);
    const std::string &GetName() const;
    void SetName(const std::string &name);
    const std::string &GetNamespace() const;
    void SetNamespace(const std::string &ns);
    std::shared_ptr<CheckpointData> GetData();
    void SetData(CheckpointData *data);
    const std::string &GetCheckSum() const;
    void SetCheckSum(const std::string &checkSum);

private:
    std::string m_version { "v1" };
    std::string m_name;
    std::string m_namespace;
    std::shared_ptr<CheckpointData> m_data { nullptr };
    std::string m_checkSum;
};

} // namespace cri
#endif
