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
 * Description: provide cri constants definition
 *********************************************************************************/
#ifndef DAEMON_ENTRY_CRI_CRI_CONSTANTS_H
#define DAEMON_ENTRY_CRI_CRI_CONSTANTS_H
#include <string>

namespace CRI {
class Constants {
public:
    const static std::string namespaceModeHost;
    const static std::string namespaceModeFile;
    // sandboxname default values
    const static std::string nameDelimiter;
    constexpr static char nameDelimiterChar { '_' };
    const static std::string kubePrefix;
    const static std::string sandboxContainerName;
    const static std::string kubeAPIVersion;
    const static std::string iSulaRuntimeName;
    constexpr static int64_t DefaultMemorySwap { 0 };
    constexpr static int64_t DefaultSandboxCPUshares { 2 };
    constexpr static int64_t PodInfraOOMAdj { -998 };

    // container mounts files
    constexpr static int MAX_DNS_SEARCHES { 6 };
};
} // namespace CRI

#endif // DAEMON_ENTRY_CRI_CRI_CONSTANTS_H