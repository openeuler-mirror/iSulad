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
 * Create: 2020-12-21
 * Description: provide cri constants definition
 *********************************************************************************/
# include "cri_constants.h"

namespace CRI {
const std::string Constants::namespaceModeHost { "host" };
const std::string Constants::namespaceModeCNI { "cni" };
const std::string Constants::nameDelimiter { "_" };
const std::string Constants::kubePrefix { "k8s" };
const std::string Constants::sandboxContainerName { "POD" };
const std::string Constants::kubeAPIVersion { "0.1.0" };
const std::string Constants::iSulaRuntimeName { "iSulad" };
}