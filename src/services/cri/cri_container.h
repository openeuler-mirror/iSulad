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
 * Description: provide cri container manager function definition
 ********************************************************************************/
#ifndef _CRI_CONTAINER_MANAGER_IMPL_H_
#define _CRI_CONTAINER_MANAGER_IMPL_H_

#include "cri_services.h"
#include "callback.h"

class CRIContainerManagerImpl : public cri::ContainerManager {
public:
    CRIContainerManagerImpl() = default;
    CRIContainerManagerImpl(const CRIContainerManagerImpl &) = delete;
    CRIContainerManagerImpl &operator=(const CRIContainerManagerImpl &) = delete;

    virtual ~CRIContainerManagerImpl() = default;
};

#endif /* _CRI_CONTAINER_MANAGER_IMPL_H_ */
