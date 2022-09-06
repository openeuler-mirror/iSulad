/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-10-17
 * Description: provide registry api v1 definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_OCI_REGISTRY_REGISTRY_APIV1_H
#define DAEMON_MODULES_IMAGE_OCI_REGISTRY_REGISTRY_APIV1_H

#include <stddef.h>
#include <isula_libutils/imagetool_search_result.h>

#include "registry_type.h"


#ifdef __cplusplus
extern "C" {
#endif

int registry_apiv1_ping(pull_descriptor *desc, char *protocol);

int registry_apiv1_fetch_search_result(pull_descriptor *desc, imagetool_search_result **result);


#ifdef __cplusplus
}
#endif

#endif

