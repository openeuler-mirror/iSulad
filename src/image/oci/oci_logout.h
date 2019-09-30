/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2019-06-18
 * Description: provide logout function definition
 ******************************************************************************/
#ifndef __OCI_LOGOUT_H
#define __OCI_LOGOUT_H

#include <stdint.h>
#include "image.h"

#ifdef __cplusplus
extern "C" {
#endif

int oci_logout(im_logout_request *request);

#ifdef __cplusplus
}
#endif

#endif
