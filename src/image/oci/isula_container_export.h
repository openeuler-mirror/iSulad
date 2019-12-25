/******************************************************************************
* Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
* Author: liuhao
* Create: 2019-07-15
* Description: isula container export operator implement
*******************************************************************************/
#ifndef __IMAGE_ISULA_CONTAINER_EXPORT_H
#define __IMAGE_ISULA_CONTAINER_EXPORT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int isula_container_export(const char *name_id, const char *out_file, uint32_t uid, uint32_t gid, uint32_t offset);

#ifdef __cplusplus
}
#endif

#endif
