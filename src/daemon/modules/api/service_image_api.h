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
 * Author: lifeng
 * Create: 2020-06-22
 * Description: provide container supervisor definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_API_SERVICE_IMAGE_API_H
#define DAEMON_MODULES_API_SERVICE_IMAGE_API_H
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int delete_image(const char *image_ref, bool force);

#ifdef __cplusplus
}
#endif

#endif
