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
 * Author: tanyifeng
 * Create: 2019-04-02
 * Description: provide overlay2 function definition
 ******************************************************************************/
#ifndef __GRAPHDRIVER_OVERLAY2_H
#define __GRAPHDRIVER_OVERLAY2_H

#include "driver.h"

#ifdef __cplusplus
extern "C" {
#endif

int overlay2_init(struct graphdriver *driver);

int overlay2_parse_options(struct graphdriver *driver, const char **options, size_t options_len);

bool overlay2_is_quota_options(struct graphdriver *driver, const char *option);

#ifdef __cplusplus
}
#endif

#endif

