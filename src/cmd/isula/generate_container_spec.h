/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-09-28
 * Description: provide generate container spec in client
 ******************************************************************************/
#ifndef CMD_ISULA_GENERATE_CONTAINER_SPEC_H
#define CMD_ISULA_GENERATE_CONTAINER_SPEC_H

#include "libisula.h"

#ifdef __cplusplus
extern "C" {
#endif

int generate_container_config(const isula_container_config_t *custom_conf, char **container_config_str);

#ifdef __cplusplus
}
#endif

#endif
