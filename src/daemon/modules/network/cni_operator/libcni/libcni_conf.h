/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide conf function definition
 *********************************************************************************/

#ifndef CLIBCNI_CONF_H
#define CLIBCNI_CONF_H

#include "isula_libutils/cni_net_conf_list.h"

#ifdef __cplusplus
extern "C" {
#endif

struct cni_network_conf *conf_from_bytes(const char *conf_str);

#ifdef __cplusplus
}
#endif

#endif
