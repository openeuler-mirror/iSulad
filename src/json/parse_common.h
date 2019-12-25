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
 * Author: wujing
 * Create: 2019-02-22
 * Description: provide common parse definition
 ******************************************************************************/

#ifndef __PARSE_COMMON_H
#define __PARSE_COMMON_H

#include "docker_seccomp.h"
#ifdef __cplusplus
extern "C" {
#endif

docker_seccomp *get_seccomp_security_opt_spec(const char *file);

#ifdef __cplusplus
}
#endif

#endif

