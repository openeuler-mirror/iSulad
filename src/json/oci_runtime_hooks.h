/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container oci runtime hooks functions definition
 *******************************************************************************/

#ifndef _CONTAINER_HOOKS_H
# define _CONTAINER_HOOKS_H

# include "oci_runtime_spec.h"

#ifdef __cplusplus
extern "C" {
#endif

oci_runtime_spec_hooks *oci_runtime_spec_hooks_parse_file(const char *filename,
                                                          const struct parser_context *ctx, parser_error *err);

#ifdef __cplusplus
}
#endif

#endif

