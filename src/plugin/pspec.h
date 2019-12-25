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
 * Author: jingrui
 * Create: 2018-12-01
 * Description: provide plugin definition
 ******************************************************************************/

#ifndef PSPEC_H
#define PSPEC_H /* PSPEC_H */

#include "oci_runtime_spec.h"
#include "oci_runtime_pspec.h"

/*
 * extract pspec from oci.
 * return NULL when failed. oci not modified.
 */
char *get_pspec(oci_runtime_spec *oci);

/*
 * set pspec into oci.
 * return -1 when failed. return 0 means ok.
 */
int set_pspec(oci_runtime_spec *oci, const char *data);

/*
 * generate new pspec using base and data.
 * return NULL when failed.
 * if field in both base and data, using data.
 * if field in base and missing in data, using base.
 */
char *merge_pspec(const char *base, const char *data);

#endif /* PSPEC_H */

