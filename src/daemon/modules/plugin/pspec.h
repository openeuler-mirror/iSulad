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
 * Author: jingrui
 * Create: 2018-12-01
 * Description: provide plugin definition
 ******************************************************************************/

#ifndef DAEMON_MODULES_PLUGIN_PSPEC_H
#define DAEMON_MODULES_PLUGIN_PSPEC_H /* PSPEC_H */

#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/oci_runtime_pspec.h"

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

#endif // DAEMON_MODULES_PLUGIN_PSPEC_H

