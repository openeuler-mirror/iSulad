/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2024. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2024-07-17
 * Description: provide nri oci functions
 *********************************************************************************/

#ifndef DAEMON_COMMON_NRI_NRI_SPEC_H
#define DAEMON_COMMON_NRI_NRI_SPEC_H

#include <isula_libutils/oci_runtime_spec.h>
#include <isula_libutils/nri_container_adjustment.h>

int nri_adjust_oci_spec(const nri_container_adjustment *adjust, oci_runtime_spec *oci_spec);

#endif // DAEMON_COMMON_NRI_NRI_SPEC_H