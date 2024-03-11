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
 * Author: liuxu
 * Create: 2024-03-06
 * Description: provide cdi version function
 ******************************************************************************/
#include "cdi_version.h"

#define CDI_V_CURRENT_VERSION "v"##CDI_CURRENT_VERSION

#define CDI_V010        "v0.1.0"
#define CDI_V020        "v0.2.0"
#define CDI_V030        "v0.3.0"
#define CDI_V040        "v0.4.0"
#define CDI_V050        "v0.5.0"
#define CDI_V060        "v0.6.0"
#define CDI_V_EARLIEST  CDI_V030

const char *cdi_minimum_required_version(cdi_spec *spec)
{
    return NULL;
}

bool cdi_is_greater_than_version(const char *v, const char *o)
{
    return true;
}

bool cdi_is_valid_version(const char *spec_version)
{
    return true;
}
