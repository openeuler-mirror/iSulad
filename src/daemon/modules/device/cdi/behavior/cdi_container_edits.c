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
 * Description: provide cdi container edits function
 ******************************************************************************/
#include "cdi_container_edits.h"

// PRESTART_HOOK is the name of the OCI "prestart" hook.
#define PRESTART_HOOK "prestart"
// CREATE_RUNTIME_HOOK is the name of the OCI "createRuntime" hook.
#define CREATE_RUNTIME_HOOK "createRuntime"
// CREATE_CONTAINER_HOOK is the name of the OCI "createContainer" hook.
#define CREATE_CONTAINER_HOOK "createContainer"
// START_CONTAINER_HOOK is the name of the OCI "startContainer" hook.
#define START_CONTAINER_HOOK "startContainer"
// POSTSTART_HOOK is the name of the OCI "poststart" hook.
#define POSTSTART_HOOK "poststart"
// POSTSTOP_HOOK is the name of the OCI "poststop" hook.
#define POSTSTOP_HOOK "poststop"

int cdi_container_edits_apply(cdi_container_edits *e, oci_runtime_spec *spec)
{
    return 0;
}

int cdi_container_edits_validate(cdi_container_edits *e, char **error)
{
    return 0;
}

int cdi_container_edits_append(cdi_container_edits *e, cdi_container_edits *o)
{
    return 0;
}

bool cdi_container_edits_is_empty(cdi_container_edits *e)
{
    return true;
}

