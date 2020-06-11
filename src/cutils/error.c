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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container error functions
 ******************************************************************************/
#include "error.h"
#include "utils.h"

#define ISULAD_ERRMSG_GEN(n, s) { ISULAD_##n, s },
struct isulad_strerror_tab_t {
    isulad_errno_t errcode;
    const char *errmsg;
};
static const struct isulad_strerror_tab_t g_isulad_strerror_tab[] = {
    ISULAD_ERRNO_MAP(ISULAD_ERRMSG_GEN)
};
#undef ISULAD_ERRMSG_GEN

/* errno to error message */
const char *errno_to_error_message(isulad_errno_t err)
{
    if ((size_t)err >= sizeof(g_isulad_strerror_tab) / sizeof(g_isulad_strerror_tab[0])) {
        return g_isulad_strerror_tab[ISULAD_ERR_UNKNOWN].errmsg;
    }
    return g_isulad_strerror_tab[err].errmsg;
}

