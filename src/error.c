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
 * Description: provide container error functions
 ******************************************************************************/
#include "error.h"
#include "utils.h"

#define LCRD_ERRMSG_GEN(n, s) { LCRD_##n, s },
struct lcrd_strerror_tab_t {
    lcrd_errno_t errcode;
    const char *errmsg;
};
static const struct lcrd_strerror_tab_t g_lcrd_strerror_tab[] = {
    LCRD_ERRNO_MAP(LCRD_ERRMSG_GEN)
};
#undef LCRD_ERRMSG_GEN

/* errno to error message */
const char *errno_to_error_message(lcrd_errno_t err)
{
    if ((size_t)err >= sizeof(g_lcrd_strerror_tab) / sizeof(g_lcrd_strerror_tab[0])) {
        return g_lcrd_strerror_tab[LCRD_ERR_UNKNOWN].errmsg;
    }
    return g_lcrd_strerror_tab[err].errmsg;
}
