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
 * Description: provide container error definition
 ******************************************************************************/
#ifndef __ISULAD_ERROR_H_
#define __ISULAD_ERROR_H_

#include <stdlib.h>
#include <stdarg.h>
#include "utils.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEF_SUCCESS_STR "Success"
#define DEF_ERR_RUNTIME_STR "Runtime error"

#define ISULAD_ERRNO_MAP(XX)                                                                   \
    XX(SUCCESS, DEF_SUCCESS_STR)                                                             \
    \
    /* err in posix api call */                                                              \
    XX(ERR_MEMOUT, "Out of memory")                                                          \
    XX(ERR_MEMSET, "Memory set error")                                                       \
    \
    /* err in other case or call function int thirdparty library */                          \
    XX(ERR_FORMAT, "Error message is too long")                                              \
    XX(ERR_INPUT, "Invalid input parameter")                                                 \
    XX(ERR_EXEC, "Execute operation failed")                                                 \
    XX(ERR_INTERNAL, "Server internal error")                                                \
    XX(ERR_CONNECT, "Can not connect with server.Is the iSulad daemon running on the host?") \
    \
    /* err in runtime module */                                                              \
    XX(ERR_RUNTIME, DEF_ERR_RUNTIME_STR)                                                     \
    \
    /* err max */                                                                            \
    XX(ERR_UNKNOWN, "Unknown error")

#define ISULAD_ERRNO_GEN(n, s) ISULAD_##n,
typedef enum { ISULAD_ERRNO_MAP(ISULAD_ERRNO_GEN) } isulad_errno_t;
#undef ISULAD_ERRNO_GEN

const char *errno_to_error_message(isulad_errno_t err);

static inline void format_errorf(char **err, const char *format, ...)
{
    int ret = 0;
    char errbuf[BUFSIZ + 1] = { 0 };

    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        *err = util_strdup_s("Error is too long!!!");
        return;
    }

    *err = util_strdup_s(errbuf);
}

#ifdef __cplusplus
}
#endif
#endif

