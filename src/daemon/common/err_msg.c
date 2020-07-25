/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2020-06-15
 * Description: provide container isulad functions
 ******************************************************************************/
#include "err_msg.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "utils.h"
#include "utils_string.h"

// record the errno
__thread char *g_isulad_errmsg = NULL;

/* isulad set error message */
void isulad_set_error_message(const char *format, ...)
{
    int ret = 0;
    char errbuf[BUFSIZ + 1] = { 0 };

    DAEMON_CLEAR_ERRMSG();
    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        return;
    }

    g_isulad_errmsg = util_strdup_s(errbuf);
}

/* isulad try set error message */
void isulad_try_set_error_message(const char *format, ...)
{
    int ret = 0;

    if (g_isulad_errmsg != NULL) {
        return;
    }
    char errbuf[BUFSIZ + 1] = { 0 };

    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        return;
    }

    g_isulad_errmsg = util_strdup_s(errbuf);
}

/* isulad append error message */
void isulad_append_error_message(const char *format, ...)
{
    int ret = 0;
    char errbuf[BUFSIZ + 1] = { 0 };
    char *result = NULL;

    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        return;
    }
    result = util_string_append(g_isulad_errmsg, errbuf);
    if (result == NULL) {
        return;
    }
    if (g_isulad_errmsg != NULL) {
        free(g_isulad_errmsg);
    }
    g_isulad_errmsg = result;
}
