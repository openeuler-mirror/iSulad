/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide tools functions
 **********************************************************************************/
#define _GNU_SOURCE
#include "libcni_errno.h"
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <signal.h>
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "isula_libutils/log.h"

#define UNDEFINE_ERR "undefine error"

const char * const g_INVOKE_ERR_MSGS[] = {
    "Invalid ERROR code",
    "Invalid invoke argument",
    "Call sprintf_s failed",
    "Terminal by signal",
    "Parse json string failed",
    /* new error message add here */
    "Success"
};

const char *get_invoke_err_msg(int errcode)
{
    if (errcode <= INK_ERR_SUCCESS) {
        return g_INVOKE_ERR_MSGS[errcode - (INK_ERR_MIN)];
    }
    return strerror(errcode);
}

const char * const g_CNI_WELL_KNOWN_ERR_MSGS[] = {
    /* 0 */
    "Success",
    /* 1 */
    "Incompatible CNI version",
    /* 2 */
    "Unsupported field in network configuration.",
    /* 3 */
    "Container unknown or does not exist.",
    /* 4 */
    "Invalid necessary environment variables, like CNI_COMMAND, CNI_CONTAINERID, etc.",
    /* 5 */
    "I/O failure.",
    /* 6 */
    "Failed to decode content.",
    /* 7 */
    "Invalid network config.",
    /* 8 */
    UNDEFINE_ERR,
    /* 9 */
    UNDEFINE_ERR,
    /* 10 */
    UNDEFINE_ERR,
    /* 11 */
    "Try again later.",
    /* max error code is 99 */
};

const char * const g_CNI_CUSTOM_ERR_MSGS[] = {
    UNDEFINE_ERR,
};

const char *get_cni_err_msg(unsigned int errcode)
{
    if (errcode < CNI_ERR_MAX) {
        return g_CNI_WELL_KNOWN_ERR_MSGS[errcode];
    }

    if (errcode > CUSTOM_ERR_MIN && errcode < CUSTOM_ERR_MAX) {
        return g_CNI_CUSTOM_ERR_MSGS[errcode - CUSTOM_ERR_MIN];
    }

    return UNDEFINE_ERR;
}

