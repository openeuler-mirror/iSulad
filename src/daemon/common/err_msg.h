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
 * Author: tanyifeng
 * Create: 2020-06-15
 * Description: provide container isulad definition
 ******************************************************************************/
#ifndef __ERROR_MSG_H
#define __ERROR_MSG_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "utils_timestamp.h"
#include "constants.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/host_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* record the isulad errmsg */
extern __thread char *g_isulad_errmsg;

/* clear the g_isulad_errmsg */
#define DAEMON_CLEAR_ERRMSG()          \
    do {                               \
        if (g_isulad_errmsg != NULL) { \
            free(g_isulad_errmsg);     \
            g_isulad_errmsg = NULL;    \
        }                              \
    } while (0)

void isulad_set_error_message(const char *format, ...);

void isulad_try_set_error_message(const char *format, ...);

void isulad_append_error_message(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
