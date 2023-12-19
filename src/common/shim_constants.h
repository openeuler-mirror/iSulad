/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2023. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2023-12-25
 * Description: provide shim related macro definition
 ******************************************************************************/

#ifndef COMMON_SHIM_CONSTANTS_H
#define COMMON_SHIM_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

#define SHIIM_LOG_PATH_ENV "ISULAD_SHIIM_LOG_PATH"
#define SHIIM_LOG_LEVEL_ENV "ISULAD_SHIIM_LOG_LEVEL"

// common exit code is defined in stdlib.h
// EXIT_FAILURE 1   : Failing exit status.
// EXIT_SUCCESS 0   : Successful exit status.
// custom shim exit code
// SHIM_EXIT_TIMEOUT 2: Container process timeout exit code
#define SHIM_EXIT_TIMEOUT 2

#define ATTACH_SOCKET "attach.sock"

#define LOG_FIFO_MODE 0600

#ifdef __cplusplus
}
#endif

#endif
