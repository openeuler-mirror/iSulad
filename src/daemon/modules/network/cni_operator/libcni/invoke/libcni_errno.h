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
 * Description: provide errno definition
 *********************************************************************************/
#ifndef CLIBCNI_INVOKE_ERRNO_H
#define CLIBCNI_INVOKE_ERRNO_H

/*
 * [ -255, -1 ] are errors define by us;
 * 0 is success;
 * [ 1 ... ] are errors return by syscall.
 * */
enum INVOKE_ERR_CODE {
    INK_ERR_MIN = -5,
    INK_ERR_INVALID_ARG,
    INK_ERR_SPRINT_FAILED,
    INK_ERR_TERM_BY_SIG,
    INK_ERR_PARSE_JSON,
    INK_ERR_SUCCESS = 0,
};

/*
 * [ 100 ... 1024 ] are errors define by us;
 * 0 is success
 * */
enum CNI_CUSTOM_ERROR {
    CUSTOM_ERR_MIN = 99,
    /* more errors add herr */
    CUSTOM_ERR_MAX, // max flag
};

const char *get_invoke_err_msg(int errcode);

enum CNI_WELL_KNOW_ERROR {
    CNI_ERR_UNKNOW = 0,
    CNI_ERR_INCOMPATIBLE_CNI_VERSION,
    CNI_ERR_UNSUPPORT_FIELD,
    CNI_ERR_UNKNOWN_CONTAINER,
    CNI_ERR_INVALID_ENV_VARIABLES,
    CNI_ERR_IO_FAILURE,
    CNI_ERR_DECODE_FAILURE,
    CNI_ERR_INVALID_NET_CONFIG,
    CNI_ERR_TRY_AGAIN = 11,
    CNI_ERR_MAX,
    /* max well know error code is 99 */
};

const char *get_cni_err_msg(unsigned int errcode);

#endif
