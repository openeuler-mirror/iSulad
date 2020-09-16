/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
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
 * [ -255 ... -1 ] are errors define by us;
 * 0 is success
 * [ 1 .... ] are errors return by call syscall.
 * */
enum InvokeErrCode {
    INK_ERR_MIN = -5,
    INK_ERR_INVALID_ARG, // invalid arguments
    INK_ERR_SPRINT_FAILED,
    INK_ERR_TERM_BY_SIG,
    INK_ERR_PARSE_JSON_TO_OBJECT_FAILED,
    INK_SUCCESS = 0,
    INK_ERR_MAX = 1024
};

extern const char *get_invoke_err_msg(int errcode);

#endif
