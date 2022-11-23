/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-10-17
 * Description: provide template string parse function
 ********************************************************************************/

#ifndef CMD_ISULA_TEMPLATE_STRING_PARSE_H
#define CMD_ISULA_TEMPLATE_STRING_PARSE_H

#ifdef __cplusplus
extern "C" {
#endif

char *parse_single_template_string(const char *arg);

#ifdef __cplusplus
}
#endif

#endif // CMD_ISULA_TEMPLATE_STRING_PARSE_H
