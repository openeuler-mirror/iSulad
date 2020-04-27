/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2019-10-25
 * Description: provide regex patten functions
 ********************************************************************************/

#ifndef __UTILS_REGEX_H
#define __UTILS_REGEX_H

#ifdef __cplusplus
extern "C" {
#endif

int util_reg_match(const char *patten, const char *str);

int util_wildcard_to_regex(const char *wildcard, char **regex);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_REGEX_H */

