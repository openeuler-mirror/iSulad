/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: haozi007
 * Create: 2020-09-15
 * Description: provide util function definition
 *********************************************************************************/
#ifndef CLIBCNI_UTILS_H
#define CLIBCNI_UTILS_H

#include <stdbool.h>

#define CNI_VALID_NAME_CHARS "^[a-zA-Z0-9][a-zA-Z0-9_.-]*$"

bool clibcni_util_validate_name(const char *name);

bool clibcni_util_validate_id(const char *id);

bool clibcni_util_validate_interface(const char *if_name);

#endif
