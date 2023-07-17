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
 * Create: 2023-06-27
 * Description: provide id and name manage functions
 ******************************************************************************/
#ifndef DAEMON_COMMON_ID_NAME_MANAGER_H
#define DAEMON_COMMON_ID_NAME_MANAGER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

int id_store_init(void);
int name_store_init(void);
void id_store_free(void);
void name_store_free(void);
char *try_generate_id(void);
bool try_add_id(const char *id);
bool try_remove_id(const char *id);
bool try_add_name(const char *name);
bool try_remove_name(const char *name);

#ifdef __cplusplus
}
#endif

#endif