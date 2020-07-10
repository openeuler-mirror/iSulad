/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: maoweiyong
 * Create: 2018-11-07
 * Description: provide image definition
 ******************************************************************************/
#ifndef DAEMON_MODULES_IMAGE_EMBEDDED_DB_DB_COMMON_H
#define DAEMON_MODULES_IMAGE_EMBEDDED_DB_DB_COMMON_H

#define DB_OUT_OF_MEMORY        -3
#define DB_INVALID_PARAM        -2
#define DB_FAIL                 -1
#define DB_OK                   0
#define DB_NAME_CONFLICT        1
#define DB_INUSE                2
#define DB_DEL_NAME_ONLY        3
#define DB_DEREF_ONLY           4
#define DB_NOT_EXIST            5

int db_common_init(const char *rootpath);

void db_common_finish(void);

#endif // DAEMON_MODULES_IMAGE_EMBEDDED_DB_DB_COMMON_H

