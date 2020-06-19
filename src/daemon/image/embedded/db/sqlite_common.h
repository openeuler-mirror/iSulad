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
 * Description: provide sqlite function definition
 ******************************************************************************/
#ifndef __DB_SQLITE_COMMON_H_
#define __DB_SQLITE_COMMON_H_

#include <sqlite3.h>

#define DBNAME "sqlite.db"

typedef int(*sqlite_callback_t)(void *, int, char **, char **);

sqlite3 *get_global_db();

int db_sqlite_init(const char *dbpath);

void db_sqlite_finish(void);

int db_sqlite_request(const char *stmt);

int db_sqlite_request_callback(const char *stmt,
                               sqlite_callback_t callback, void *data);

#endif

