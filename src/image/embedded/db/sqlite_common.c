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
 * Description: provide sqlite functions
 ******************************************************************************/
#include "sqlite_common.h"
#include <limits.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "utils.h"
#include "constants.h"
#include "isula_libutils/log.h"
#include "db_common.h"

// Waiting at most (10 * 1000ms) when database is busy
// to avoid concurrent write or read.
#define SQLITE_BUSY_TIMEOUT 120000

#define SQLITE_PAGECACHE_SIZE 4096
#define SQLITE_PAGECACHE_NUM 8

sqlite3 *g_db = NULL;

sqlite3 *get_global_db()
{
    return g_db;
}

/* db sqlite init */
int db_sqlite_init(const char *dbpath)
{
    int ret = 0;

    sqlite3_config(SQLITE_CONFIG_SERIALIZED);
    ret = sqlite3_open(dbpath, &g_db);
    if (ret != SQLITE_OK) {
        ERROR("Failed to open database %s", sqlite3_errmsg(g_db));
        goto cleanup;
    }
    if (chmod(dbpath, DEFAULT_SECURE_FILE_MODE) != 0) {
        ERROR("Change mode of db file failed: %s", strerror(errno));
        goto cleanup;
    }
    return 0;
cleanup:
    if (g_db != NULL) {
        (void)sqlite3_close(g_db);
    }
    return -1;
}

/* db sqlite finish */
void db_sqlite_finish(void)
{
    if (g_db != NULL) {
        (void)sqlite3_close(g_db);
    }
}

/* db sqlite request */
int db_sqlite_request(const char *stmt)
{
    char *errmsg = NULL;
    int ret;

    ret = sqlite3_busy_timeout(g_db, SQLITE_BUSY_TIMEOUT);
    if (ret != SQLITE_OK) {
        ERROR("Falied to set sqlite busy timeout");
        return ret;
    }
    ret = sqlite3_exec(g_db, stmt, NULL, NULL, &errmsg);
    if (ret != SQLITE_OK) {
        ERROR("Statement %s -> error sqlite3_exec(): %s", stmt, errmsg);
        sqlite3_free(errmsg);
    }
    return ret;
}

/* db sqlite request callback */
int db_sqlite_request_callback(const char *stmt,
                               sqlite_callback_t callback, void *data)
{
    char *errmsg = NULL;
    int ret;

    ret = sqlite3_busy_timeout(g_db, SQLITE_BUSY_TIMEOUT);
    if (ret != SQLITE_OK) {
        ERROR("Falied to set sqlite busy timeout");
        return ret;
    }
    ret = sqlite3_exec(g_db, stmt, callback, data, &errmsg);
    if (ret != SQLITE_OK) {
        ERROR("Statement %s -> error sqlite3_exec(): %s", stmt, errmsg);
        sqlite3_free(errmsg);
    }
    return ret;
}

/* Callback for sql request of 'PRAGMA integrity_check' */
static int callback_integrity_check_result(void *data, int argc, char **argv, char **colname)
{
    if (argc != 1) {
        ERROR("Invalid colums num:%d, it should be 1", argc);
        return DB_FAIL;
    }

    if (argv[0] == NULL) {
        ERROR("Empty result when do integrity check");
        return DB_FAIL;
    }

    if (strcmp(argv[0], "ok") == 0) {
        return DB_OK;
    } else {
        ERROR("Integrity check result not ok");
        return DB_FAIL;
    }
}

/* db integrity check */
int db_integrity_check()
{
    int ret = 0;
    char *buf;

    buf = sqlite3_mprintf("PRAGMA integrity_check;");
    if (buf == NULL) {
        ERROR("Out of memory");
        return DB_OUT_OF_MEMORY;
    }

    ret = db_sqlite_request_callback(buf, callback_integrity_check_result,
                                     NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to do integrity check");
    }

    sqlite3_free(buf);
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db common init */
int db_common_init(const char *rootpath)
{
    int ret = 0;
    int nret = 0;
    char dbpath[PATH_MAX] = { 0 };
    bool retry = true;

    nret = snprintf(dbpath, sizeof(dbpath), "%s/%s", rootpath, DBNAME);
    if (nret < 0 || (size_t)nret >= sizeof(dbpath)) {
        ERROR("Failed to print string");
        return -1;
    }
    ret = sqlite3_config(SQLITE_CONFIG_PAGECACHE, NULL, SQLITE_PAGECACHE_SIZE,
                         SQLITE_PAGECACHE_NUM);
    if (ret != SQLITE_OK) {
        goto open_new_db;
    }

try_open_db:
    ret = db_sqlite_init(dbpath);
    if (ret != SQLITE_OK) {
        goto open_new_db;
    }

    /* Ensure database not broken. */
    ret = db_integrity_check();
    if (ret == DB_OUT_OF_MEMORY) {
        db_common_finish();
        return -1;
    } else if (ret != DB_OK) {
        db_common_finish();
        goto open_new_db;
    }

    (void)sqlite3_soft_heap_limit64(65536);
    INFO("sqlite3 used size: %lld", sqlite3_memory_used());

    return 0;

open_new_db:

    if (retry) {
        /* We can delete database file safely because user will
         * reload image if image not found. Only image managerment
         * module is using database currently. */
        (void)unlink(dbpath);
        ERROR("Delete database file %s because database broken detected", dbpath);

        retry = false;
        /* Try to open a new empty database file if it's deleted. */
        goto try_open_db;
    }

    return -1;
}

/* db common finish */
void db_common_finish(void)
{
    db_sqlite_finish();
}

