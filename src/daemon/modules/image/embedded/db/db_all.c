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
 * Description: provide image functions
 ******************************************************************************/
#include "db_all.h"
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include "isula_libutils/log.h"
#include "utils.h"
#include "db_common.h"
#include "sqlite_common.h"


#define IMAGE_INFO_TABLE_COLUMS_NUM 11
#define IMAGE_INFO_TABLE_STMT "CREATE TABLE IF NOT EXISTS image_info("\
    "image_type TEXT,"\
    "size REAL,"\
    "layer_num INTERGER,"\
    "top_chainid TEXT,"\
    "top_cacheid TEXT,"\
    "config_digest TEXT,"\
    "config_cacheid TEXT,"\
    "config_path TEXT,"\
    "created TEXT,"\
    "mount_string TEXT,"\
    "config TEXT,"\
    "UNIQUE(config_digest,config_path)"\
    ");"

#define IMAGE_NAME_TABLE_COLUMS_NUM 2
#define IMAGE_NAME_TABLE_STMT "CREATE TABLE IF NOT EXISTS image_names("\
    "image_name TEXT PRIMARY KEY,"\
    "image_rowid INTERGER,"\
    "UNIQUE(image_name,image_rowid));"

struct db_image_name {
    char *image_name;
    long long image_rowid;
};

struct db_image_wrapper {
    struct db_image *image;
    long long image_rowid;
};

static pthread_mutex_t g_mutex;

/* g mutex lock */
static inline void g_mutex_lock()
{
    if (pthread_mutex_lock(&g_mutex)) {
        ERROR("Failed to lock mutex");
    }
}

/* g mutex unlock */
static inline void g_mutex_unlock()
{
    if (pthread_mutex_unlock(&g_mutex)) {
        ERROR("Failed to unlock mutex");
    }
}

/* db all init */
int db_all_init()
{
    int ret = 0;

    ret = pthread_mutex_init(&g_mutex, NULL);
    if (ret) {
        ERROR("Mutex initialization failed");
        return -1;
    }

    ret = db_sqlite_request(IMAGE_INFO_TABLE_STMT);
    if (ret != SQLITE_OK) {
        ERROR("Failed to crerate table\n");
        ret = -1;
        goto out;
    }

    ret = db_sqlite_request(IMAGE_NAME_TABLE_STMT);
    if (ret != SQLITE_OK) {
        ERROR("Failed to crerate table\n");
        ret = -1;
        goto out;
    }
out:

    return ret;
}

/* db imgname free */
static void db_imgname_free(struct db_image_name **imagename)
{
    if (imagename == NULL) {
        return;
    }
    if (*imagename == NULL) {
        return;
    }

    UTIL_FREE_AND_SET_NULL((*imagename)->image_name);
    UTIL_FREE_AND_SET_NULL(*imagename);

    return;
}

static int read_single_image_info(sqlite3_stmt *stmt, void *data)
{
    struct db_image *image = NULL;
    long long image_rowid = 0;
    if (sqlite3_column_count(stmt) < IMAGE_INFO_TABLE_COLUMS_NUM) {
        ERROR("Invalid colums num when read image info:%d", sqlite3_column_count(stmt));
        return DB_FAIL;
    }

    image = util_common_calloc_s(sizeof(struct db_image));
    if (image == NULL) {
        ERROR("Out of memory");
        return DB_FAIL;
    }
    image_rowid = sqlite3_column_int64(stmt, 0);

    if (sqlite3_column_text(stmt, 1)) {
        image->image_type = util_strdup_s((char *)sqlite3_column_text(stmt, 1));
    }

    image->size = sqlite3_column_int64(stmt, 2);

    image->layer_num = (size_t) sqlite3_column_int64(stmt, 3);

    if (sqlite3_column_text(stmt, 4)) {
        image->top_chainid = util_strdup_s((const char *)sqlite3_column_text(stmt, 4));
    }

    if (sqlite3_column_text(stmt, 5)) {
        image->top_cacheid = util_strdup_s((const char *)sqlite3_column_text(stmt, 5));
    }

    if (sqlite3_column_text(stmt, 6)) {
        image->config_digest = util_strdup_s((const char *)sqlite3_column_text(stmt, 6));
    }

    if (sqlite3_column_text(stmt, 7)) {
        image->config_cacheid = util_strdup_s((const char *)sqlite3_column_text(stmt, 7));
    }

    if (sqlite3_column_text(stmt, 8)) {
        image->config_path = util_strdup_s((const char *)sqlite3_column_text(stmt, 8));
    }

    if (sqlite3_column_text(stmt, 9)) {
        image->created = util_strdup_s((const char *)sqlite3_column_text(stmt, 9));
    }

    if (sqlite3_column_text(stmt, 10)) {
        image->mount_string = util_strdup_s((const char *)sqlite3_column_text(stmt, 10));
    }

    if (sqlite3_column_text(stmt, 11)) {
        image->config = util_strdup_s((const char *)sqlite3_column_text(stmt, 11));
    }

    ((struct db_image_wrapper *)data)->image = image;
    ((struct db_image_wrapper *)data)->image_rowid = image_rowid;
    return DB_OK;
}

/* db read image sql */
static int db_read_image_sql(const char *image_name,
                             struct db_image **image_info,
                             long long *image_rowid)
{
    int ret = 0;
    struct db_image_wrapper w = { 0 };

    char *sql = "SELECT "
                "image_names.image_rowid,"
                "image_info.image_type,"
                "image_info.size,"
                "image_info.layer_num,"
                "image_info.top_chainid,"
                "image_info.top_cacheid,"
                "image_info.config_digest,"
                "image_info.config_cacheid,"
                "image_info.config_path,"
                "image_info.created,"
                "image_info.mount_string,"
                "image_info.config"
                " FROM image_info,image_names WHERE "
                "image_names.image_name = ? AND "
                "image_info.rowid = "
                "image_names.image_rowid";
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    db = get_global_db();
    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    sqlite3_bind_text(stmt, 1, image_name, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        ret = read_single_image_info(stmt, (void *)&w);
        if (ret != DB_OK) {
            ERROR("Failed to read image info by %s", image_name);
            goto cleanup;
        }
    }

    if (w.image != NULL) {
        w.image->image_name = util_strdup_s(image_name);
    }

    *image_info = w.image;
    *image_rowid = w.image_rowid;

cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db add image name sql */
static int db_add_image_name_sql(const char *image_name, const char *digest, const char *path)
{
    int ret = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char *sql = "INSERT INTO image_names SELECT  ?1,image_info.rowid"
                " FROM image_info WHERE image_info.config_digest = ?2 AND "
                "image_info.config_path = ?3;";
    db = get_global_db();
    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    sqlite3_bind_text(stmt, 1, image_name, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, digest, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, path, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ERROR("Failed to add image name info");
        ret = DB_FAIL;
    }

cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }

    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db save image info sql */
static int db_save_image_info_sql(struct db_image *image)
{
    int ret = 0;
    int64_t layer_num = 0;
    sqlite3 *db = NULL;
    char *sql = "INSERT INTO image_info"
                " SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11 "
                " WHERE NOT EXISTS(SELECT rowid FROM image_info WHERE "
                "image_info.config_digest = ?12 AND "
                "image_info.config_path = ?13);";
    sqlite3_stmt *stmt = NULL;
    db = get_global_db();
    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    sqlite3_bind_text(stmt, 1, image->image_type, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 2, image->size);
    sqlite3_bind_int64(stmt, 3, layer_num);
    image->layer_num = (size_t) layer_num;
    sqlite3_bind_text(stmt, 4, image->top_chainid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, image->top_cacheid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 6, image->config_digest, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 7, image->config_cacheid, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 8, image->config_path, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 9, image->created, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 10, image->mount_string, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 11, image->config, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 12, image->config_digest, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 13, image->config_path, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ERROR("Insert image info into the image information table failed!");
        ret = DB_FAIL;
    }

cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db delete image name sql */
static int db_delete_image_name_sql(char *name)
{
    int ret = 0;
    char *sql = "DELETE FROM image_names WHERE image_name = ?;";
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    db = get_global_db();
    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ERROR("Failed to delete image name by %s", name);
        ret = DB_FAIL;
    }
cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db save image */
int db_save_image(struct db_image *image)
{
    int ret = 0;
    long long image_rowid = 0;
    struct db_image *read_image = NULL;

    if (image == NULL) {
        ERROR("invalid NULL param");
        return DB_INVALID_PARAM;
    }

    g_mutex_lock();

    ret = db_read_image_sql(image->image_name, &read_image, &image_rowid);
    if (ret < 0) {
        goto out;
    }

    if (read_image != NULL) {
        if (strcmp(read_image->config_digest, image->config_digest) == 0 &&
            strcmp(read_image->config_path, image->config_path) == 0) {
            ret = DB_OK;
            goto out;
        }

        ret = DB_NAME_CONFLICT;
        goto out;
    }

    ret = db_save_image_info_sql(image);
    if (ret < 0) {
        goto out;
    }

    ret = db_add_image_name_sql(image->image_name,
                                image->config_digest, image->config_path);
    if (ret) {
        /* Should not error when add image name. If error occurred,
         * database is abnormal, so do not rollback. */
        goto out;
    }

out:
    g_mutex_unlock();
    if (read_image != NULL) {
        db_image_free(&read_image);
    }

    return ret;
}

static int read_single_image_name(sqlite3_stmt *stmt, void *data)
{
    struct db_image_name *imagename = NULL;

    if (sqlite3_column_count(stmt) < IMAGE_NAME_TABLE_COLUMS_NUM) {
        ERROR("Invalid colums num for image name:%d", sqlite3_column_count(stmt));
        return DB_FAIL;
    }

    imagename = util_common_calloc_s(sizeof(struct db_image_name));
    if (imagename == NULL) {
        ERROR("Out of memory");
        return DB_FAIL;
    }

    if (sqlite3_column_text(stmt, 0)) {
        imagename->image_name = util_strdup_s((const char *)sqlite3_column_text(stmt, 0));
    }

    imagename->image_rowid = sqlite3_column_int64(stmt, 1);

    *(struct db_image_name **)data = imagename;
    return DB_OK;
}

/* db read image name sql */
static int db_read_image_name_sql(char *name,
                                  struct db_image_name **imagename)
{
    int ret = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char *sql = "SELECT * FROM image_names WHERE image_name = ?";
    db = get_global_db();
    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    sqlite3_bind_text(stmt, 1, name, -1, SQLITE_STATIC);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ret = read_single_image_name(stmt, (void *)imagename);
        if (ret != DB_OK) {
            ERROR("Failed to read image name by %s", name);
        }
    }
cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db read image rowid sql */
static int db_read_image_rowid_sql(long long rowid,
                                   struct db_image_name **imagename)
{
    int ret = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char *sql = "SELECT * FROM image_names WHERE image_rowid = ?";
    db = get_global_db();
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    sqlite3_bind_int64(stmt, 1, rowid);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        ret = read_single_image_name(stmt, (void *)imagename);
        if (ret != DB_OK) {
            ERROR("Failed to read image rowid by %lld", rowid);
        }
    }
cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db read image */
int db_read_image(const char *name, struct db_image **image)
{
    int ret = 0;
    long long image_rowid = 0;

    if (name == NULL || image == NULL) {
        ERROR("invalid NULl param");
        return DB_INVALID_PARAM;
    }

    g_mutex_lock();

    ret = db_read_image_sql(name, image, &image_rowid);
    if (ret < 0) {
        goto out;
    }

    if (*image == NULL) {
        ret = DB_NOT_EXIST;
        goto out;
    }

out:
    g_mutex_unlock();

    if (ret) {
        db_image_free(image);
    }

    return ret;
}

/* db delete image info sql */
static int db_delete_image_info_sql(long long image_rowid)
{
    int ret = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    char *sql = "DELETE FROM image_info WHERE rowid = ?1 AND NOT EXISTS"
                " (SELECT rowid FROM image_names WHERE image_rowid = ?2);";
    db = get_global_db();
    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    sqlite3_bind_int64(stmt, 1, image_rowid);
    sqlite3_bind_int64(stmt, 2, image_rowid);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ERROR("Failed to delete image info by %lld", image_rowid);
        ret = DB_FAIL;
    }
cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db delete image */
int db_delete_image(char *name, bool force)
{
    int ret = 0;
    struct db_image_name *imagename = NULL;

    if (name == NULL) {
        ERROR("invalid NULl param");
        return DB_INVALID_PARAM;
    }

    g_mutex_lock();

    ret = db_read_image_name_sql(name, &imagename);
    if (ret < 0) {
        ret = -1;
        goto out;
    }

    if (imagename == NULL) {
        ret = DB_NOT_EXIST;
        goto out;
    }

    ret = db_delete_image_name_sql(name);
    if (ret < 0) {
        goto out;
    }

    ret = db_delete_image_info_sql(imagename->image_rowid);
    if (ret < 0) {
        goto out;
    }

out:
    g_mutex_unlock();

    db_imgname_free(&imagename);

    return ret;
}

static int db_exec_sql(const char *sql)
{
    int ret = 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;

    if (sql == NULL || strlen(sql) == 0) {
        return DB_FAIL;
    }

    db = get_global_db();
    ret = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    if (ret != SQLITE_OK) {
        ERROR("Failed to prepare SQL");
        goto cleanup;
    }
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        ERROR("Failed to delete dangling image name");
        ret = DB_FAIL;
    }
cleanup:
    if (stmt && (sqlite3_finalize(stmt) != SQLITE_OK)) {
        ERROR("Failed to finalize sqlite3_stmt");
    }
    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db delete dangling image name sql */
static int db_delete_dangling_image_name_sql()
{
    char *sql = "DELETE FROM image_names WHERE image_rowid NOT IN "
                " (SELECT rowid FROM image_info );";

    return db_exec_sql(sql);
}

/* db delete dangling image info sql */
static int db_delete_dangling_image_info_sql()
{
    char *sql = "DELETE FROM image_info WHERE rowid NOT IN "
                " (SELECT image_rowid FROM "
                "image_names );";

    return db_exec_sql(sql);
}

/* db delete dangling images no lock */
static int db_delete_dangling_image_no_lock()
{
    int ret = 0;

    ret = db_delete_dangling_image_name_sql();
    if (ret) {
        goto out;
    }

    ret = db_delete_dangling_image_info_sql();
    if (ret) {
        goto out;
    }

out:
    return ret;
}

/* db delete dangling images */
int db_delete_dangling_images()
{
    int ret = 0;

    g_mutex_lock();
    ret = db_delete_dangling_image_no_lock();
    g_mutex_unlock();

    return ret;
}

/* db image free */
void db_image_free(struct db_image **image)
{
    if (image == NULL) {
        return;
    }
    if (*image == NULL) {
        return;
    }

    UTIL_FREE_AND_SET_NULL((*image)->image_name);
    UTIL_FREE_AND_SET_NULL((*image)->image_type);
    UTIL_FREE_AND_SET_NULL((*image)->top_chainid);
    UTIL_FREE_AND_SET_NULL((*image)->top_cacheid);
    UTIL_FREE_AND_SET_NULL((*image)->config_digest);
    UTIL_FREE_AND_SET_NULL((*image)->config_cacheid);
    UTIL_FREE_AND_SET_NULL((*image)->config_path);
    UTIL_FREE_AND_SET_NULL((*image)->created);
    UTIL_FREE_AND_SET_NULL((*image)->mount_string);
    UTIL_FREE_AND_SET_NULL((*image)->config);
    UTIL_FREE_AND_SET_NULL(*image);

    return;
}

static int read_all_images_info(sqlite3_stmt *stmt, void **data)
{
    struct db_all_images **imagesinfo = (struct db_all_images **)data;
    struct db_image_wrapper wrapinfo = { 0 };
    size_t oldsize, newsize;
    struct db_image_name *dbimg_name = NULL;
    int ret = 0;

    /* malloc memory when first entering this callback */
    if (*imagesinfo == NULL) {
        *imagesinfo = util_common_calloc_s(sizeof(struct db_all_images));
        if (*imagesinfo == NULL) {
            ERROR("Out of memory");
            goto cleanup;
        }
    }

    if (read_single_image_info(stmt, (void *)&wrapinfo) != DB_OK) {
        ERROR("Failed to read image info!");
        goto cleanup;
    }
    if ((*imagesinfo)->imagesnum > (SIZE_MAX / sizeof(struct db_image *) - 1)) {
        ERROR("List of images is too long:%ld", (*imagesinfo)->imagesnum);
        goto cleanup;
    }
    oldsize = (*imagesinfo)->imagesnum * sizeof(struct db_image *);
    newsize = ((*imagesinfo)->imagesnum + 1) * sizeof(struct db_image *);
    ret = util_mem_realloc((void **)(&(*imagesinfo)->images_info), newsize,
                           (*imagesinfo)->images_info, oldsize);
    if (ret < 0) {
        ERROR("Out of memory!");
        goto cleanup;
    }

    ret = db_read_image_rowid_sql(wrapinfo.image_rowid, &dbimg_name);
    if (ret != 0 || (dbimg_name == NULL) || dbimg_name->image_name == NULL) {
        ERROR("Image not in image name table");
        goto cleanup;
    }
    /* append newinfo to infolist */
    wrapinfo.image->image_name = util_strdup_s(dbimg_name->image_name);

    (*imagesinfo)->images_info[(*imagesinfo)->imagesnum] = wrapinfo.image;
    (*imagesinfo)->imagesnum++;

    db_imgname_free(&dbimg_name);

    return DB_OK;

cleanup:
    if (dbimg_name != NULL) {
        db_imgname_free(&dbimg_name);
    }

    if (*imagesinfo != NULL) {
        db_all_imginfo_free(*imagesinfo);
        *imagesinfo = NULL;
    }

    if (wrapinfo.image != NULL) {
        db_image_free(&wrapinfo.image);
    }
    return DB_FAIL;
}

/* db read all images info sql */
int db_read_all_images_info_sql(struct db_all_images **image_info)
{
    int ret = 0;
    struct db_all_images *w = NULL;
    char *sql = "SELECT rowid,"
                "image_info.image_type,"
                "image_info.size,"
                "image_info.layer_num,"
                "image_info.top_chainid,"
                "image_info.top_cacheid,"
                "image_info.config_digest,"
                "image_info.config_cacheid,"
                "image_info.config_path,"
                "image_info.created,"
                "image_info.mount_string,"
                "image_info.config"
                " FROM image_info";
    sqlite3 *db = NULL;
    sqlite3_stmt *stmt = NULL;
    db = get_global_db();
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        if (stmt != NULL) {
            ERROR("Failed to prepare SQL");
            sqlite3_finalize(stmt);
            return DB_FAIL;
        }
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        if (read_all_images_info(stmt, (void **)&w) != DB_OK) {
            ERROR("Failed to read image info");
            if (w != NULL) {
                db_all_imginfo_free(w);
            }
            sqlite3_finalize(stmt);
            return DB_FAIL;
        }
    }
    ret = sqlite3_finalize(stmt);
    if (ret != SQLITE_OK) {
        ERROR("Failed to finalize sqlite3_stmt");
    }

    *image_info = w;

    return (ret == SQLITE_OK) ? DB_OK : DB_FAIL;
}

/* db read all images info */
int db_read_all_images_info(struct db_all_images **image_info)
{
    int ret = 0;

    g_mutex_lock();

    ret = db_read_all_images_info_sql(image_info);
    if (ret < 0) {
        goto out;
    }

    if (*image_info == NULL) {
        ret = DB_NOT_EXIST;
        goto out;
    }

out:
    g_mutex_unlock();

    if (ret) {
        db_all_imginfo_free(*image_info);
    }

    return ret;
}

/* db all imginfo free */
void db_all_imginfo_free(struct db_all_images *images_info)
{
    struct db_all_images *img = NULL;

    if (images_info == NULL) {
        return;
    }

    img = images_info;

    if (img->images_info != NULL) {
        size_t i;
        for (i = 0; i < img->imagesnum; i++) {
            db_image_free(&(img->images_info[i]));
            img->images_info[i] = NULL;
        }
        free(img->images_info);
        img->images_info = NULL;
    }
    free(img);

    return;
}

