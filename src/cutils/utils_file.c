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
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide container utils functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_file.h"
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <regex.h>
#include <dirent.h>

#include "constants.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "sha256.h"
#include "path.h"
#include "map.h"

static void do_calculate_dir_size_without_hardlink(const char *dirpath, int recursive_depth, int64_t *total_size,
                                                   int64_t *total_inode, map_t *map);

bool util_dir_exists(const char *path)
{
    struct stat s;
    int nret;

    if (path == NULL) {
        return false;
    }

    nret = stat(path, &s);
    if (nret < 0) {
        return false;
    }

    return S_ISDIR(s.st_mode);
}

// This function is identical to "util_file_exists",except that if f is a symbolic file, return true
bool util_fileself_exists(const char *f)
{
    struct stat buf;
    int nret;

    if (f == NULL) {
        return false;
    }

    nret = lstat(f, &buf);
    if (nret < 0) {
        return false;
    }
    return true;
}

// When f is a symbolic file, if the file that it refers to not exits ,return false
bool util_file_exists(const char *f)
{
    struct stat buf;
    int nret;

    if (f == NULL) {
        return false;
    }

    nret = stat(f, &buf);
    if (nret < 0) {
        return false;
    }
    return true;
}

// Remove removes the named file or directory.
int util_path_remove(const char *path)
{
    int saved_errno;

    if (path == NULL) {
        return -1;
    }

    if (unlink(path) == 0) {
        return 0;
    }
    saved_errno = errno;
    if (rmdir(path) == 0) {
        return 0;
    }
    if (errno == ENOTDIR) {
        errno = saved_errno;
    }
    return -1;
}

ssize_t util_write_nointr(int fd, const void *buf, size_t count)
{
    ssize_t nret;

    if (buf == NULL) {
        return -1;
    }

    for (;;) {
        nret = write(fd, buf, count);
        if (nret < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    return nret;
}

ssize_t util_read_nointr(int fd, void *buf, size_t count)
{
    ssize_t nret;

    if (buf == NULL) {
        return -1;
    }

    for (;;) {
        nret = read(fd, buf, count);
        if (nret < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }

    return nret;
}

int util_mkdir_p(const char *dir, mode_t mode)
{
    const char *tmp_pos = NULL;
    const char *base = NULL;
    char *cur_dir = NULL;
    int len = 0;

    if (dir == NULL || strlen(dir) > PATH_MAX) {
        goto err_out;
    }

    tmp_pos = dir;
    base = dir;

    do {
        dir = tmp_pos + strspn(tmp_pos, "/");
        tmp_pos = dir + strcspn(dir, "/");
        len = (int)(dir - base);
        if (len <= 0) {
            break;
        }
        cur_dir = strndup(base, (size_t)len);
        if (cur_dir == NULL) {
            ERROR("strndup failed");
            goto err_out;
        }
        if (*cur_dir) {
            if (mkdir(cur_dir, mode) && (errno != EEXIST || !util_dir_exists(cur_dir))) {
                ERROR("failed to create directory '%s': %s", cur_dir, strerror(errno));
                goto err_out;
            }
        }
        UTIL_FREE_AND_SET_NULL(cur_dir);
    } while (tmp_pos != dir);

    return 0;
err_out:
    free(cur_dir);
    return -1;
}

static bool check_dir_valid(const char *dirpath, int recursive_depth, int *failure)
{
    if ((recursive_depth + 1) > MAX_PATH_DEPTH) {
        ERROR("Reach max path depth: %s", dirpath);
        *failure = 1;
        return false;
    }

    if (!util_dir_exists(dirpath)) {
        return false;
    }

    return true;
}

static int recursive_rmdir_next_depth(struct stat fstat, const char *fname, int recursive_depth, int *saved_errno,
                                      int failure)
{
    if (S_ISDIR(fstat.st_mode)) {
        if (util_recursive_rmdir(fname, (recursive_depth + 1)) < 0) {
            failure = 1;
        }
    } else {
        if (unlink(fname) < 0) {
            ERROR("Failed to delete %s: %s", fname, strerror(errno));
            if (*saved_errno == 0) {
                *saved_errno = errno;
            }
            failure = 1;
        }
    }

    return failure;
}

static int recursive_rmdir_helper(const char *dirpath, int recursive_depth, int *saved_errno)
{
    int nret = 0;
    struct dirent *pdirent = NULL;
    DIR *directory = NULL;
    int failure = 0;
    char fname[MAXPATHLEN];

    directory = opendir(dirpath);
    if (directory == NULL) {
        ERROR("Failed to open %s", dirpath);
        return 1;
    }
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        struct stat fstat;
        int pathname_len;

        if (!strcmp(pdirent->d_name, ".") || !strcmp(pdirent->d_name, "..")) {
            continue;
        }

        (void)memset(fname, 0, sizeof(fname));

        pathname_len = snprintf(fname, MAXPATHLEN, "%s/%s", dirpath, pdirent->d_name);
        if (pathname_len < 0 || pathname_len >= MAXPATHLEN) {
            ERROR("Pathname too long");
            failure = 1;
            continue;
        }

        nret = lstat(fname, &fstat);
        if (nret) {
            ERROR("Failed to stat %s", fname);
            failure = 1;
            continue;
        }

        failure = recursive_rmdir_next_depth(fstat, fname, recursive_depth, saved_errno, failure);
    }

    if (rmdir(dirpath) < 0 && errno != ENOENT) {
        if (*saved_errno == 0) {
            *saved_errno = errno;
        }
        ERROR("Failed to delete %s", dirpath);
        failure = 1;
    }

    nret = closedir(directory);
    if (nret) {
        ERROR("Failed to close directory %s", dirpath);
        failure = 1;
    }

    return failure;
}

int util_recursive_rmdir(const char *dirpath, int recursive_depth)
{
    int failure = 0;
    int saved_errno = 0;

    if (dirpath == NULL) {
        return -1;
    }

    if (!check_dir_valid(dirpath, recursive_depth, &failure)) {
        goto err_out;
    }

    failure = recursive_rmdir_helper(dirpath, recursive_depth, &saved_errno);

err_out:
    errno = saved_errno;
    return failure ? -1 : 0;
}

char *util_path_join(const char *dir, const char *file)
{
    int nret = 0;
    char path[PATH_MAX] = { 0 };
    char cleaned[PATH_MAX] = { 0 };

    if (dir == NULL || file == NULL) {
        ERROR("NULL dir or file failed");
        return NULL;
    }

    nret = snprintf(path, PATH_MAX, "%s/%s", dir, file);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("dir or file too long failed");
        return NULL;
    }

    if (cleanpath(path, cleaned, sizeof(cleaned)) == NULL) {
        ERROR("Failed to clean path: %s", path);
        return NULL;
    }

    return util_strdup_s(cleaned);
}

/*
 * if path do not exist, this function will create it.
 */
int util_ensure_path(char **confpath, const char *path)
{
    int err = -1;
    int fd;
    char real_path[PATH_MAX + 1] = { 0 };

    if (confpath == NULL || path == NULL) {
        return -1;
    }

    fd = util_open(path, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0 && errno != EEXIST) {
        ERROR("failed to open '%s'", path);
        goto err;
    }
    if (fd >= 0) {
        close(fd);
    }

    if (strlen(path) > PATH_MAX || NULL == realpath(path, real_path)) {
        ERROR("Failed to get real path: %s", path);
        goto err;
    }

    *confpath = util_strdup_s(real_path);

    err = EXIT_SUCCESS;

err:
    return err;
}

static void set_char_to_terminator(char *p)
{
    *p = '\0';
}

/*
 * @name is absolute path of this file.
 * make all directory in this absolute path.
 */
int util_build_dir(const char *name)
{
    char *n = NULL;
    char *p = NULL;
    char *e = NULL;
    int nret;

    if (name == NULL) {
        return -1;
    }

    n = util_strdup_s(name);

    if (n == NULL) {
        ERROR("Out of memory while creating directory '%s'.", name);
        return -1;
    }

    e = &n[strlen(n)];
    for (p = n + 1; p < e; p++) {
        if (*p != '/') {
            continue;
        }
        set_char_to_terminator(p);
        nret = mkdir(n, DEFAULT_SECURE_DIRECTORY_MODE);
        if (nret && (errno != EEXIST || !util_dir_exists(n))) {
            ERROR("failed to create directory '%s'.", n);
            free(n);
            return -1;
        }
        *p = '/';
    }
    free(n);
    return 0;
}

char *util_human_size(uint64_t val)
{
    int index = 0;
    int ret = 0;
    size_t len = 0;
    uint64_t ui = 0;
    char *out = NULL;
    char *uf[] = { "B", "KB", "MB", "GB" };

    ui = val;

    for (;;) {
        if (ui < 1024 || index >= 3) {
            break;
        }

        ui = (uint64_t)(ui / 1024);
        index++;
    }

    len = ISULAD_NUMSTRLEN64 + 2 + 1;
    out = util_common_calloc_s(len);
    if (out == NULL) {
        ERROR("Memory out");
        return NULL;
    }

    ret = snprintf(out, len, "%llu%s", (unsigned long long)ui, uf[index]);
    if (ret < 0 || ret >= len) {
        ERROR("Failed to print string");
        free(out);
        return NULL;
    }

    return out;
}

char *util_human_size_decimal(int64_t val)
{
    int nret = 0;
    int kb = 1024;
    int mb = kb * 1024;
    int gb = mb * 1024;
    char out[16] = { 0 }; /* 16 is enough, format like: 123.456 MB */

    if (val >= gb) {
        nret = snprintf(out, sizeof(out), "%.3lf GB", ((double)val / gb));
    } else if (val >= mb) {
        nret = snprintf(out, sizeof(out), "%.3lf MB", ((double)val / mb));
    } else if (val >= kb) {
        nret = snprintf(out, sizeof(out), "%.3lf KB", ((double)val / kb));
    } else {
        nret = snprintf(out, sizeof(out), "%lld B", (long long int)val);
    }
    if (nret < 0 || nret >= sizeof(out)) {
        ERROR("Failed to print string");
        return NULL;
    }

    return util_strdup_s(out);
}

int util_open(const char *filename, int flags, mode_t mode)
{
    char rpath[PATH_MAX] = { 0x00 };

    if (cleanpath(filename, rpath, sizeof(rpath)) == NULL) {
        return -1;
    }
    if (mode) {
        return open(rpath, flags | O_CLOEXEC, mode);
    } else {
        return open(rpath, flags | O_CLOEXEC);
    }
}

FILE *util_fopen(const char *filename, const char *mode)
{
    unsigned int fdmode = 0;
    int f_fd = -1;
    int tmperrno;
    FILE *fp = NULL;
    char rpath[PATH_MAX] = { 0x00 };

    if (mode == NULL) {
        return NULL;
    }

    if (cleanpath(filename, rpath, sizeof(rpath)) == NULL) {
        ERROR("cleanpath failed");
        return NULL;
    }
    if (strncmp(mode, "a+", 2) == 0) {
        fdmode = O_RDWR | O_CREAT | O_APPEND;
    } else if (strncmp(mode, "a", 1) == 0) {
        fdmode = O_WRONLY | O_CREAT | O_APPEND;
    } else if (strncmp(mode, "w+", 2) == 0) {
        fdmode = O_RDWR | O_TRUNC | O_CREAT;
    } else if (strncmp(mode, "w", 1) == 0) {
        fdmode = O_WRONLY | O_TRUNC | O_CREAT;
    } else if (strncmp(mode, "r+", 2) == 0) {
        fdmode = O_RDWR;
    } else if (strncmp(mode, "r", 1) == 0) {
        fdmode = O_RDONLY;
    }

    fdmode |= O_CLOEXEC;

    f_fd = open(rpath, (int)fdmode, 0666);
    if (f_fd < 0) {
        return NULL;
    }

    fp = fdopen(f_fd, mode);
    tmperrno = errno;
    if (fp == NULL) {
        close(f_fd);
    }
    errno = tmperrno;
    return fp;
}

char *util_file_digest(const char *filename)
{
    FILE *fp = NULL;
    char *digest = NULL;

    if (filename == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    fp = util_fopen(filename, "r");
    if (fp == NULL) {
        ERROR("failed to open file %s: %s", filename, strerror(errno));
        return NULL;
    }

    digest = sha256_digest_file(filename, false);
    if (digest == NULL) {
        ERROR("calc digest for file %s failed: %s", filename, strerror(errno));
        goto err_out;
    }

err_out:
    fclose(fp);

    return digest;
}

char *util_gzip_digest(const char *filename)
{
    int ret = 0;
    char *digest = NULL;
    bool gzip = false;

    if (filename == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    ret = util_gzip_compressed(filename, &gzip);
    if (ret != 0) {
        ERROR("Failed to check if it's gzip compressed");
        return NULL;
    }

    if (!gzip) {
        ERROR("File %s is not gziped", filename);
        return NULL;
    }

    digest = sha256_digest_file(filename, true);
    if (digest == NULL) {
        ERROR("calc digest for file %s failed: %s", filename, strerror(errno));
        goto err_out;
    }

err_out:

    return digest;
}

char *util_full_file_digest(const char *filename)
{
    char *digest = NULL;
    char *full_digest = NULL;

    if (filename == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    digest = util_file_digest(filename);
    full_digest = util_full_digest(digest);
    free(digest);

    return full_digest;
}

int util_gzip_compressed(const char *filename, bool *gzip)
{
#define GZIPHEADERLEN 3
    const char gzip_key[GZIPHEADERLEN] = { 0x1F, 0x8B, 0x08 };
    char data[GZIPHEADERLEN] = { 0 };
    size_t size_read = 0;
    int i = 0;
    FILE *f = NULL;
    int ret = 0;

    f = fopen(filename, "rb");
    if (f == NULL) {
        ERROR("Failed to open file %s: %s", filename, strerror(errno));
        return -1;
    }

    size_read = fread(data, 1, GZIPHEADERLEN, f);
    if ((0 == size_read && !feof(f)) || size_read > GZIPHEADERLEN) {
        ERROR("Failed to read file %s, size read %d", filename, (int)size_read);
        ret = -1;
        goto out;
    }

    if (size_read < GZIPHEADERLEN) {
        *gzip = false;
        goto out;
    }

    for (i = 0; i < GZIPHEADERLEN; i++) {
        if (data[i] != gzip_key[i]) {
            *gzip = false;
            goto out;
        }
    }
    *gzip = true;

out:
    fclose(f);
    f = NULL;

    return ret;
}

char *util_full_gzip_digest(const char *filename)
{
    char *digest = NULL;
    char *full_digest = NULL;

    if (filename == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    digest = util_gzip_digest(filename);
    full_digest = util_full_digest(digest);
    free(digest);

    return full_digest;
}

char *util_path_dir(const char *path)
{
    char *dir = NULL;
    int len = 0;
    int i = 0;

    if (path == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    len = (int)strlen(path);
    if (len == 0) {
        return util_strdup_s(".");
    }

    dir = util_strdup_s(path);

    for (i = len - 1; i > 0; i--) {
        if (dir[i] == '/') {
            dir[i] = 0;
            break;
        }
    }

    if (i == 0 && dir[0] == '/') {
        free(dir);
        return util_strdup_s("/");
    }

    return dir;
}

char *util_path_base(const char *path)
{
    char *dir = NULL;
    int len = 0;
    int i = 0;

    if (path == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    len = (int)strlen(path);
    if (len == 0) {
        return util_strdup_s(".");
    }

    dir = util_strdup_s(path);

    // strip last slashes
    for (i = len - 1; i >= 0; i--) {
        if (dir[i] != '/') {
            break;
        }
        dir[i] = '\0';
    }

    len = (int)strlen(dir);
    if (len == 0) {
        free(dir);
        return util_strdup_s("/");
    }

    for (i = len - 1; i >= 0; i--) {
        if (dir[i] == '/') {
            break;
        }
    }

    if (i < 0) {
        return dir;
    }

    char *result = util_strdup_s(&dir[i + 1]);
    free(dir);
    return result;
}

char *util_add_path(const char *path, const char *name)
{
    char *tmp_dir = NULL;
    char *new_path = NULL;

    if (path == NULL || name == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    tmp_dir = util_path_dir(path);
    new_path = util_path_join(tmp_dir, name);
    free(tmp_dir);

    return new_path;
}

/* note: This function can only read small text file. */
char *util_read_text_file(const char *path)
{
    char *buf = NULL;
    long len = 0;
    size_t readlen = 0;
    FILE *filp = NULL;
    const long max_size = 10 * 1024 * 1024; /* 10M */

    if (path == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    filp = util_fopen(path, "r");
    if (filp == NULL) {
        SYSERROR("open file %s failed", path);
        goto err_out;
    }

    if (fseek(filp, 0, SEEK_END)) {
        ERROR("Seek end failed");
        goto err_out;
    }

    len = ftell(filp);
    if (len > max_size) {
        ERROR("File to large!");
        goto err_out;
    }

    if (fseek(filp, 0, SEEK_SET)) {
        ERROR("Seek set failed");
        goto err_out;
    }

    buf = util_common_calloc_s((size_t)(len + 1));
    if (buf == NULL) {
        ERROR("out of memroy");
        goto err_out;
    }

    readlen = fread(buf, 1, (size_t)len, filp);
    if (((readlen < (size_t)len) && (!feof(filp))) || (readlen > (size_t)len)) {
        ERROR("Failed to read file %s, error: %s\n", path, strerror(errno));
        UTIL_FREE_AND_SET_NULL(buf);
        goto err_out;
    }

    buf[(size_t)len] = 0;

err_out:

    if (filp != NULL) {
        fclose(filp);
    }

    return buf;
}

int64_t util_file_size(const char *filename)
{
    struct stat st;

    if (filename == NULL) {
        ERROR("invalid NULL param");
        return -1;
    }

    if (stat(filename, &st)) {
        ERROR("stat file %s failed: %s", filename, strerror(errno));
        return -1;
    }

    return (int64_t)st.st_size;
}

int util_scan_subdirs(const char *directory, subdir_callback_t cb)
{
    DIR *dir = NULL;
    struct dirent *direntp = NULL;
    int ret = 0;

    if (directory == NULL || cb == NULL) {
        return -1;
    }

    dir = opendir(directory);
    if (dir == NULL) {
        ERROR("Failed to open directory: %s error:%s", directory, strerror(errno));
        return -1;
    }

    direntp = readdir(dir);
    for (; direntp != NULL; direntp = readdir(dir)) {
        if (strncmp(direntp->d_name, ".", 1) == 0) {
            continue;
        }

        if (!cb(directory, direntp)) {
            ERROR("Dealwith subdir: %s failed", direntp->d_name);
            ret = -1;
            break;
        }
    }

    closedir(dir);
    return ret;
}

int util_list_all_subdir(const char *directory, char ***out)
{
    DIR *dir = NULL;
    struct dirent *direntp = NULL;
    char **names_array = NULL;
    char tmpdir[PATH_MAX] = { 0 };
    int nret;

    if (directory == NULL || out == NULL) {
        return -1;
    }

    dir = opendir(directory);
    if (dir == NULL) {
        ERROR("Failed to open directory: %s error:%s", directory, strerror(errno));
        return -1;
    }
    direntp = readdir(dir);
    for (; direntp != NULL; direntp = readdir(dir)) {
        if (strncmp(direntp->d_name, ".", 1) == 0) {
            continue;
        }

        nret = snprintf(tmpdir, PATH_MAX, "%s/%s", directory, direntp->d_name);
        if (nret < 0 || nret >= PATH_MAX) {
            ERROR("Sprintf: %s failed", direntp->d_name);
            goto error_out;
        }
        if (!util_dir_exists(tmpdir)) {
            DEBUG("%s is not directory", direntp->d_name);
            continue;
        }
        if (util_array_append(&names_array, direntp->d_name)) {
            ERROR("Failed to append subdirectory array");
            goto error_out;
        }
    }

    closedir(dir);
    *out = names_array;
    return 0;

error_out:
    closedir(dir);
    util_free_array(names_array);
    names_array = NULL;
    return -1;
}

int util_file2str(const char *filename, char *buf, size_t len)
{
    int fd = -1;
    int num_read;

    if (filename == NULL || buf == NULL) {
        return -1;
    }

    fd = util_open(filename, O_RDONLY, 0);
    if (fd == -1) {
        return -1;
    }
    num_read = (int)read(fd, buf, len - 1);
    if (num_read <= 0) {
        num_read = -1;
    } else {
        buf[num_read] = 0;
    }
    close(fd);

    return num_read;
}

static int find_executable(const char *file)
{
    struct stat buf;
    int nret;

    nret = stat(file, &buf);
    if (nret < 0) {
        return errno;
    }
    if (!S_ISDIR(buf.st_mode) && (buf.st_mode & 0111) != 0) {
        return 0;
    }

    return EPERM;
}

char *look_path(const char *file, char **err)
{
    char *path_env = NULL;
    char *tmp = NULL;
    char *full_path = NULL;
    char *ret = NULL;
    char **paths = NULL;
    char **work = NULL;

    if (file == NULL || err == NULL) {
        return NULL;
    }

    /* if slash in file, directly use file and do not try PATH. */
    if (strings_contains_any(file, "/")) {
        int en = find_executable(file);
        if (en == 0) {
            return util_strdup_s(file);
        }
        if (asprintf(err, "find exec %s : %s", file, strerror(en)) < 0) {
            *err = util_strdup_s("Out of memory");
        }
        return NULL;
    }

    path_env = getenv("PATH");
    if (path_env == NULL) {
        *err = util_strdup_s("Not found PATH env");
        return NULL;
    }

    paths = util_string_split(path_env, ':');
    if (paths == NULL) {
        *err = util_strdup_s("Split PATH failed");
        goto free_out;
    }
    for (work = paths; work && *work; work++) {
        tmp = *work;
        if (strcmp("", tmp) == 0) {
            tmp = ".";
        }

        full_path = util_path_join(tmp, file);
        if (full_path == NULL) {
            *err = util_strdup_s("Out of memory");
            goto free_out;
        }
        if (find_executable(full_path) == 0) {
            ret = full_path;
            goto free_out;
        }
        UTIL_FREE_AND_SET_NULL(full_path);
    }

free_out:
    util_free_array(paths);
    return ret;
}

int util_write_file(const char *fname, const char *content, size_t content_len, mode_t mode)
{
    int ret = 0;
    int dst_fd = -1;
    ssize_t len = 0;

    if (fname == NULL) {
        return -1;
    }
    if (content == NULL || content_len == 0) {
        return 0;
    }
    dst_fd = util_open(fname, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (dst_fd < 0) {
        ERROR("Creat file: %s, failed: %s", fname, strerror(errno));
        ret = -1;
        goto free_out;
    }
    len = util_write_nointr(dst_fd, content, content_len);
    if (len < 0 || ((size_t)len) != content_len) {
        ret = -1;
        ERROR("Write file failed: %s", strerror(errno));
        goto free_out;
    }
free_out:
    if (dst_fd >= 0) {
        close(dst_fd);
    }
    return ret;
}

char *verify_file_and_get_real_path(const char *file)
{
#define MAX_FILE_SIZE (10 * SIZE_MB)
    char resolved_path[PATH_MAX] = { 0 };

    if (file == NULL) {
        return NULL;
    }
    if (realpath(file, resolved_path) == NULL) {
        ERROR("Failed to get realpath: %s , %s", resolved_path, strerror(errno));
        return NULL;
    }

    if (!util_file_exists(resolved_path)) {
        ERROR("%s not exist!", resolved_path);
        return NULL;
    }
    if (util_file_size(resolved_path) > MAX_FILE_SIZE) {
        ERROR("%s too large!", resolved_path);
        return NULL;
    }
    return util_strdup_s(resolved_path);
}

int util_copy_file(const char *src_file, const char *dst_file, mode_t mode)
{
#define BUFSIZE 4096
    int ret = 0;
    char *nret = NULL;
    char real_src_file[PATH_MAX + 1] = { 0 };
    int src_fd = -1;
    int dst_fd = -1;
    char buf[BUFSIZE + 1] = { 0 };

    if (src_file == NULL || dst_file == NULL) {
        return ret;
    }
    nret = realpath(src_file, real_src_file);
    if (nret == NULL) {
        ERROR("real path: %s, return: %s", src_file, strerror(errno));
        ret = -1;
        return ret;
    }
    src_fd = util_open(real_src_file, O_RDONLY, CONFIG_FILE_MODE);
    if (src_fd < 0) {
        ERROR("Open src file: %s, failed: %s", real_src_file, strerror(errno));
        ret = -1;
        goto free_out;
    }
    dst_fd = util_open(dst_file, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (dst_fd < 0) {
        ERROR("Creat file: %s, failed: %s", dst_file, strerror(errno));
        ret = -1;
        goto free_out;
    }
    while (true) {
        ssize_t len = util_read_nointr(src_fd, buf, BUFSIZE);
        if (len < 0) {
            ERROR("Read src file failed: %s", strerror(errno));
            ret = -1;
            goto free_out;
        } else if (len == 0) {
            break;
        }
        if (util_write_nointr(dst_fd, buf, (size_t)len) != len) {
            ERROR("Write file failed: %s", strerror(errno));
            ret = -1;
            goto free_out;
        }
    }

free_out:
    if (src_fd >= 0) {
        close(src_fd);
    }
    if (dst_fd >= 0) {
        close(dst_fd);
    }
    return ret;
}

static void recursive_cal_dir_size_helper(const char *dirpath, int recursive_depth, int64_t *total_size,
                                          int64_t *total_inode)
{
    int nret = 0;
    struct dirent *pdirent = NULL;
    DIR *directory = NULL;
    char fname[MAXPATHLEN];

    directory = opendir(dirpath);
    if (directory == NULL) {
        ERROR("Failed to open %s", dirpath);
        return;
    }
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        struct stat fstat;
        int pathname_len;

        if (!strcmp(pdirent->d_name, ".") || !strcmp(pdirent->d_name, "..")) {
            continue;
        }

        (void)memset(fname, 0, sizeof(fname));

        pathname_len = snprintf(fname, MAXPATHLEN, "%s/%s", dirpath, pdirent->d_name);
        if (pathname_len < 0 || pathname_len >= MAXPATHLEN) {
            ERROR("Pathname too long");
            continue;
        }

        nret = lstat(fname, &fstat);
        if (nret) {
            ERROR("Failed to stat %s", fname);
            continue;
        }

        if (S_ISDIR(fstat.st_mode)) {
            int64_t subdir_size = 0;
            int64_t subdir_inode = 0;
            util_calculate_dir_size(fname, (recursive_depth + 1), &subdir_size, &subdir_inode);
            *total_size = *total_size + subdir_size;
            *total_inode = *total_inode + subdir_inode;
        } else {
            *total_size = *total_size + fstat.st_size;
            *total_inode = *total_inode + 1;
        }
    }

    nret = closedir(directory);
    if (nret) {
        ERROR("Failed to close directory %s", dirpath);
    }

    return;
}

void util_calculate_dir_size(const char *dirpath, int recursive_depth, int64_t *total_size, int64_t *total_inode)
{
    int64_t total_size_tmp = 0;
    int64_t total_inode_tmp = 0;

    if (dirpath == NULL) {
        return;
    }

    if ((recursive_depth + 1) > MAX_PATH_DEPTH) {
        ERROR("Reach max path depth: %s", dirpath);
        goto out;
    }

    if (!util_dir_exists(dirpath)) {
        ERROR("dir not exists: %s", dirpath);
        goto out;
    }

    recursive_cal_dir_size_helper(dirpath, recursive_depth, &total_size_tmp, &total_inode_tmp);

    if (total_size != NULL) {
        *total_size = total_size_tmp;
    }
    if (total_inode != NULL) {
        *total_inode = total_inode_tmp;
    }

out:
    return;
}

static void recursive_cal_dir_size__without_hardlink_helper(const char *dirpath, int recursive_depth,
                                                            int64_t *total_size, int64_t *total_inode, map_t *map)
{
    int nret = 0;
    struct dirent *pdirent = NULL;
    DIR *directory = NULL;
    char fname[MAXPATHLEN];

    directory = opendir(dirpath);
    if (directory == NULL) {
        ERROR("Failed to open %s", dirpath);
        return;
    }
    pdirent = readdir(directory);
    for (; pdirent != NULL; pdirent = readdir(directory)) {
        struct stat fstat;
        int pathname_len;

        if (!strcmp(pdirent->d_name, ".") || !strcmp(pdirent->d_name, "..")) {
            continue;
        }

        (void)memset(fname, 0, sizeof(fname));

        pathname_len = snprintf(fname, MAXPATHLEN, "%s/%s", dirpath, pdirent->d_name);
        if (pathname_len < 0 || pathname_len >= MAXPATHLEN) {
            ERROR("Pathname too long");
            continue;
        }

        nret = lstat(fname, &fstat);
        if (nret) {
            ERROR("Failed to stat %s", fname);
            continue;
        }

        if (S_ISDIR(fstat.st_mode)) {
            int64_t subdir_size = 0;
            int64_t subdir_inode = 0;
            do_calculate_dir_size_without_hardlink(fname, (recursive_depth + 1), &subdir_size, &subdir_inode, map);
            *total_size = *total_size + subdir_size;
            *total_inode = *total_inode + subdir_inode;
        } else {
            if (map_search(map, (void *)(&(fstat.st_ino))) != NULL) {
                continue;
            }
            *total_size = *total_size + fstat.st_size;
            *total_inode = *total_inode + 1;
            bool val = true;
            map_insert(map, (void *)(&(fstat.st_ino)), (void *)&val);
        }
    }

    nret = closedir(directory);
    if (nret) {
        ERROR("Failed to close directory %s", dirpath);
    }

    return;
}

static void do_calculate_dir_size_without_hardlink(const char *dirpath, int recursive_depth, int64_t *total_size,
                                                   int64_t *total_inode, map_t *map)
{
    int64_t total_size_tmp = 0;
    int64_t total_inode_tmp = 0;

    if (dirpath == NULL) {
        return;
    }

    if ((recursive_depth + 1) > MAX_PATH_DEPTH) {
        ERROR("Reach max path depth: %s", dirpath);
        goto out;
    }

    if (!util_dir_exists(dirpath)) {
        ERROR("dir not exists: %s", dirpath);
        goto out;
    }

    recursive_cal_dir_size__without_hardlink_helper(dirpath, recursive_depth, &total_size_tmp, &total_inode_tmp, map);

    if (total_size != NULL) {
        *total_size = total_size_tmp;
    }
    if (total_inode != NULL) {
        *total_inode = total_inode_tmp;
    }

out:
    return;
}

void utils_calculate_dir_size_without_hardlink(const char *dirpath, int64_t *total_size, int64_t *total_inode)
{
    int64_t total_size_tmp = 0;
    int64_t total_inode_tmp = 0;
    map_t *map = NULL;

    if (dirpath == NULL) {
        return;
    }

    map = map_new(MAP_INT_BOOL, MAP_DEFAULT_CMP_FUNC, MAP_DEFAULT_FREE_FUNC);
    if (map == NULL) {
        ERROR("Out of memory");
        return;
    }

    if (!util_dir_exists(dirpath)) {
        ERROR("dir not exists: %s", dirpath);
        goto out;
    }

    do_calculate_dir_size_without_hardlink(dirpath, 0, &total_size_tmp, &total_inode_tmp, map);

    if (total_size != NULL) {
        *total_size = total_size_tmp;
    }
    if (total_inode != NULL) {
        *total_inode = total_inode_tmp;
    }

out:
    map_free(map);
    return;
}

static char *get_random_tmp_file(const char *fname)
{
#define RANDOM_TMP_PATH 10
    int nret = 0;
    char *result = NULL;
    char *base = NULL;
    char *dir = NULL;
    char rpath[PATH_MAX] = { 0x00 };
    char random_tmp[RANDOM_TMP_PATH + 1] = { 0x00 };

    base = util_path_base(fname);
    if (base == NULL) {
        ERROR("Failed to get base of %s", fname);
        goto out;
    }

    dir = util_path_dir(fname);
    if (dir == NULL) {
        ERROR("Failed to get dir of %s", fname);
        goto out;
    }

    if (util_generate_random_str(random_tmp, (size_t)RANDOM_TMP_PATH)) {
        ERROR("Failed to generate random str for random path");
        goto out;
    }

    nret = snprintf(rpath, PATH_MAX, ".tmp-%s-%s", base, random_tmp);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Failed to generate tmp base file");
        goto out;
    }

    result = util_path_join(dir, rpath);

out:
    free(base);
    free(dir);
    return result;
}

int util_atomic_write_file(const char *fname, const char *content, size_t content_len, mode_t mode)
{
    int ret = 0;
    char *tmp_file = NULL;
    char rpath[PATH_MAX] = { 0x00 };

    if (fname == NULL) {
        return -1;
    }
    if (content == NULL || content_len == 0) {
        return 0;
    }

    if (cleanpath(fname, rpath, sizeof(rpath)) == NULL) {
        return -1;
    }

    tmp_file = get_random_tmp_file(fname);
    if (tmp_file == NULL) {
        ERROR("Failed to get tmp file for %s", fname);
        ret = -1;
        goto free_out;
    }

    ret = util_write_file(tmp_file, content, content_len, mode);
    if (ret != 0) {
        ERROR("Failed to write content to tmp file for %s", tmp_file);
        ret = -1;
        goto free_out;
    }

    ret = rename(tmp_file, rpath);
    if (ret != 0) {
        ERROR("Failed to rename old file %s to target %s", tmp_file, rpath);
        ret = -1;
        goto free_out;
    }

free_out:
    free(tmp_file);
    return ret;
}

static char *isula_utils_fisula_utils_read_file(FILE *stream, size_t *length)
{
#define JSON_MAX_SIZE (10LL * 1024LL * 1024LL)
    char *buf = NULL;
    char *tmpbuf = NULL;
    size_t off = 0;

    while (1) {
        size_t ret, newsize, sizejudge;
        sizejudge = (JSON_MAX_SIZE - BUFSIZ) - 1;
        if (sizejudge < off) {
            goto out;
        }
        newsize = off + BUFSIZ + 1;

        tmpbuf = (char *)calloc(1, newsize);
        if (tmpbuf == NULL) {
            goto out;
        }

        if (buf != NULL) {
            (void)memcpy(tmpbuf, buf, off);

            (void)memset(buf, 0, off);

            free(buf);
        }

        buf = tmpbuf;
        tmpbuf = NULL;

        ret = fread(buf + off, 1, BUFSIZ, stream);
        if (ret == 0 && ferror(stream)) {
            goto out;
        }
        if (ret < BUFSIZ || feof(stream)) {
            *length = off + ret + 1;
            buf[*length - 1] = '\0';
            return buf;
        }

        off += BUFSIZ;
    }
out:
    free(buf);
    free(tmpbuf);
    return NULL;
}

static int do_check_args(const char *path)
{
    if (path == NULL) {
        return -1;
    }
    if (strlen(path) > PATH_MAX) {
        return -1;
    }
    return 0;
}

char *isula_utils_read_file(const char *path)
{
#define FILE_MODE 0640
    char *buf = NULL;
    char rpath[PATH_MAX + 1] = { 0 };
    int fd = -1;
    int tmperrno = -1;
    FILE *fp = NULL;
    size_t length = 0;

    if (do_check_args(path) != 0) {
        return NULL;
    }

    if (realpath(path, rpath) == NULL) {
        return NULL;
    }

    fd = open(rpath, O_RDONLY | O_CLOEXEC, FILE_MODE);
    if (fd < 0) {
        return NULL;
    }

    fp = fdopen(fd, "r");
    tmperrno = errno;
    if (fp == NULL) {
        (void)close(fd);
        errno = tmperrno;
        return NULL;
    }

    buf = isula_utils_fisula_utils_read_file(fp, &length);
    (void)fclose(fp);
    return buf;
}
