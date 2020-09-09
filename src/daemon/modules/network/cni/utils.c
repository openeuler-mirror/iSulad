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
 * Description: provide util functions
 *********************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <regex.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "utils.h"
#include "isula_libutils/log.h"

#define ISSLASH(C) ((C) == '/')
#define IS_ABSOLUTE_FILE_NAME(F) (ISSLASH((F)[0]))

char *clibcni_util_strdup_s(const char *src)
{
    char *dst = NULL;

    if (src == NULL) {
        return NULL;
    }

    dst = strdup(src);
    if (dst == NULL) {
        abort();
    }

    return dst;
}

static bool do_clean_path_continue(const char *endpos, const char *stpos, const char *respath, char **dst)
{
    bool check_dot = (endpos - stpos == 1 && stpos[0] == '.');
    bool check_dot_dot = (endpos - stpos == 2 && stpos[0] == '.' && stpos[1] == '.');

    if (check_dot) {
        return true;
    } else if (check_dot_dot) {
        char *dest = *dst;
        if (dest <= respath + 1) {
            return true;
        }
        for (--dest; dest > respath && !ISSLASH(dest[-1]); --dest) {
            continue;
        }
        *dst = dest;
        return true;
    }
    return false;
}

static int do_clean_path(const char *respath, const char *limit_respath, const char *stpos, char **dst)
{
    char *dest = *dst;
    const char *endpos = NULL;

    endpos = stpos;

    for (; *stpos; stpos = endpos) {
        while (ISSLASH(*stpos)) {
            ++stpos;
        }

        for (endpos = stpos; *endpos && !ISSLASH(*endpos); ++endpos) {
        }

        if (endpos - stpos == 0) {
            break;
        } else if (do_clean_path_continue(endpos, stpos, respath, &dest)) {
            continue;
        }

        if (!ISSLASH(dest[-1])) {
            *dest++ = '/';
        }

        if (dest + (endpos - stpos) >= limit_respath) {
            ERROR("Path is too long");
            if (dest > respath + 1) {
                dest--;
            }
            *dest = '\0';
            return -1;
        }

        (void)memcpy(dest, stpos, (size_t)(endpos - stpos));
        dest += endpos - stpos;
        *dest = '\0';
    }
    *dst = dest;
    return 0;
}

static inline bool check_cleanpath_args(const char *path, const char *cleaned_path, size_t cleaned_path_len)
{
    return (path == NULL || path[0] == '\0' || cleaned_path == NULL || (cleaned_path_len < PATH_MAX));
}

char *cleanpath(const char *path, char *cleaned_path, size_t cleaned_path_len)
{
    char *respath = NULL;
    char *dest = NULL;
    const char *stpos = NULL;
    const char *limit_respath = NULL;

    if (check_cleanpath_args(path, cleaned_path, cleaned_path_len)) {
        return NULL;
    }

    respath = cleaned_path;

    (void)memset(respath, 0, cleaned_path_len);
    limit_respath = respath + PATH_MAX;

    if (!IS_ABSOLUTE_FILE_NAME(path)) {
        if (!getcwd(respath, PATH_MAX)) {
            ERROR("Failed to getcwd");
            respath[0] = '\0';
            goto error;
        }
        dest = strchr(respath, '\0');
        if (dest == NULL) {
            ERROR("Failed to get the end of respath");
            goto error;
        }
        if (strlen(path) >= (PATH_MAX - 1) - strlen(respath)) {
            ERROR("%s path too long", path);
            goto error;
        }
        (void)strcat(respath, path);
        stpos = path;
    } else {
        dest = respath;
        *dest++ = '/';
        stpos = path;
    }

    if (do_clean_path(respath, limit_respath, stpos, &dest)) {
        goto error;
    }

    if (dest > respath + 1 && ISSLASH(dest[-1])) {
        --dest;
    }
    *dest = '\0';

    return respath;

error:
    return NULL;
}

bool clibcni_is_null_or_empty(const char *str)
{
    return (str == NULL || strlen(str) == 0);
}

void *clibcni_util_smart_calloc_s(size_t count, size_t unit_size)
{
    if (unit_size == 0) {
        return NULL;
    }

    if (count > (CLIBCNI_MAX_MEMORY_SIZE / unit_size)) {
        return NULL;
    }

    return calloc(count, unit_size);
}

void *clibcni_util_common_calloc_s(size_t size)
{
    if (size == 0) {
        return NULL;
    }

    return calloc(1, size);
}

size_t clibcni_util_array_len(const char * const *array)
{
    const char * const *pos;
    size_t len = 0;

    for (pos = array; pos != NULL && *pos != NULL; pos++) {
        len++;
    }

    return len;
}

/* util free array */
void clibcni_util_free_array(char **array)
{
    char **p = NULL;

    if (array == NULL) {
        return;
    }

    for (p = array; p != NULL && *p != NULL; p++) {
        free(*p);
        *p = NULL;
    }
    free((void *)array);
}

ssize_t clibcni_util_write_nointr(int fd, const void *buf, size_t count)
{
    ssize_t n = 0;
    bool empty_buf = (buf == NULL || count == 0);

    if (fd == -1) {
        return -1;
    }
    if (empty_buf) {
        return 0;
    }
    for (;;) {
        n = write(fd, buf, count);
        if (n < 0 && errno == EINTR) {
            continue;
        } else if (n < 0 && errno == EAGAIN) {
            continue;
        } else {
            break;
        }
    }
    return n;
}

ssize_t clibcni_util_read_nointr(int fd, void *buf, size_t count)
{
    ssize_t rn = 0;
    bool empty_buf = (buf == NULL || count == 0);

    if (fd == -1) {
        return -1;
    }
    if (empty_buf) {
        return 0;
    }
    for (;;) {
        rn = read(fd, buf, count);
        if (rn < 0 && errno == EINTR) {
            continue;
        }
        break;
    }

    return rn;
}

static char *do_string_join(const char *sep, const char * const *parts, size_t parts_len, size_t result_len)
{
    char *res_string = NULL;
    size_t iter = 0;

    if (result_len > (SIZE_MAX - 1)) {
        return NULL;
    }

    res_string = clibcni_util_common_calloc_s(result_len + 1);
    if (res_string == NULL) {
        return NULL;
    }

    for (iter = 0; iter < parts_len - 1; iter++) {
        (void)strcat(res_string, parts[iter]);
        (void)strcat(res_string, sep);
    }
    (void)strcat(res_string, parts[parts_len - 1]);

    return res_string;
}

static inline bool check_clibcni_util_string_join_args(const char *sep, const char * const *parts, size_t len)
{
    return (sep == NULL || strlen(sep) == 0 || len == 0 || parts == NULL);
}

char *clibcni_util_string_join(const char *sep, const char * const *parts, size_t len)
{
    size_t sep_len = 0;
    size_t result_len = 0;
    size_t iter = 0;

    if (check_clibcni_util_string_join_args(sep, parts, len)) {
        ERROR("Invalid arguments");
        return NULL;
    }

    sep_len = strlen(sep);
    if (len > SIZE_MAX / sep_len) {
        ERROR("Large string");
        return NULL;
    }
    result_len = (len - 1) * sep_len;
    for (iter = 0; iter < len; iter++) {
        if (parts[iter] == NULL) {
            return NULL;
        }
        result_len += strlen(parts[iter]);
    }
    return do_string_join(sep, parts, len, result_len);
}

static char *do_uint8_join(const char *sep, const char *type, const uint8_t *parts, size_t parts_len, size_t result_len)
{
#define MAX_UINT_LEN 3
    char *res_string = NULL;
    size_t iter = 0;
    char buffer[MAX_UINT_LEN + 1] = { 0 };
    int nret = 0;

    if (result_len > (SIZE_MAX - 1)) {
        ERROR("Large string");
        return NULL;
    }

    res_string = clibcni_util_common_calloc_s(result_len + 1);
    if (res_string == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    for (iter = 0; iter < parts_len - 1; iter++) {
        nret = snprintf(buffer, MAX_UINT_LEN + 1, type, parts[iter]);
        if (nret < 0 || nret >= MAX_UINT_LEN + 1) {
            ERROR("Sprint failed");
            free(res_string);
            return NULL;
        }
        (void)strcat(res_string, buffer);
        (void)strcat(res_string, sep);
    }
    nret = snprintf(buffer, sizeof(buffer), type, parts[parts_len - 1]);
    if (nret < 0 || nret >= MAX_UINT_LEN + 1) {
        ERROR("Sprint failed");
        free(res_string);
        return NULL;
    }
    (void)strcat(res_string, buffer);

    return res_string;
}

static inline bool check_clibcni_util_uint8_join_args(const char *sep, const uint8_t *parts, size_t len)
{
    return (sep == NULL || strlen(sep) == 0 || len == 0 || parts == NULL);
}

char *clibcni_util_uint8_join(const char *sep, const char *type, const uint8_t *parts, size_t len)
{
    size_t sep_len = 0;
    size_t result_len = 0;

    if (check_clibcni_util_uint8_join_args(sep, parts, len)) {
        ERROR("Invalid arguments");
        return NULL;
    }

    sep_len = strlen(sep);
    if (len > SIZE_MAX / sep_len) {
        ERROR("Large string");
        return NULL;
    }
    result_len = (len - 1) * sep_len;

    if (len > SIZE_MAX / MAX_UINT_LEN) {
        ERROR("Large string");
        return NULL;
    }
    result_len += (MAX_UINT_LEN * len);

    return do_uint8_join(sep, type, parts, len, result_len);
}

static inline bool check_do_clibcni_util_safe_uint_args(const char *numstr, const char *err_str)
{
    return (err_str == NULL || err_str == numstr || *err_str != '\0');
}

static int do_clibcni_util_safe_uint(const char *numstr, const char *err_str, unsigned long long ull,
                                     unsigned int *converted)
{
    if (check_do_clibcni_util_safe_uint_args(numstr, err_str)) {
        return -EINVAL;
    }

    if (ull > UINT_MAX) {
        return -ERANGE;
    }

    *converted = (unsigned int)ull;
    return 0;
}

int clibcni_util_safe_uint(const char *numstr, unsigned int *converted)
{
    char *err_str = NULL;
    unsigned long long ull = 0;

    if (converted == NULL) {
        return -1;
    }
    errno = 0;
    ull = strtoull(numstr, &err_str, 0);
    if (errno > 0) {
        return -errno;
    }

    return do_clibcni_util_safe_uint(numstr, err_str, ull, converted);
}

bool clibcni_util_dir_exists(const char *path)
{
    struct stat s = { 0 };
    int nret = 0;

    if (path == NULL) {
        return false;
    }
    nret = stat(path, &s);
    if (nret < 0) {
        return false;
    }

    return S_ISDIR(s.st_mode);
}

static int do_clibcni_util_grow_array(char ***orig_array, size_t *orig_capacity, size_t size, size_t increment)
{
    size_t add_capacity = 0;
    char **add_array = NULL;

    if (increment == 0) {
        return 0;
    }
    add_capacity = *orig_capacity;
    while (size + 1 > add_capacity) {
        add_capacity += increment;
    }
    if (add_capacity != *orig_capacity) {
        add_array = clibcni_util_smart_calloc_s(add_capacity, sizeof(void *));
        if (add_array == NULL) {
            return -1;
        }
        if (*orig_array != NULL) {
            (void)memcpy(add_array, *orig_array, *orig_capacity * sizeof(void *));
            free((void *)*orig_array);
        }

        *orig_array = add_array;
        *orig_capacity = add_capacity;
    }

    return 0;
}

int clibcni_util_grow_array(char ***orig_array, size_t *orig_capacity, size_t size, size_t increment)
{
    if (orig_array == NULL || orig_capacity == NULL) {
        return -1;
    }

    if (*orig_array == NULL || *orig_capacity == 0) {
        *orig_array = NULL;
        *orig_capacity = 0;
    }

    return do_clibcni_util_grow_array(orig_array, orig_capacity, size, increment);
}

static int do_clibcni_util_validate_absolute_path(const char *path, regmatch_t *pregmatch)
{
    regex_t preg;
    int nret = 0;
    int status = 0;

    if (regcomp(&preg, "^(/[^/ ]*)+/?$", REG_NOSUB | REG_EXTENDED) != 0) {
        nret = -1;
        goto err_out;
    }

    status = regexec(&preg, path, 1, pregmatch, 0);
    regfree(&preg);
    if (status != 0) {
        nret = -1;
        goto err_out;
    }
err_out:
    return nret;
}

int clibcni_util_validate_absolute_path(const char *path)
{
    regmatch_t regmatch;

    if (path == NULL) {
        return -1;
    }

    (void)memset(&regmatch, 0, sizeof(regmatch_t));

    return do_clibcni_util_validate_absolute_path(path, &regmatch);
}

static int do_clibcni_util_validate_name(const char *name, regmatch_t *pregmatch)
{
    int nret = 0;
    int status = 0;
    regex_t preg;

    if (regcomp(&preg, "^([a-z0-9][-a-z0-9.]*)?[a-z0-9]$", REG_NOSUB | REG_EXTENDED) != 0) {
        nret = -1;
        goto err_out;
    }

    status = regexec(&preg, name, 1, pregmatch, 0);
    regfree(&preg);
    if (status != 0) {
        nret = -1;
        goto err_out;
    }
err_out:
    return nret;
}

static inline bool check_clibcni_util_validate_name_args(const char *name)
{
#define MAX_LEN_NAME 200
    return (name == NULL || strlen(name) > MAX_LEN_NAME);
}

int clibcni_util_validate_name(const char *name)
{
    regmatch_t regmatch;

    if (check_clibcni_util_validate_name_args(name)) {
        return -1;
    }

    (void)memset(&regmatch, 0, sizeof(regmatch_t));

    return do_clibcni_util_validate_name(name, &regmatch);
}

static void set_char_to_terminator(char *p)
{
    *p = '\0';
}

/*
 * @name is absolute path of this file.
 * make all directory in this absolute path.
 * */
int clibcni_util_build_dir(const char *name)
{
    char *n = NULL; // because we'll be modifying it
    char *p = NULL;
    char *e = NULL;
    int nret = 0;

    if (name == NULL) {
        ERROR("name is NULL");
        return -1;
    }
    n = clibcni_util_strdup_s(name);

    e = &(n[strlen(n)]);
    for (p = n + 1; p < e; p++) {
        if (*p != '/') {
            continue;
        }
        set_char_to_terminator(p);
        nret = mkdir(n, CLIBCNI_DEFAULT_SECURE_DIRECTORY_MODE);
        if (nret != 0 && (errno != EEXIST || !clibcni_util_dir_exists(n))) {
            SYSERROR("failed to create directory '%s'.", n);
            free(n);
            return -1;
        }
        *p = '/';
    }
    free(n);
    return 0;
}

/* util open */
int clibcni_util_open(const char *filename, unsigned int flags, mode_t mode)
{
    char rpath[PATH_MAX] = { 0x00 };

    if (cleanpath(filename, rpath, sizeof(rpath)) == NULL) {
        return -1;
    }
    if (mode) {
        return open(rpath, (int)(flags | O_CLOEXEC), (int)mode);
    } else {
        return open(rpath, (int)(flags | O_CLOEXEC));
    }
}

FILE *clibcni_util_fopen(const char *filename, const char *mode)
{
    int f_fd = -1;
    int tmperrno;
    FILE *fp = NULL;
    unsigned int fdmode = 0;

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

    f_fd = clibcni_util_open(filename, fdmode, 0660);
    if (f_fd < 0) {
        return fp;
    }

    fp = fdopen(f_fd, mode);
    tmperrno = errno;
    if (fp == NULL) {
        close(f_fd);
    }
    errno = tmperrno;

    return fp;
}

/* note: This function can only read small text file. */
char *clibcni_util_read_text_file(const char *path)
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

    filp = clibcni_util_fopen(path, "r");
    if (filp == NULL) {
        ERROR("open file %s failed", path);
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

    buf = clibcni_util_common_calloc_s((size_t)(len + 1));
    if (buf == NULL) {
        ERROR("out of memroy");
        goto err_out;
    }

    readlen = fread(buf, 1, (size_t)len, filp);
    if (((readlen < (size_t)len) && (!feof(filp))) || (readlen > (size_t)len)) {
        ERROR("Failed to read file %s, error: %s\n", path, strerror(errno));
        free(buf);
        buf = NULL;
        goto err_out;
    }

    buf[(size_t)len] = 0;

err_out:

    if (filp != NULL) {
        fclose(filp);
    }

    return buf;
}
