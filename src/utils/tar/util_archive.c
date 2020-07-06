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
 * Description: provide tar functions
 ********************************************************************************/
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/stat.h>
#include <archive.h>
#include <archive_entry.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>

#include "stdbool.h"
#include "util_archive.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "io_wrapper.h"
#include "utils_file.h"

struct archive;
struct archive_entry;

#define ARCHIVE_READ_BUFFER_SIZE (10 * 1024)

#define WHITEOUT_PREFIX ".wh."
#define WHITEOUT_META_PREFIX ".wh..wh."
#define WHITEOUT_OPAQUEDIR ".wh..wh..opq"

struct archive_content_data {
    const struct io_read_wrapper *content;
    char buff[ARCHIVE_READ_BUFFER_SIZE];
};

ssize_t read_content(struct archive *a, void *client_data, const void **buff)
{
    struct archive_content_data *mydata = client_data;

    memset(mydata->buff, 0, sizeof(mydata->buff));

    *buff = mydata->buff;

    return mydata->content->read(mydata->content->context, mydata->buff, sizeof(mydata->buff));
}

static bool whiteout_convert_read(struct archive_entry *entry, const char *dst_path)
{
    bool do_write = true;
    char *base = NULL;
    char *dir = NULL;
    char *originalpath = NULL;

    base = util_path_base(dst_path);
    if (base == NULL) {
        ERROR("Failed to get base of %s", dst_path);
        goto out;
    }

    dir = util_path_dir(dst_path);
    if (dir == NULL) {
        ERROR("Failed to get dir of %s", dst_path);
        goto out;
    }

    if (strcmp(base, WHITEOUT_OPAQUEDIR) == 0) {
        if (setxattr(dir, "trusted.overlay.opaque", "y", 1, 0) != 0) {
            SYSERROR("Failed to set attr for dir %s", dir);
        }
        do_write = false;
        goto out;
    }

    if (strncmp(base, WHITEOUT_PREFIX, strlen(WHITEOUT_PREFIX)) == 0) {
        char *origin_base = &base[strlen(WHITEOUT_PREFIX)];
        originalpath = util_path_join(dir, origin_base);
        if (originalpath == NULL) {
            ERROR("Failed to get original path of %s", dst_path);
            goto out;
        }

        uid_t uid = archive_entry_uid(entry);
        gid_t gid = archive_entry_gid(entry);

        ERROR("mknod %s", originalpath);

        if (mknod(originalpath, S_IFCHR, 0) != 0) {
            SYSERROR("Failed to mknod for dir %s", originalpath);
        }

        if (chown(originalpath, uid, gid) != 0) {
            SYSERROR("Failed to chown for dir %s", originalpath);
        }

        do_write = false;
        goto out;
    }

out:
    free(base);
    free(dir);
    free(originalpath);
    return do_write;
}

static int copy_data(struct archive *ar, struct archive *aw)
{
    int r;
    const void *buff = NULL;
    size_t size;
    int64_t offset;

    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF) {
            return ARCHIVE_OK;
        }
        if (r < ARCHIVE_OK) {
            return r;
        }
        r = archive_write_data_block(aw, buff, size, offset);
        if (r < ARCHIVE_OK) {
            ERROR("tar extraction error: %s", archive_error_string(aw));
            return r;
        }
    }
}

int archive_unpack_handler(const struct io_read_wrapper *content, const char *dstdir,
                           const struct archive_options *options)
{
    int ret = 0;
    struct archive *a = NULL;
    struct archive *ext = NULL;
    struct archive_content_data *mydata = NULL;
    struct archive_entry *entry = NULL;
    char *dst_path = NULL;
    int flags;

    mydata = util_common_calloc_s(sizeof(struct archive_content_data));
    if (mydata == NULL) {
        ERROR("Memory out");
        ret = -1;
        goto out;
    }
    mydata->content = content;

    flags = ARCHIVE_EXTRACT_TIME;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;
    flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;
    flags |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;

    a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    ret = archive_read_open(a, mydata, NULL, read_content, NULL);
    if (ret != 0) {
        SYSERROR("Failed to open archive");
        ret = -1;
        goto out;
    }

    for (;;) {
        free(dst_path);
        dst_path = NULL;

        ret = archive_read_next_header(a, &entry);

        if (ret == ARCHIVE_EOF) {
            break;
        }

        if (ret != ARCHIVE_OK) {
            ERROR("Warning reading tar header: %s", archive_error_string(a));
            ret = -1;
            goto out;
        }

        const char *pathname = archive_entry_pathname(entry);
        if (pathname == NULL) {
            ERROR("Failed to get archive entry path name");
            ret = -1;
            goto out;
        }

        dst_path = util_path_join(dstdir, pathname);
        if (dst_path == NULL) {
            ERROR("Failed to get archive entry dst path %s/%s", dstdir, pathname);
            ret = -1;
            goto out;
        }

        if (options->whiteout_format == OVERLAY_WHITEOUT_FORMATE && !whiteout_convert_read(entry, dst_path)) {
            continue;
        }

        ret = archive_write_header(ext, entry);
        if (ret != ARCHIVE_OK) {
            ERROR("Fail to handle tar header: %s", archive_error_string(ext));
        } else if (archive_entry_size(entry) > 0) {
            ret = copy_data(a, ext);
            if (ret != ARCHIVE_OK) {
                ERROR("Failed to do copy tar data: %s", archive_error_string(ext));
            }
        }
        ret = archive_write_finish_entry(ext);
        if (ret != ARCHIVE_OK) {
            ERROR("Failed to freeing archive entry: %s\n", archive_error_string(ext));
        }
    }

    ret = 0;

out:
    free(dst_path);
    archive_read_close(a);
    archive_read_free(a);
    archive_write_close(ext);
    archive_write_free(ext);
    free(mydata);
    return ret;
}

int archive_unpack(const struct io_read_wrapper *content, const char *dstdir, const struct archive_options *options)
{
    int ret = 0;
    pid_t pid = -1;
    int keepfds[] = { -1, -1 };

    pid = fork();
    if (pid == (pid_t) -1) {
        ERROR("Failed to fork: %s", strerror(errno));
        goto cleanup;
    }

    if (pid == (pid_t)0) {
        keepfds[0] = isula_libutils_get_log_fd();
        keepfds[1] = *(int *)(content->context);
        ret = util_check_inherited_exclude_fds(true, keepfds, 2);
        if (ret != 0) {
            ERROR("Failed to close fds.");
            ret = -1;
            goto child_out;
        }

        if (chroot(dstdir) != 0) {
            SYSERROR("Failed to chroot to %s", dstdir);
            ret = -1;
            goto child_out;
        }

        if (chdir("/") != 0) {
            SYSERROR("Failed to chroot to /");
            ret = -1;
            goto child_out;
        }

        ret = archive_unpack_handler(content, "/", options);

child_out:
        if (ret != 0) {
            exit(EXIT_FAILURE);
        } else {
            exit(EXIT_SUCCESS);
        }
    }

    ret = wait_for_pid(pid);
    if (ret != 0) {
        ERROR("Wait archive_untar_handler failed");
    }

cleanup:
    return ret;
}

static void try_set_errbuf_and_log(char *errbuf, const char *format, ...)
{
    int ret = 0;

    if (errbuf == NULL || strlen(errbuf) > 0) {
        return;
    }

    va_list argp;
    va_start(argp, format);

    ret = vsnprintf(errbuf, BUFSIZ, format, argp);
    va_end(argp);
    if (ret < 0 || ret >= BUFSIZ) {
        return;
    }

    ERROR("%s", errbuf);

    return;
}

static int copy_data_between_archives(struct archive *ar, struct archive *aw, char *errbuf)
{
    int r = ARCHIVE_FAILED;
    const void *buff = NULL;
    size_t size;
    int64_t offset;

    for (;;) {
        r = archive_read_data_block(ar, &buff, &size, &offset);
        if (r == ARCHIVE_EOF) {
            return ARCHIVE_OK;
        }
        if (r < ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "tar archive read result %d, error: %s",
                                   r, archive_error_string(ar));
            return r;
        }
        r = archive_write_data(aw, buff, size);
        if (r < ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "tar archive write result %d, error: %s",
                                   r, archive_error_string(aw));
            return r;
        }
    }
}

static int archive_uncompress_handler(struct archive* src, struct archive* dest, char *errbuf)
{
    int ret = 0;
    struct archive_entry *entry = NULL;

    for (;;) {
        ret = archive_read_next_header(src, &entry);
        if (ret == ARCHIVE_EOF) {
            break;
        }

        if (ret != ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "Warning reading tar header: %s", archive_error_string(src));
            ret = -1;
            goto out;
        }

        ret = archive_write_header(dest, entry);
        if (ret != ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "Fail to handle tar header: %s", archive_error_string(dest));
            ret = -1;
            goto out;
        } else if (archive_entry_size(entry) > 0) {
            ret = copy_data_between_archives(src, dest, errbuf);
            if (ret != ARCHIVE_OK) {
                try_set_errbuf_and_log(errbuf, "Failed to do copy tar data: %s", archive_error_string(dest));
                ret = -1;
                goto out;
            }
        }
        ret = archive_write_finish_entry(dest);
        if (ret != ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "Failed to freeing archive entry: %s\n", archive_error_string(dest));
            ret = -1;
            goto out;
        }
    }

    ret = 0;

out:

    return ret;
}

static struct archive * create_read_archive(const char *file, char *errbuf)
{
    int ret = 0;
    struct archive *read_archive = NULL;

    read_archive = archive_read_new();
    if (read_archive == NULL) {
        try_set_errbuf_and_log(errbuf, "Failed to malloc archive read object: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    ret = archive_read_support_filter_all(read_archive);
    if (ret != ARCHIVE_OK) {
        try_set_errbuf_and_log(errbuf, "Failed to set archive read support filter all, result is %d, errmsg: %s",
                               ret, archive_error_string(read_archive));
        ret = -1;
        goto out;
    }

    ret = archive_read_support_format_all(read_archive);
    if (ret != ARCHIVE_OK) {
        try_set_errbuf_and_log(errbuf, "Failed to set archive read support format all, result is %d, errmsg: %s",
                               ret, archive_error_string(read_archive));
        ret = -1;
        goto out;
    }

    ret = archive_read_open_filename(read_archive, file, ARCHIVE_READ_BUFFER_SIZE);
    if (ret != ARCHIVE_OK) {
        try_set_errbuf_and_log(errbuf, "Failed to open archive %s: %s", file, archive_error_string(read_archive));
        ret = -1;
        goto out;
    }

out:
    if (ret != ARCHIVE_OK && read_archive != NULL) {
        if (archive_read_free(read_archive) != ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "Failed to free archive %s: %s", file, archive_error_string(read_archive));
        }
        read_archive = NULL;
    }

    return read_archive;
}

static struct archive * create_write_archive(const char *file, int format_code, char *errbuf)
{
    int ret = 0;
    struct archive *write_archive = NULL;

    write_archive = archive_write_new();
    if (write_archive == NULL) {
        try_set_errbuf_and_log(errbuf, "Failed to malloc archive write object: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    ret = archive_write_set_format(write_archive, format_code);
    if (ret != ARCHIVE_OK) {
        try_set_errbuf_and_log(errbuf, "Failed to set format %d, result is %d, errmsg: %s",
                               format_code, ret, archive_error_string(write_archive));
        ret = -1;
        goto out;
    }

    ret = archive_write_open_filename(write_archive, file);
    if (ret != ARCHIVE_OK) {
        try_set_errbuf_and_log(errbuf, "Failed to open archive %s: %s",
                               file, archive_error_string(write_archive));
        ret = -1;
        goto out;
    }

out:
    if (ret != ARCHIVE_OK && write_archive != NULL) {
        if (archive_write_free(write_archive) != ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "Failed to free archive %s: %s",
                                   file, archive_error_string(write_archive));
        }
        write_archive = NULL;
    }

    return write_archive;
}

void destroy_all_archive(struct archive *read_archive, struct archive *write_archive, char *errbuf)
{
    if (read_archive != NULL) {
        if (archive_read_free(read_archive) != ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "Failed to free read archive: %s", archive_error_string(read_archive));
        }
    }

    if (write_archive != NULL) {
        if (archive_write_free(write_archive) != ARCHIVE_OK) {
            try_set_errbuf_and_log(errbuf, "Failed to free write archive: %s", archive_error_string(write_archive));
        }
    }

    return;
}

static int try_read_format_code(const char *file)
{
    int ret = 0;
    char errbuf[BUFSIZ] = {0};
    int format_code = ARCHIVE_FORMAT_TAR_GNUTAR;
    struct archive_entry *entry = NULL;
    struct archive *ar = NULL;

    ar = create_read_archive(file, errbuf);
    if (ar == NULL) {
        return ARCHIVE_FORMAT_TAR_GNUTAR;
    }

    // format code upated when archive_read_next_header is called
    ret = archive_read_next_header(ar, &entry);
    if (ret == ARCHIVE_OK) {
        ret = archive_format(ar);
        if (ret != 0) { // if not updated, result format code is default to be 0
            format_code = ret;
        }
    }

    archive_read_free(ar);

    return format_code;
}

int archive_uncompress(const char *src, const char *dest, char **errmsg)
{
    char errbuf[BUFSIZ] = {0};
    struct archive *src_archive = NULL;
    struct archive *dest_archive = NULL;
    int ret = 0;

    src_archive = create_read_archive(src, errbuf);
    if (src_archive == NULL) {
        try_set_errbuf_and_log(errbuf, "Failed to create archive read object");
        ret = -1;
        goto out;
    }

    dest_archive = create_write_archive(dest, try_read_format_code(src), errbuf);
    if (dest_archive == NULL) {
        try_set_errbuf_and_log(errbuf, "Failed to create archive write object");
        ret = -1;
        goto out;
    }

    ret = archive_uncompress_handler(src_archive, dest_archive, errbuf);
    if (ret != 0) {
        try_set_errbuf_and_log(errbuf, "Failed to uncompress %s to %s", src, dest);
        goto out;
    }

out:
    destroy_all_archive(src_archive, dest_archive, errbuf);
    src_archive = NULL;
    dest_archive = NULL;
    if (errmsg != NULL && strlen(errbuf) != 0) {
        *errmsg = util_strdup_s(errbuf);
    }

    return ret;
}
