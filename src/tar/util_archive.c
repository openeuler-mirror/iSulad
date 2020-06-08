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
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "stdbool.h"
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <sys/stat.h>
#include <archive.h>
#include <archive_entry.h>

#include "util_archive.h"
#include "utils.h"
#include "path.h"
#include "isula_libutils/log.h"
#include "error.h"
#include "isula_libutils/json_common.h"

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
