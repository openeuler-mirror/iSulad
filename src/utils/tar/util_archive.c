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
#include "map.h"

struct archive;
struct archive_entry;

#define ARCHIVE_READ_BUFFER_SIZE (10 * 1024)
#define TAR_DEFAULT_MODE 0600
#define TAR_DEFAULT_FLAG (O_WRONLY | O_CREAT | O_TRUNC)

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
    flags |= ARCHIVE_EXTRACT_OWNER;
    flags |= ARCHIVE_EXTRACT_PERM;
    flags |= ARCHIVE_EXTRACT_ACL;
    flags |= ARCHIVE_EXTRACT_FFLAGS;
    flags |= ARCHIVE_EXTRACT_SECURE_SYMLINKS;
    flags |= ARCHIVE_EXTRACT_SECURE_NODOTDOT;
    flags |= ARCHIVE_EXTRACT_XATTR;
    flags |= ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS;

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

bool valid_archive_format(const char *file)
{
    int ret = ARCHIVE_FAILED;
    struct archive *read_archive = NULL;
    struct archive_entry *entry = NULL;

    if (file == NULL) {
        ERROR("Invalid NULL file path when checking archive format");
        return false;
    }

    read_archive = archive_read_new();
    if (read_archive == NULL) {
        ERROR("archive read new failed");
        return false;
    }

    ret = archive_read_support_filter_all(read_archive);
    if (ret != ARCHIVE_OK) {
        ERROR("Failed to set archive read support filter all, result is %d, errmsg: %s", ret,
              archive_error_string(read_archive));
        goto out;
    }

    ret = archive_read_support_format_all(read_archive);
    if (ret != ARCHIVE_OK) {
        ERROR("Failed to set archive read support format all, result is %d, errmsg: %s", ret,
              archive_error_string(read_archive));
        goto out;
    }

    ret = archive_read_open_filename(read_archive, file, ARCHIVE_READ_BUFFER_SIZE);
    if (ret != ARCHIVE_OK) {
        ERROR("Failed to open archive %s: %s", file, archive_error_string(read_archive));
        goto out;
    }

    // format code upated when archive_read_next_header is called
    ret = archive_read_next_header(read_archive, &entry);
    if (ret == ARCHIVE_EOF) {
        ERROR("Invalid empty archive, it's not archive format");
        goto out;
    }
    if (ret != ARCHIVE_OK) {
        ERROR("Failed to read next header for file %s: %s", file, archive_error_string(read_archive));
        goto out;
    }

out:
    if (archive_read_free(read_archive) != ARCHIVE_OK) {
        ERROR("Failed to free archive %s: %s", file, archive_error_string(read_archive));
    }
    read_archive = NULL;

    return (ret == ARCHIVE_OK);
}

static int copy_data_between_archives(struct archive *ar, struct archive *aw)
{
    int ret = ARCHIVE_FAILED;
    const void *buff = NULL;
    size_t size;
    int64_t offset;

    for (;;) {
        ret = archive_read_data_block(ar, &buff, &size, &offset);
        if (ret == ARCHIVE_EOF) {
            return ARCHIVE_OK;
        }
        if (ret < ARCHIVE_OK) {
            ERROR("tar archive read result %d, error: %s", ret, archive_error_string(ar));
            fprintf(stderr, "tar archive read result %d, error: %s", ret, archive_error_string(ar));
            return ret;
        }
        ret = archive_write_data(aw, buff, size);
        if (ret < ARCHIVE_OK) {
            ERROR("tar archive write result %d, error: %s", ret, archive_error_string(aw));
            fprintf(stderr, "tar archive write result %d, error: %s", ret, archive_error_string(aw));
            return ret;
        }
    }
}

int update_entry_for_hardlink(map_t *map_link, struct archive_entry *entry)
{
    const char *path = archive_entry_pathname(entry);
    char *linkname = NULL;
    unsigned int nlink = archive_entry_nlink(entry);
    int ino = archive_entry_ino(entry);

    // hardlink is regular file, not type AE_IFLNK
    if (archive_entry_filetype(entry) != AE_IFREG) {
        return 0;
    }

    // no hardlink
    if (nlink <= 1) {
        return 0;
    }

    linkname = map_search(map_link, (void *)&ino);
    if (linkname == NULL) {
        linkname = (char *)path;
        if (!map_insert(map_link, (void *)&ino, linkname)) {
            ERROR("insert to map failed");
            fprintf(stderr, "insert to map failed");
            return -1;
        }
        return 0;
    }

    archive_entry_set_size(entry, 0);
    archive_entry_set_hardlink(entry, linkname);

    return 0;
}

static void link_kvfree(void *key, void *value)
{
    free(key);
    free(value);
    return;
}

int tar_handler(struct archive *r, struct archive *w)
{
    int ret = ARCHIVE_OK;
    struct archive_entry *entry = NULL;
    map_t *map_link = NULL;

    map_link = map_new(MAP_INT_STR, MAP_DEFAULT_CMP_FUNC, link_kvfree);
    if (map_link == NULL) {
        ERROR("out of memory");
        fprintf(stderr, "out of memory\n");
        return -1;
    }

    for (;;) {
        ret = archive_read_next_header(r, &entry);
        if (ret == ARCHIVE_EOF) {
            ret = ARCHIVE_OK;
            break;
        }

        if (ret != ARCHIVE_OK) {
            ERROR("read from disk failed: %s", archive_error_string(r));
            fprintf(stderr, "read from disk failed: %s\n", archive_error_string(r));
            break;
        }

        if (update_entry_for_hardlink(map_link, entry) != 0) {
            ret = ARCHIVE_FAILED;
            break;
        }

        ret = archive_write_header(w, entry);
        if (ret != ARCHIVE_OK) {
            ERROR("Fail to write tar header: %s", archive_error_string(w));
            fprintf(stderr, "Fail to write tar header: %s\nlink:%s target:%s", archive_error_string(w),
                    archive_entry_pathname(entry), archive_entry_hardlink(entry));
            break;
        }

        if (archive_entry_size(entry) > 0) {
            ret = copy_data_between_archives(r, w);
            if (ret != ARCHIVE_OK) {
                ERROR("Failed to do copy data: %s", archive_error_string(w));
                fprintf(stderr, "Failed to do copy data: %s\n", archive_error_string(w));
                break;
            }
        }

        ret = archive_write_finish_entry(w);
        if (ret != ARCHIVE_OK) {
            ERROR("Failed to freeing archive entry: %s\n", archive_error_string(w));
            fprintf(stderr, "Failed to freeing archive entry: %s\n", archive_error_string(w));
            break;
        }

        if (archive_entry_filetype(entry) == AE_IFDIR) {
            ret = archive_read_disk_descend(r);
            if (ret != ARCHIVE_OK) {
                ERROR("read disk descend failed: %s\n", archive_error_string(w));
                fprintf(stderr, "read disk descend failed: %s\n", archive_error_string(w));
                break;
            }
        }
    }

    map_free(map_link);

    return ret;
}

static int tar_all(int fd)
{
    struct archive *r = NULL;
    struct archive *w = NULL;
    int ret = ARCHIVE_OK;

    r = archive_read_disk_new();
    archive_read_disk_set_standard_lookup(r);
    archive_read_disk_set_symlink_physical(r);
    archive_read_disk_set_behavior(r, ARCHIVE_READDISK_NO_TRAVERSE_MOUNTS);
    ret = archive_read_disk_open(r, ".");
    if (ret != ARCHIVE_OK) {
        ERROR("open archive read failed: %s", archive_error_string(r));
        fprintf(stderr, "open archive read failed: %s\n", archive_error_string(r));
        goto out;
    }

    w = archive_write_new();
    archive_write_set_format_pax(w);
    archive_write_set_options(w, "xattrheader=SCHILY");
    ret = archive_write_open_fd(w, fd);
    if (ret != ARCHIVE_OK) {
        ERROR("open archive write failed: %s", archive_error_string(w));
        fprintf(stderr, "open archive write failed: %s\n", archive_error_string(w));
        goto out;
    }

    ret = tar_handler(r, w);

out:
    archive_free(r);
    archive_free(w);

    return (ret == ARCHIVE_OK) ? 0 : -1;
}

int archive_chroot_tar(char *path, char *file, char **errmsg)
{
    int ret = 0;
    pid_t pid;
    int pipe_for_read[2] = { -1, -1 };
    int keepfds[] = { -1, -1 };
    char errbuf[BUFSIZ] = { 0 };
    int fd = 0;

    if (pipe2(pipe_for_read, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe");
        ret = -1;
        goto cleanup;
    }

    pid = fork();
    if (pid == (pid_t) -1) {
        ERROR("Failed to fork()");
        ret = -1;
        close(pipe_for_read[0]);
        close(pipe_for_read[1]);
        goto cleanup;
    }

    if (pid == (pid_t)0) {
        keepfds[0] = isula_libutils_get_log_fd();
        keepfds[1] = pipe_for_read[1];
        ret = util_check_inherited_exclude_fds(true, keepfds, 2);
        if (ret != 0) {
            ERROR("Failed to close fds.");
            ret = -1;
            goto child_out;
        }

        // child process, dup2 pipe_for_read[1] to stderr,
        if (dup2(pipe_for_read[1], 2) < 0) {
            ERROR("Dup fd error: %s", strerror(errno));
            ret = -1;
            goto child_out;
        }

        fd = open(file, TAR_DEFAULT_FLAG, TAR_DEFAULT_MODE);
        if (fd < 0) {
            ERROR("Failed to open file %s for export: %s", file, strerror(errno));
            fprintf(stderr, "Failed to open file %s for export: %s\n", file, strerror(errno));
            ret = -1;
            goto child_out;
        }

        if (chroot(path) != 0) {
            ERROR("Failed to chroot to %s", path);
            fprintf(stderr, "Failed to chroot to %s\n", path);
            ret = -1;
            goto child_out;
        }

        if (chdir("/") != 0) {
            ERROR("Failed to chroot to /");
            fprintf(stderr, "Failed to chroot to /\n");
            ret = -1;
            goto child_out;
        }

        ret = tar_all(fd);

child_out:

        if (ret != 0) {
            exit(EXIT_FAILURE);
        } else {
            exit(EXIT_SUCCESS);
        }
    }

    ret = wait_for_pid(pid);
    if (ret != 0) {
        ERROR("tar failed");
        fcntl(pipe_for_read[0], F_SETFL, O_NONBLOCK);
        if (read(pipe_for_read[0], errbuf, BUFSIZ) < 0) {
            ERROR("read error message from child failed");
        }
        close(pipe_for_read[0]);
        pipe_for_read[0] = -1;
    }

    close(pipe_for_read[1]);
    pipe_for_read[1] = -1;

cleanup:
    if (errmsg != NULL && strlen(errbuf) != 0) {
        *errmsg = util_strdup_s(errbuf);
    }

    return ret;
}
