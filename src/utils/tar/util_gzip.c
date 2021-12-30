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
 * Author: wangfengtu
 * Create: 2020-07-13
 * Description: provide tar functions
 ********************************************************************************/
#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "util_gzip.h"
#include <zlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "utils.h"
#include "isula_libutils/log.h"
#include "utils_file.h"

#define BLKSIZE 32768

// Compress
int util_gzip_z(const char *srcfile, const char *dstfile, const mode_t mode)
{
    int ret = 0;
    int srcfd = 0;
    gzFile stream = NULL;
    ssize_t size = 0;
    size_t n = 0;
    void *buffer = 0;
    const char *gzerr = NULL;
    int errnum = 0;

    srcfd = util_open(srcfile, O_RDONLY, SECURE_CONFIG_FILE_MODE);
    if (srcfd < 0) {
        ERROR("Open src file: %s, failed: %s", srcfile, strerror(errno));
        return -1;
    }

    stream = gzopen(dstfile, "w");
    if (stream == NULL) {
        ERROR("gzopen %s error: %s", dstfile, strerror(errno));
        close(srcfd);
        return -1;
    }

    buffer = util_common_calloc_s(BLKSIZE);
    if (buffer == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    while (true) {
        size = util_read_nointr(srcfd, buffer, BLKSIZE);
        if (size < 0) {
            ERROR("read file %s failed: %s", srcfile, strerror(errno));
            ret = -1;
            break;
        } else if (size == 0) {
            break;
        }

        n = gzwrite(stream, buffer, size);
        if (n <= 0 || n != (size_t)size) {
            gzerr = gzerror(stream, &errnum);
            if (gzerr != NULL && strcmp(gzerr, "") != 0) {
                ERROR("gzread error: %s", gzerr);
            }
            ret = -1;
            break;
        }
    }
    if (chmod(dstfile, mode) != 0) {
        ERROR("Change mode of tar-split file");
        ret = -1;
    }

out:
    gzclose(stream);
    close(srcfd);
    free(buffer);
    if (ret != 0) {
        if (util_path_remove(dstfile) != 0) {
            ERROR("Remove file %s failed: %s", dstfile, strerror(errno));
        }
    }

    return ret;
}

// Decompress
int util_gzip_d(const char *srcfile, const FILE *dstfp)
{
    gzFile stream = NULL;
    const char *gzerr = NULL;
    int errnum = 0;
    int ret = 0;
    size_t size = 0;
    void *buffer = NULL;
    size_t n = 0;

    stream = gzopen(srcfile, "r");
    if (stream == NULL) {
        ERROR("gzopen %s failed: %s", srcfile, strerror(errno));
        return -1;
    }

    buffer = util_common_calloc_s(BLKSIZE);
    if (buffer == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    while (true) {
        n = gzread(stream, buffer, BLKSIZE);
        if (n <= 0) {
            gzerr = gzerror(stream, &errnum);
            if (gzerr != NULL && strcmp(gzerr, "") != 0) {
                ERROR("gzread error: %s", gzerr);
                ret = -1;
            }
            break;
        }

        if (n > 0) {
            size = fwrite(buffer, 1, n, (FILE *)dstfp);
            if (size != n) {
                ret = -1;
                ERROR("Write file failed: %s", strerror(errno));
                break;
            }
        }

        if (gzeof(stream)) {
            break;
        }
    }

out:
    gzclose(stream);
    free(buffer);
    if (ret == 0) {
        (void)fflush((FILE *)dstfp);
    }

    return ret;
}

/*
 * compress file.
 * param filename:      archive file to compres.
 * return:              zero if compress success, non-zero if not.
 */
int gzip(const char *filename, size_t len)
{
    int pipefd[2] = { -1, -1 };
    int status = 0;
    pid_t pid = 0;

    if (filename == NULL) {
        return -1;
    }
    if (len == 0) {
        return -1;
    }

    if (pipe2(pipefd, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe\n");
        return -1;
    }

    pid = fork();
    if (pid == -1) {
        ERROR("Failed to fork()\n");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        // child process, dup2 pipefd[1] to stderr
        close(pipefd[0]);
        dup2(pipefd[1], 2);
        dup2(pipefd[1], 2);

        if (!util_valid_cmd_arg(filename)) {
            fprintf(stderr, "Invalid filename: %s\n", filename);
            exit(EXIT_FAILURE);
        }

        execlp("gzip", "gzip", "-f", filename, NULL);

        fprintf(stderr, "Failed to exec gzip");
        exit(EXIT_FAILURE);
    }

    ssize_t size_read = 0;
    char buffer[BUFSIZ] = { 0 };

    close(pipefd[1]);

    if (waitpid(pid, &status, 0) != pid) {
        close(pipefd[0]);
        return -1;
    }

    size_read = read(pipefd[0], buffer, BUFSIZ);
    close(pipefd[0]);

    if (size_read) {
        ERROR("Received error:\n%s", buffer);
    }
    return status;
}
