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
 * Description: provide container sha256 functions
 *******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <unistd.h>
#include <stdalign.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <libwebsockets.h>
#include <openssl/sha.h>

#include "sha256.h"
#include "isula_libutils/log.h"
#include "utils.h"

#define BLKSIZE 32768

static bool stream_check_eof(void *stream, bool isgzip)
{
    if (isgzip) {
        if (gzeof(stream)) {
            return true;
        }
    } else {
        if (feof(stream)) {
            return true;
        }
    }
    return false;
}

static bool stream_check_error(void *stream, bool isgzip)
{
    const char *gzerr = NULL;
    if (isgzip) {
        int errnum;
        gzerr = gzerror(stream, &errnum);
    } else if (ferror(stream)) {
        return true;
    }
    if (gzerr != NULL && strcmp(gzerr, "") != 0) {
        ERROR("gzread error: %s", gzerr);
        return true;
    }
    return false;
}

int stream_read(void *stream, int fd, bool isgzip)
{
    size_t n = 0;
    char *buffer = NULL;

    buffer = util_common_calloc_s(BLKSIZE + 72);
    if (buffer == NULL) {
        ERROR("Malloc BLKSIZE memory error");
        return -1;
    }

    /* Read block.  Take care for partial reads. */
    while (1) {
        if (isgzip) {
            n = (size_t)gzread((gzFile)stream, buffer, BLKSIZE);
        } else {
            n = fread(buffer, 1, BLKSIZE, (FILE *)stream);
        }

        if (n == BLKSIZE) {
            if (write(fd, buffer, BLKSIZE) == -1) {
                ERROR("Write pipe failed: %s", strerror(errno));
                goto free_out;
            }
            n = 0;
            continue;
        }

        if (n == 0) {
            if (stream_check_error(stream, isgzip)) {
                goto free_out;
            }
            goto end_send;
        }

        if (stream_check_eof(stream, isgzip)) {
            goto end_send;
        }
    }

end_send:
    /* Process any remaining bytes. */
    if (n > 0) {
        if (write(fd, buffer, n) == -1) {
            ERROR("Write pipe_for_write failed: %s", strerror(errno));
            goto free_out;
        }
    }
    free(buffer);
    return 0;

free_out:
    free(buffer);
    return -1;
}

static int sha256sum_calculate_parent_handle(pid_t pid, int pipe_for_read[], int pipe_for_write[], bool isfile,
                                             bool isgzip, void *stream, char *buffer_out, size_t len)
{
    ssize_t size_pipe_read;

    close(pipe_for_read[1]);
    pipe_for_read[1] = -1;
    close(pipe_for_write[0]);
    pipe_for_write[0] = -1;

    if (isfile) {
        int ret = stream_read((gzFile)stream, pipe_for_write[1], isgzip);
        if (ret != 0) {
            close(pipe_for_read[0]);
            pipe_for_read[0] = -1;
            close(pipe_for_write[1]);
            pipe_for_write[1] = -1;
            ERROR("Read buffer error");
            return -1;
        }
    } else if (write(pipe_for_write[1], (char *)stream, len) == -1) {
        close(pipe_for_read[0]);
        pipe_for_read[0] = -1;
        close(pipe_for_write[1]);
        pipe_for_write[1] = -1;
        ERROR("Write pipe_for_write failed: %s", strerror(errno));
        return -1;
    }

    close(pipe_for_write[1]);
    pipe_for_write[1] = -1;
    if (wait_for_pid(pid)) {
        char buffer_errmsg[BUFSIZ] = { 0 };
        size_t size_read = (size_t)read(pipe_for_read[0], buffer_errmsg, BUFSIZ);
        if (size_read != 0) {
            ERROR("Sha256sum run error: %s", buffer_errmsg);
        }
        close(pipe_for_read[0]);
        pipe_for_read[0] = -1;
        return -1;
    }

    size_pipe_read = read(pipe_for_read[0], buffer_out, SHA256_SIZE);
    close(pipe_for_read[0]);
    pipe_for_read[0] = -1;
    if (size_pipe_read <= 0) {
        ERROR("Read sha256 buffer failed");
        return -1;
    }
    buffer_out[SHA256_SIZE] = '\0';
    return 0;
}

int sha256sum_calculate(void *stream, char *buffer_out, size_t len, bool isfile,
                        bool isgzip)
{
    int ret = 0;
    pid_t pid;
    int pipe_for_read[2] = { -1, -1 };
    int pipe_for_write[2] = { -1, -1 };

    if (!stream || !buffer_out) {
        ERROR("Param Error");
        ret = -1;
        goto out;
    }
    if (pipe2(pipe_for_read, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe");
        ret = -1;
        goto out;
    }

    if (pipe2(pipe_for_write, O_CLOEXEC) != 0) {
        ERROR("Failed to create pipe");
        ret = -1;
        goto out;
    }

    pid = fork();
    if (pid == (pid_t) - 1) {
        ERROR("Failed to fork()");
        ret = -1;
        close(pipe_for_read[0]);
        close(pipe_for_read[1]);
        close(pipe_for_write[0]);
        close(pipe_for_write[1]);
        goto out;
    }

    if (pid == (pid_t)0) {
        // child process, dup2 pipe_for_read[1] to stdout,
        // pipe_for_write[1] to stdin
        close(pipe_for_read[0]);
        close(pipe_for_write[1]);
        if (dup2(pipe_for_read[1], 1) < 0) {
            fprintf(stdout, "Dup fd error: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }
        if (dup2(pipe_for_write[0], 0)) {
            fprintf(stdout, "Dup fd error: %s", strerror(errno));
            exit(EXIT_FAILURE);
        }

        if (util_check_inherited(true, -1)) {
            fprintf(stdout, "Failed to close fds.");
            exit(EXIT_FAILURE);
        }
        execlp("sha256sum", "sha256sum", NULL);

        fprintf(stdout, "Failed to exec sha256sum program");
        exit(EXIT_FAILURE);
    }

    ret = sha256sum_calculate_parent_handle(pid, pipe_for_read, pipe_for_write,
                                            isfile, isgzip, stream, buffer_out, len);

out:
    return ret;
}

char *sha256_digest(void *stream, bool isgzip)
{
    int ret = 0;
    int cnt;
    char buffer_out[SHA256_SIZE + 1];
    char *digest = NULL;

    if (stream == NULL) {
        return NULL;
    }

    ret = sha256sum_calculate(stream, buffer_out, 0, true, isgzip);
    if (ret != 0) {
        return NULL;
    }

    digest = (char *)util_common_calloc_s(SHA256_SIZE + 1);
    if (digest == NULL) {
        return NULL;
    }
    digest[SHA256_SIZE] = 0;

    /* translate from binary to hex string */
    for (cnt = 0; cnt < SHA256_SIZE; ++cnt) {
        digest[cnt] = buffer_out[cnt];
    }
    return digest;
}

char *sha256_digest_str(const char *val)
{
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH] = { 0x00 };
    char output_buffer[(SHA256_DIGEST_LENGTH * 2) + 1] = { 0x00 };
    int i = 0;

    if (val == NULL) {
        return NULL;
    }

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, val, strlen(val));
    SHA256_Final(hash, &ctx);

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        int ret = snprintf(output_buffer + (i * 2), 3, "%02x", (unsigned int)hash[i]);
        if (ret >= 3 || ret < 0) {
            return NULL;
        }
    }
    output_buffer[SHA256_DIGEST_LENGTH * 2] = '\0';

    return util_strdup_s(output_buffer);
}

char *sha256_digest_file(const char *filename, bool isgzip)
{
    SHA256_CTX ctx;
    unsigned char hash[SHA256_DIGEST_LENGTH] = { 0x00 };
    char output_buffer[(SHA256_DIGEST_LENGTH * 2) + 1] = { 0x00 };
    int i = 0;
    char *buffer = NULL;
    int n = 0;
    int ret = 0;
    void *stream = NULL;

    if (filename == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    if (isgzip) {
        stream = (void*)gzopen(filename, "r");
    } else {
        stream = (void*)fopen(filename, "r");
    }
    if (stream == NULL) {
        ERROR("open file %s failed: %s", filename, strerror(errno));
        return NULL;
    }

    buffer = util_common_calloc_s(BLKSIZE);
    if (buffer == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    SHA256_Init(&ctx);

    while (true) {
        if (isgzip) {
            n = gzread((gzFile)stream, buffer, BLKSIZE);
        } else {
            n = fread(buffer, 1, BLKSIZE, (FILE *)stream);
        }
        if (n <= 0) {
            if (stream_check_error(stream, isgzip)) {
                ret = -1;
                goto out;
            }
            break;
        }

        if (n > 0) {
            SHA256_Update(&ctx, buffer, n);
        }

        if (stream_check_eof(stream, isgzip)) {
            break;
        }
    }

    SHA256_Final(hash, &ctx);

    for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        int sret = snprintf(output_buffer + (i * 2), 3, "%02x", (unsigned int)hash[i]);
        if (sret >= 3 || sret < 0) {
            ERROR("snprintf failed when calc sha256 from file %s, result is %s", filename, sret);
            return NULL;
        }
    }
    output_buffer[SHA256_DIGEST_LENGTH * 2] = '\0';

out:
    if (isgzip) {
        gzclose((gzFile)stream);
    } else {
        fclose((FILE*)stream);
    }

    free(buffer);
    buffer = NULL;

    if (ret == 0) {
        return util_strdup_s(output_buffer);
    } else {
        return NULL;
    }
}
