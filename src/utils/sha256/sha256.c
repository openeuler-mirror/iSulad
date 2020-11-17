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

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "sha256.h"
#include <fcntl.h> /* Obtain O_* constant definitions */
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/sha.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_file.h"
#include "utils_string.h"

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
        stream = (void *)gzopen(filename, "r");
    } else {
        stream = (void *)fopen(filename, "r");
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
            ERROR("snprintf failed when calc sha256 from file %s, result is %d", filename, sret);
            return NULL;
        }
    }
    output_buffer[SHA256_DIGEST_LENGTH * 2] = '\0';

out:
    if (isgzip) {
        gzclose((gzFile)stream);
    } else {
        fclose((FILE *)stream);
    }

    free(buffer);
    buffer = NULL;

    if (ret == 0) {
        return util_strdup_s(output_buffer);
    } else {
        return NULL;
    }
}

static char *cal_file_digest(const char *filename)
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

static char *cal_gzip_digest(const char *filename)
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

char *sha256_full_gzip_digest(const char *filename)
{
    char *digest = NULL;
    char *full_digest = NULL;

    if (filename == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    digest = cal_gzip_digest(filename);
    full_digest = util_full_digest(digest);
    free(digest);

    return full_digest;
}

char *sha256_full_file_digest(const char *filename)
{
    char *digest = NULL;
    char *full_digest = NULL;

    if (filename == NULL) {
        ERROR("invalid NULL param");
        return NULL;
    }

    digest = cal_file_digest(filename);
    full_digest = util_full_digest(digest);
    free(digest);

    return full_digest;
}

bool sha256_valid_digest_file(const char *path, const char *digest)
{
    char *file_digest = NULL;

    if (path == NULL || digest == NULL) {
        ERROR("invalid NULL param");
        return false;
    }

    file_digest = sha256_full_file_digest(path);
    if (file_digest == NULL) {
        ERROR("calc digest of file %s failed", path);
        return false;
    }

    if (strcmp(file_digest, digest)) {
        ERROR("file %s digest %s not match %s", path, file_digest, digest);
        free(file_digest);
        return false;
    }

    free(file_digest);

    return true;
}

char *sha256_full_digest_str(char *str)
{
    char *digest = NULL;
    char *full_digest = NULL;

    digest = sha256_digest_str(str);
    if (digest == NULL) {
        ERROR("Failed to calculate chain id");
        return NULL;
    }

    full_digest = util_full_digest(digest);
    free(digest);

    return full_digest;
}

char *util_without_sha256_prefix(char *digest)
{
    if (digest == NULL || !util_has_prefix(digest, SHA256_PREFIX)) {
        ERROR("Invalid digest when strip sha256 prefix");
        return NULL;
    }

    return digest + strlen(SHA256_PREFIX);
}
