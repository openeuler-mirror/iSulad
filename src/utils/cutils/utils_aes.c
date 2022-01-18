/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wangfengtu
 * Create: 2020-03-26
 * Description: provide base64 functions
 *******************************************************************************/

#define _GNU_SOURCE
#include "utils_aes.h"
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <openssl/ossl_typ.h>

#include "isula_libutils/log.h"
#include "utils.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "utils_file.h"

#define AES_256_CFB_IV_LEN 16

int util_aes_key(char *key_file, bool create, unsigned char *aeskey)
{
    char *key_dir = NULL;
    int fd = 0;
    int ret = 0;

    if (!util_file_exists(key_file)) {
        if (!create) {
            ERROR("init aes failed, file %s not exist", key_file);
            return -1;
        }

        ret = util_generate_random_str((char *)aeskey, AES_256_CFB_KEY_LEN);
        if (ret != 0) {
            ERROR("generate random string for aeskey failed");
            goto out;
        }

        key_dir = util_path_dir(key_file);
        if (key_dir == NULL) {
            ERROR("get dir of %s for aeskey failed", key_file);
            ret = -1;
            goto out;
        }

        ret = util_mkdir_p(key_dir, 0700);
        if (ret != 0) {
            ERROR("mkdir of %s for aeskey failed", key_dir);
            goto out;
        }

        ret = util_write_file(key_file, (char *)aeskey, AES_256_CFB_KEY_LEN, 0600);
        if (ret != 0) {
            ERROR("write aeskey to file failed");
            goto out;
        }
    } else {
        fd = open(key_file, O_RDONLY);
        if (fd < 0) {
            ERROR("open key file %s failed: %s", key_file, strerror(errno));
            ret = -1;
            goto out;
        }

        if (read(fd, aeskey, AES_256_CFB_KEY_LEN) != AES_256_CFB_KEY_LEN) {
            ERROR("read key file %s failed: %s", key_file, strerror(errno));
            ret = -1;
            goto out;
        }
    }

out:
    free(key_dir);
    key_dir = NULL;
    if (fd != 0) {
        close(fd);
    }

    return ret;
}

size_t util_aes_decode_buf_len(size_t len)
{
    if (len % AES_BLOCK_SIZE == 0) {
        return len;
    }

    return (len / AES_BLOCK_SIZE * AES_BLOCK_SIZE) + AES_BLOCK_SIZE;
}

size_t util_aes_encode_buf_len(size_t len)
{
    return AES_256_CFB_IV_LEN + util_aes_decode_buf_len(len);
}

int util_aes_encode(unsigned char *aeskey, unsigned char *bytes, size_t len, unsigned char **out)
{
    int ret = 0;
    int evp_ret = 0;
    int tmp_out_len = 0;
    int size = 0;
    int expected_size = len;
    unsigned char *iv = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cfb();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL || cipher == NULL) {
        ERROR("EVP init failed");
        return -1;
    }

    *out = util_common_calloc_s(util_aes_encode_buf_len(len) + 1);
    if (*out == NULL) {
        ERROR("out of memory");
        return -1;
    }
    iv = *out;

    ret = util_generate_random_str((char *)iv, AES_256_CFB_IV_LEN);
    if (ret != 0) {
        ERROR("generate random string for iv failed");
        goto out;
    }

    evp_ret = EVP_EncryptInit(ctx, cipher, aeskey, iv);
    if (evp_ret != 1) {
        ERROR("init evp decrypt failed, result %d: %s", evp_ret, strerror(errno));
        ret = -1;
        goto out;
    }

    evp_ret = EVP_EncryptUpdate(ctx, (*out) + AES_256_CFB_IV_LEN, &tmp_out_len, bytes, len);
    if (evp_ret != 1) {
        ERROR("evp encrypt update failed, result %d: %s", evp_ret, strerror(errno));
        ret = -1;
        goto out;
    }
    size = tmp_out_len;

    evp_ret = EVP_EncryptFinal(ctx, (*out) + AES_256_CFB_IV_LEN + tmp_out_len, &tmp_out_len);
    if (evp_ret != 1) {
        ERROR("evp encrypt final failed, result %d: %s", evp_ret, strerror(errno));
        ret = -1;
        goto out;
    }
    size += tmp_out_len;

    if (size != expected_size) {
        ERROR("aes encode failed, input length %d, output length %d", size, expected_size);
        ret = -1;
        goto out;
    }

    *(*out + AES_256_CFB_IV_LEN + expected_size) = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if (ret != 0) {
        free(*out);
        *out = NULL;
    }

    return ret;
}

int util_aes_decode(unsigned char *aeskey, unsigned char *bytes, size_t len, unsigned char **out)
{
    int ret = 0;
    int evp_ret = 0;
    int tmp_out_len = 0;
    int size = 0;
    int expected_size = 0;
    unsigned char *iv = NULL;
    const EVP_CIPHER *cipher = EVP_aes_256_cfb();
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (ctx == NULL || cipher == NULL) {
        ERROR("EVP init failed");
        return -1;
    }

    if (len <= AES_256_CFB_IV_LEN) {
        ERROR("Invalid aes length, it must be larger than %d", AES_256_CFB_IV_LEN);
        return -1;
    }

    *out = util_common_calloc_s(util_aes_decode_buf_len(len) + 1);
    if (*out == NULL) {
        ERROR("out of memory");
        return -1;
    }

    iv = bytes;
    evp_ret = EVP_DecryptInit(ctx, cipher, aeskey, iv);
    if (evp_ret != 1) {
        ERROR("init evp decrypt failed, result %d: %s", evp_ret, strerror(errno));
        ret = -1;
        goto out;
    }

    expected_size = len - AES_256_CFB_IV_LEN;
    evp_ret = EVP_DecryptUpdate(ctx, *out, &tmp_out_len, bytes + AES_256_CFB_IV_LEN, expected_size);
    if (evp_ret != 1) {
        ERROR("evp decrypt update failed, result %d: %s", evp_ret, strerror(errno));
        ret = -1;
        goto out;
    }
    size = tmp_out_len;

    evp_ret = EVP_DecryptFinal(ctx, (*out) + tmp_out_len, &tmp_out_len);
    if (evp_ret != 1) {
        ERROR("evp decrypt final failed, result %d: %s", evp_ret, strerror(errno));
        ret = -1;
        goto out;
    }
    size += tmp_out_len;

    if (size != expected_size) {
        ERROR("aes decode failed, input length %d, output length %d", size, expected_size);
        ret = -1;
        goto out;
    }

    *(*out + expected_size) = 0;

out:
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;
    if (ret != 0) {
        free(*out);
        *out = NULL;
    }

    return ret;
}
