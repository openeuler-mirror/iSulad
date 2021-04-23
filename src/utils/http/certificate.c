/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: lifeng
 * Create: 2019-06-07
 * Description: provide certificate function
 ******************************************************************************/
#include "certificate.h"

#include <openssl/x509.h>
#include <openssl/pem.h>
#include <string.h>
#include <openssl/obj_mac.h>
#include <openssl/ossl_typ.h>
#include <stdio.h>

#include "isula_libutils/log.h"
#include "utils_file.h"

#if (OPENSSL_VERSION_NUMBER >= 0x10100000L)
#define HAVE_OPAQUE_STRUCTS 1
#endif

static const char * const g_weak_algos[] = {
    "sha1WithRSAEncryption",
    "md5WithRSAEncryption",
    "md2WithRSAEncryption",
    "ecdsaWithSHA1",
    "dsaWithSHA1"
};

static void check_algo(X509 *cert)
{
    size_t i = 0;
    size_t len = sizeof(g_weak_algos) / sizeof(char *);
#if HAVE_OPAQUE_STRUCTS
    const char *sig_algo = OBJ_nid2ln(X509_get_signature_nid(cert));
#else
    if (cert->sig_alg == NULL) {
        ERROR("signature algorithm is null");
        return;
    }
    const char *sig_algo = OBJ_nid2ln(OBJ_obj2nid(cert->sig_alg->algorithm));
#endif
    if (sig_algo == NULL) {
        ERROR("sig algo is NULL");
        return;
    }

    for (i = 0; i < len; i++) {
        if (strcmp(g_weak_algos[i], sig_algo) == 0) {
            WARN("Weak signature algorithm is used: %s", sig_algo);
            return;
        }
    }
}

static void check_pub_key(X509 *cert)
{
    EVP_PKEY *pkey = X509_get_pubkey(cert);

    if (pkey == NULL) {
        ERROR("Failed to get public key");
        return;
    }

#if HAVE_OPAQUE_STRUCTS
    int pkey_type = EVP_PKEY_base_id(pkey);
#else
    int pkey_type = EVP_PKEY_type(pkey->type);
#endif

    switch (pkey_type) {
        case EVP_PKEY_RSA:
            if (EVP_PKEY_bits(pkey) < RSA_PKEY_MIN_LEN) {
                WARN("PublicKey's length is less then RSA suggested minimum length");
            }
            break;
        case EVP_PKEY_EC:
            if (EVP_PKEY_bits(pkey) < ECC_PKEY_MIN_LEN) {
                WARN("PublicKey's length is less then ECC suggested minimum length");
            }
            break;
        default:
            break;
    }

    EVP_PKEY_free(pkey);
}

int get_common_name_from_tls_cert(const char *cert_path, char *value, size_t len)
{
    int ret = 0;
    X509 *cert = NULL;
    X509_NAME *subject_name = NULL;
    FILE *fp = NULL;

    if (cert_path == NULL || strlen(cert_path) == 0) {
        return 0;
    }

    fp = util_fopen(cert_path, "r");
    if (fp == NULL) {
        ERROR("Failed to open cert file: %s", cert_path);
        return -1;
    }
    cert = PEM_read_X509(fp, NULL, NULL, NULL);
    if (cert == NULL) {
        ERROR("Failed to parse cert in: %s", cert_path);
        ret = -1;
        goto out;
    }

    // check signature algorithm and public key length
    check_algo(cert);
    check_pub_key(cert);

    subject_name = X509_get_subject_name(cert);
    if (subject_name == NULL) {
        ERROR("Failed to get subject name in: %s\n", cert_path);
        ret = -1;
        goto out;
    }
    if (X509_NAME_get_text_by_NID(subject_name, NID_commonName, value, (int)len) < 0) {
        ret = -1;
        goto out;
    }

out:
    if (cert != NULL) {
        X509_free(cert);
    }
    fclose(fp);
    return ret;
}

