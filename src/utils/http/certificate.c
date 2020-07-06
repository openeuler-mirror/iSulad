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

