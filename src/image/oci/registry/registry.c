/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: wangfengtu
 * Create: 2020-02-27
 * Description: provide registry functions
 ******************************************************************************/

#define _GNU_SOURCE             /* See feature_test_macros(7) */
#include <fcntl.h>              /* Obtain O_* constant definitions */
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>

#include "mediatype.h"
#include "log.h"
#include "registry_type.h"
#include "registry.h"
#include "utils.h"
#include "oci_common_operators.h"
#include "registry_apiv2.h"
#include "auths.h"
#include "certs.h"

static int registry_fetch(pull_descriptor *desc)
{
    int ret = 0;

    ret = fetch_manifests(desc);
    if (ret != 0) {
        ERROR("fetch manifest failed");
        return ret;
    }

    return ret;
}

static int prepare_pull_desc(pull_descriptor *desc, registry_pull_options *options)
{
    int ret = 0;
    int sret = 0;
    char blobpath[32] = "/var/tmp/isulad-registry-XXXXXX";
    char scope[PATH_MAX] = {0};

    ret = oci_split_image_name(options->image_name, &desc->host,
                               &desc->name, &desc->tag);
    if (ret != 0) {
        ERROR("split image name %s failed", options->image_name);
        ret = -1;
        goto out;
    }

    if (desc->host == NULL || desc->name == NULL || desc->tag == NULL) {
        ERROR("Invalid image %s, host or name or tag not found", options->image_name);
        ret = -1;
        goto out;
    }

    // registry-1.docker.io is the real docker.io's registry. index.docker.io is V1 registry, we do not support
    // V1 registry, try use registry-1.docker.io.
    if (!strcmp(desc->host, DOCKER_HOSTNAME) || !strcmp(desc->host, DOCKER_V1HOSTNAME)) {
        free(desc->host);
        desc->host = util_strdup_s(DOCKER_REGISTRY);
    }

    if (mkdtemp(blobpath) == NULL) {
        ERROR("make temporary direcory failed: %s", strerror(errno));
        ret = -1;
        goto out;
    }

    sret = snprintf(scope, sizeof(scope), "repository:%s:pull", desc->name);
    if (sret < 0 || (size_t)sret >= sizeof(scope)) {
        ERROR("Failed to sprintf scope");
        ret = -1;
        goto out;
    }

    desc->scope = util_strdup_s(scope);
    desc->blobpath = util_strdup_s(blobpath);
    desc->skip_tls_verify = options->comm_opt.skip_tls_verify;

out:

    return ret;
}

int registry_pull(registry_pull_options *options)
{
    int ret = 0;
    pull_descriptor *desc = NULL;

    if (options == NULL || options->image_name == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    desc = util_common_calloc_s(sizeof(pull_descriptor));
    if (desc == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }

    ret = prepare_pull_desc(desc, options);
    if (ret != 0) {
        ERROR("registry prepare failed");
        ret = -1;
        goto out;
    }

    ret = registry_fetch(desc);
    if (ret != 0) {
        ERROR("error fetching %s", options->image_name);
        ret = -1;
        goto out;
    }

    INFO("Pull images %s success", options->image_name);

out:
    if (desc->blobpath != NULL) {
        if (util_recursive_rmdir(desc->blobpath, 0)) {
            WARN("failed to remove directory %s", desc->blobpath);
        }
    }

    free_pull_desc(desc);

    return ret;
}

int registry_login(registry_login_options *options)
{
    return 0;
}

int registry_logout(char *auth_file_path, char *host)
{
    return 0;
}

static void free_registry_options(registry_options *options)
{
    if (options == NULL) {
        return;
    }
    free(options->cert_path);
    options->cert_path = NULL;
    free(options->auth_file_path);
    options->auth_file_path = NULL;
    free(options->use_decrypted_key);
    options->use_decrypted_key = NULL;
    return;
}

static void free_registry_auth(registry_auth *auth)
{
    if (auth == NULL) {
        return;
    }
    free_sensitive_string(auth->username);
    auth->username = NULL;
    free_sensitive_string(auth->password);
    auth->password = NULL;
    return;
}

void free_registry_pull_options(registry_pull_options *options)
{
    free_registry_options(&options->comm_opt);
    free_registry_auth(&options->auth);
    free(options->image_name);
    options->image_name = NULL;
    free(options);
    return;
}

void free_registry_login_options(registry_login_options *options)
{
    free_registry_options(&options->comm_opt);
    free_registry_auth(&options->auth);
    free(options->host);
    options->host = NULL;
    free(options);
    return;
}

void free_pull_desc(pull_descriptor *desc)
{
    return;
}
