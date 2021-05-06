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
 * Create: 2020-03-20
 * Description: provide http request functions
 ******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "http_request.h"
#include <stdio.h>
#include <string.h>
#include <isula_libutils/json_common.h>
#include <stdbool.h>
#include <stdlib.h>
#include <strings.h>
#include <time.h>
#include <curl/curl.h>
#include <pthread.h>

#include "isula_libutils/log.h"
#include "buffer.h"
#include "http.h"
#include "utils.h"
#include "utils_images.h"
#include "certs.h"
#include "isula_libutils/registry_token.h"
#include "err_msg.h"
#include "utils_array.h"
#include "utils_base64.h"
#include "utils_string.h"

#define MIN_TOKEN_EXPIRES_IN 60

static int http_request_get_token(pull_descriptor *desc, challenge *c, char **output);

static char *get_url_host(const char *url)
{
    char *tmp_url = NULL;
    char *prefix = NULL;
    char *end = NULL;
    char *host = NULL;

    if (url == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    if (util_has_prefix(url, HTTPS_PREFIX)) {
        prefix = HTTPS_PREFIX;
    } else if (util_has_prefix(url, HTTP_PREFIX)) {
        prefix = HTTP_PREFIX;
    } else {
        ERROR("Unexpected url %s, it must be prefixed with %s or %s", url, HTTP_PREFIX, HTTPS_PREFIX);
        goto out;
    }

    tmp_url = util_strdup_s(url);
    end = strchr(tmp_url + strlen(prefix), '/');
    if (end != NULL) {
        *end = 0;
    }

    host = util_strdup_s(tmp_url + strlen(prefix));
out:
    free(tmp_url);
    tmp_url = NULL;

    return host;
}

static int setup_ssl_config(pull_descriptor *desc, struct http_get_options *options, const char *url)
{
    int ret = 0;
    char *host = NULL;

    if (desc == NULL || url == NULL || options == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    // Add only https related options
    if (!util_has_prefix(url, HTTPS_PREFIX)) {
        return 0;
    }

    host = get_url_host(url);
    if (host == NULL) {
        ERROR("Get host from url failed");
        return -1;
    }

    // If target is registry server, we can save ssl related config to avoid load it again next time.
    if (!strcmp(host, desc->host)) {
        if (!desc->cert_loaded) {
            ret = certs_load(host, desc->use_decrypted_key, &desc->ca_file, &desc->cert_file, &desc->key_file);
            if (ret != 0) {
                ret = -1;
                goto out;
            }
            desc->cert_loaded = true;
        }
        options->ca_file = util_strdup_s(desc->ca_file);
        options->cert_file = util_strdup_s(desc->cert_file);
        options->key_file = util_strdup_s(desc->key_file);
    } else {
        ret = certs_load(host, desc->use_decrypted_key, &options->ca_file, &options->cert_file, &options->key_file);
        if (ret != 0) {
            ret = -1;
            goto out;
        }
    }

    options->ssl_verify_peer = !desc->skip_tls_verify;
    options->ssl_verify_host = !desc->skip_tls_verify;

out:

    free(host);
    host = NULL;

    return ret;
}

static char *encode_auth(const char *username, const char *password)
{
    char *auth = NULL;
    size_t auth_len = 0;
    char *auth_base64 = NULL;
    int ret = 0;
    int nret = 0;

    if (username == NULL || password == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    auth_len = strlen(username) + strlen(":") + strlen(password);
    auth = util_common_calloc_s(auth_len + 1);
    if (auth == NULL) {
        ERROR("out of memory");
        return NULL;
    }
    // username:password
    nret = snprintf(auth, auth_len + 1, "%s:%s", username, password);
    if (nret < 0 || (size_t)nret > auth_len) {
        ret = -1;
        ERROR("Failed to sprintf username and password");
        goto out;
    }

    nret = util_base64_encode((unsigned char *)auth, strlen(auth), &auth_base64);
    if (nret < 0) {
        ret = -1;
        ERROR("Encode auth to base64 failed");
        goto out;
    }

out:
    free(auth);
    auth = NULL;

    if (ret != 0) {
        free(auth_base64);
        auth_base64 = NULL;
    }

    return auth_base64;
}

static char *auth_header_str(const char *schema, const char *value)
{
    int ret = 0;
    int sret = 0;
    char *auth_header = NULL;
    size_t auth_header_len = 0;

    if (schema == NULL || value == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    // Auth header's format example:
    // Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l
    auth_header_len = strlen("Authorization") + strlen(": ") + strlen(schema) + strlen(" ") + strlen(value) + 1;
    auth_header = util_common_calloc_s(auth_header_len);
    if (auth_header == NULL) {
        ERROR("out of memory");
        ret = -1;
        goto out;
    }

    sret = snprintf(auth_header, auth_header_len, "Authorization: %s %s", schema, value);
    if (sret < 0 || (size_t)sret >= auth_header_len) {
        ret = -1;
        ERROR("Failed to sprintf authorization");
        goto out;
    }

out:
    if (ret != 0) {
        free(auth_header);
        auth_header = NULL;
    }

    return auth_header;
}

static char *basic_auth_header(const char *schema, const char *username, const char *password)
{
    int ret = 0;
    char *auth_base64 = NULL;
    char *auth_header = NULL;

    if (username == NULL || password == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    auth_base64 = encode_auth(username, password);
    if (auth_base64 == NULL) {
        return NULL;
    }

    auth_header = auth_header_str(schema, auth_base64);
    if (auth_header == NULL) {
        ret = -1;
        goto out;
    }

out:
    free(auth_base64);
    auth_base64 = NULL;
    if (ret != 0) {
        free(auth_header);
        auth_header = NULL;
    }

    return auth_header;
}

static int setup_auth_basic(pull_descriptor *desc, char ***custom_headers)
{
    int ret = 0;
    char *auth_header = NULL;

    if (desc == NULL || custom_headers == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    // Setup auth config only when username and password are provided.
    if (desc->username == NULL || desc->password == NULL) {
        return 0;
    }

    auth_header = basic_auth_header("Basic", desc->username, desc->password);
    if (auth_header == NULL) {
        ret = -1;
        goto out;
    }
    ret = util_array_append(custom_headers, (const char *)auth_header);
    if (ret != 0) {
        ERROR("append custom headers failed");
        goto out;
    }

out:
    free(auth_header);
    auth_header = NULL;

    return ret;
}

static int get_bearer_token(pull_descriptor *desc, challenge *c)
{
    int ret = 0;
    char *output = NULL;
    time_t now = time(NULL);
    registry_token *token = NULL;
    parser_error err = NULL;

    if (desc == NULL || c == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    // Token have not expired, reuse it.
    if (c->cached_token != NULL && c->expires_time != 0 && c->expires_time < now) {
        return 0;
    }

    free(c->cached_token);
    c->cached_token = NULL;
    c->expires_time = 0;

    ret = http_request_get_token(desc, c, &output);
    if (ret != 0 || output == NULL) {
        ERROR("http request get token failed, result is %d", ret);
        ret = -1;
        goto out;
    }

    token = registry_token_parse_data(output, NULL, &err);
    if (token == NULL) {
        ret = -1;
        ERROR("parse token from response failed due to err: %s", err);
        goto out;
    }

    if (token->token != NULL) {
        c->cached_token = util_strdup_s(token->token);
    } else if (token->access_token != NULL) {
        c->cached_token = util_strdup_s(token->access_token);
    } else {
        ret = -1;
        ERROR("no valid token found");
        goto out;
    }

    if (token->expires_in > MIN_TOKEN_EXPIRES_IN) {
        c->expires_time = time(NULL) + token->expires_in;
    } else {
        c->expires_time = MIN_TOKEN_EXPIRES_IN;
    }

out:
    free(err);
    err = NULL;
    free_registry_token(token);
    token = NULL;
    free(output);
    output = NULL;

    return ret;
}

static int setup_auth_challenges(pull_descriptor *desc, char ***custom_headers)
{
    int ret = 0;
    int i = 0;
    char *auth_header = NULL;
    size_t count = 0;

    if (desc == NULL || custom_headers == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    for (i = 0; i < CHALLENGE_MAX; i++) {
        if (desc->challenges[i].schema == NULL || desc->challenges[i].realm == NULL) {
            continue;
        }
        if (!strcasecmp(desc->challenges[i].schema, "Basic")) {
            // Setup auth config only when username and password are provided.
            if (desc->username == NULL || desc->password == NULL) {
                WARN("username or password not found while challenges is basic, try other challenges");
                continue;
            }

            auth_header = basic_auth_header("Basic", desc->username, desc->password);
            if (auth_header == NULL) {
                ERROR("encode basic auth header failed");
                ret = -1;
                goto out;
            }
        } else if (!strcasecmp(desc->challenges[i].schema, "Bearer")) {
            (void)pthread_mutex_lock(&desc->challenges_mutex);
            ret = get_bearer_token(desc, &desc->challenges[i]);
            if (ret != 0) {
                (void)pthread_mutex_unlock(&desc->challenges_mutex);
                ERROR("get bearer token failed");
                isulad_try_set_error_message("authentication failed");
                goto out;
            }

            auth_header = auth_header_str("Bearer", desc->challenges[i].cached_token);
            if (auth_header == NULL) {
                (void)pthread_mutex_unlock(&desc->challenges_mutex);
                ret = -1;
                goto out;
            }
            (void)pthread_mutex_unlock(&desc->challenges_mutex);
        } else {
            WARN("Unsupported schema %s", desc->challenges[i].schema);
            continue;
        }
        ret = util_array_append(custom_headers, (const char *)auth_header);
        if (ret != 0) {
            ERROR("append custom headers failed");
            ret = -1;
            goto out;
        }
        count++;
        free(auth_header);
        auth_header = NULL;
    }

    if (count == 0) {
        DEBUG("No valid challenge found, try continue to send url without auth");
    }

out:
    free(auth_header);
    auth_header = NULL;

    return ret;
}

static int setup_common_options(pull_descriptor *desc, struct http_get_options *options, const char *url,
                                const char **custom_headers)
{
    int ret = 0;

    if (desc == NULL || url == NULL || options == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    // Add https related options
    ret = setup_ssl_config(desc, options, url);
    if (ret != 0) {
        ERROR("Failed setup ssl config");
        isulad_try_set_error_message("setup ssl config failed");
        ret = -1;
        goto out;
    }

    if (custom_headers != NULL) {
        options->custom_headers = util_str_array_dup(custom_headers, util_array_len(custom_headers));
        if (options->custom_headers == NULL) {
            ERROR("dup headers failed");
            ret = -1;
            goto out;
        }
    }

    ret = setup_auth_challenges(desc, &options->custom_headers);
    if (ret != 0) {
        ERROR("setup auth challenges failed");
        isulad_try_set_error_message("setup auth challenges failed");
        ret = -1;
        goto out;
    }

    options->debug = false;

out:

    return ret;
}

static int setup_get_token_options(pull_descriptor *desc, struct http_get_options *options, const char *url)
{
    int ret = 0;

    if (desc == NULL || options == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    // Add https related options
    ret = setup_ssl_config(desc, options, url);
    if (ret != 0) {
        ERROR("Failed setup ssl config");
        ret = -1;
        goto out;
    }

    ret = setup_auth_basic(desc, &options->custom_headers);
    if (ret != 0) {
        ERROR("dup headers failed");
        ret = -1;
        goto out;
    }

    options->debug = false;

out:

    return ret;
}

static int http_request_buf_options(pull_descriptor *desc, struct http_get_options *options, const char *url,
                                    char **output)
{
    int ret = 0;
    Buffer *output_buffer = NULL;

    if (desc == NULL || url == NULL || output == NULL || options == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    output_buffer = buffer_alloc(HTTP_GET_BUFFER_SIZE);
    if (output_buffer == NULL) {
        ERROR("Failed to malloc output_buffer");
        return -1;
    }

    options->outputtype = HTTP_REQUEST_STRBUF;
    options->output = output_buffer;
    ret = http_request(url, options, NULL, 0);
    if (ret) {
        ERROR("Failed to get http request: %s", options->errmsg);
        isulad_try_set_error_message("%s", options->errmsg);
        ret = -1;
        goto out;
    }

    *output = util_strdup_s(output_buffer->contents);
out:

    buffer_free(output_buffer);

    return ret;
}

int http_request_buf(pull_descriptor *desc, const char *url, const char **custom_headers, char **output,
                     resp_data_type type)
{
    int ret = 0;
    struct http_get_options *options = NULL;

    if (desc == NULL || url == NULL || output == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    options = (struct http_get_options *)util_common_calloc_s(sizeof(struct http_get_options));
    if (options == NULL) {
        ERROR("Failed to malloc http_get_options");
        ret = -1;
        goto out;
    }

    memset(options, 0x00, sizeof(struct http_get_options));
    if (type == BODY_ONLY || type == HEAD_BODY) {
        options->with_body = 1;
    }
    if (type == HEAD_ONLY || type == HEAD_BODY) {
        options->with_head = 1;
    }

    ret = setup_common_options(desc, options, url, custom_headers);
    if (ret != 0) {
        ERROR("Failed setup common options");
        ret = -1;
        goto out;
    }

    ret = http_request_buf_options(desc, options, url, output);
    if (ret) {
        ERROR("Failed to get http request");
        ret = -1;
        goto out;
    }

out:
    free_http_get_options(options);
    options = NULL;

    return ret;
}

static char *build_get_token_url(challenge *c, char *username, char *scope)
{
    char *url = NULL;
    size_t url_len = 0;

    // Do not check username, it can be NULL
    if (c == NULL || c->realm == NULL) {
        ERROR("Invalid NULL pointer");
        return NULL;
    }

    // url format example:
    // https://auth.isula.org/token?account=name&service=registry.isula.org&scope=repository:samalba/my-app:pull
    url_len += strlen(c->realm) + strlen("?");
    if (username != NULL) {
        url_len += strlen("account=") + strlen(username) + strlen("&");
    }
    if (c->service != NULL) {
        url_len += strlen("service=") + strlen(c->service) + strlen("&");
    }
    if (scope != NULL) {
        url_len += strlen("scope=") + strlen(scope) + strlen("&");
    }

    url = util_common_calloc_s(url_len);
    if (url == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    (void)strcat(url, c->realm);
    if (username != NULL || c->service != NULL || scope != NULL) {
        (void)strcat(url, "?");
    }

    if (username != NULL) {
        (void)strcat(url, "account=");
        (void)strcat(url, username);
        if (c->service != NULL || scope != NULL) {
            (void)strcat(url, "&");
        }
    }

    if (c->service != NULL) {
        (void)strcat(url, "service=");
        (void)strcat(url, c->service);
        if (scope != NULL) {
            (void)strcat(url, "&");
        }
    }

    if (scope != NULL) {
        (void)strcat(url, "scope=");
        (void)strcat(url, scope);
    }

    return url;
}

static int http_request_get_token(pull_descriptor *desc, challenge *c, char **output)
{
    char *url = NULL;
    int ret = 0;
    struct http_get_options *options = NULL;

    if (desc == NULL || c == NULL || output == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    options = util_common_calloc_s(sizeof(struct http_get_options));
    if (options == NULL) {
        ERROR("Failed to malloc http_get_options");
        ret = -1;
        goto out;
    }

    memset(options, 0x00, sizeof(struct http_get_options));
    options->with_body = 1;
    options->with_head = 0;

    ret = setup_get_token_options(desc, options, c->realm);
    if (ret != 0) {
        ERROR("Failed setup common options");
        ret = -1;
        goto out;
    }

    url = build_get_token_url(c, desc->username, desc->scope);
    if (url == NULL) {
        ret = -1;
        goto out;
    }

    ret = http_request_buf_options(desc, options, url, output);
    if (ret) {
        ERROR("Failed to get http request");
        ret = -1;
        goto out;
    }

out:
    free_http_get_options(options);
    options = NULL;
    free(url);
    url = NULL;

    return ret;
}

static int progress(void *p, double dltotal, double dlnow, double ultotal, double ulnow)
{
    bool *cancel = p;
    if (*cancel) {
        // return nonzero code means abort transition
        return -1;
    }
    return 0;
}

int http_request_file(pull_descriptor *desc, const char *url, const char **custom_headers, char *file,
                      resp_data_type type, CURLcode *errcode)
{
    int ret = 0;
    struct http_get_options *options = NULL;

    if (desc == NULL || url == NULL || file == NULL || errcode == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    options = util_common_calloc_s(sizeof(struct http_get_options));
    if (options == NULL) {
        ERROR("Failed to malloc http_get_options");
        ret = -1;
        goto out;
    }

    memset(options, 0x00, sizeof(struct http_get_options));
    if (type == HEAD_BODY) {
        options->with_head = 1;
    }
    options->with_body = 1;
    if (type == RESUME_BODY) {
        options->resume = true;
    }
    options->outputtype = HTTP_REQUEST_FILE;
    options->output = file;
    options->show_progress = 1;
    options->progressinfo = &desc->cancel;
    options->progress_info_op = progress;

    ret = setup_common_options(desc, options, url, custom_headers);
    if (ret != 0) {
        ERROR("Failed setup common options");
        ret = -1;
        goto out;
    }

    ret = http_request(url, options, NULL, 0);
    if (ret != 0) {
        ERROR("Failed to get http request: %s", options->errmsg);
        isulad_try_set_error_message("%s", options->errmsg);
        ret = -1;
        goto out;
    }

out:
    *errcode = options->errcode;
    free_http_get_options(options);
    options = NULL;

    return ret;
}
