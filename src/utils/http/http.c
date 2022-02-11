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
 * Create: 2018-11-08
 * Description: provide container http function
 ******************************************************************************/
#include "http.h"
#include <curl/curl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "buffer.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_file.h"

size_t fwrite_buffer(const char *ptr, size_t eltsize, size_t nmemb, void *buffer_)
{
    size_t size = eltsize * nmemb;
    struct Buffer *buffer = buffer_;
    int status = 0;

    status = buffer_append(buffer, ptr, size);
    if (status != 0) {
        ERROR("Failed to write buffer\n");
    }
    return size;
}

size_t fwrite_file(const void *ptr, size_t size, size_t nmemb, void *stream)
{
    size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
    return written;
}

size_t fwrite_null(char *ptr, size_t eltsize, size_t nmemb, void *strbuf)
{
    return eltsize * nmemb;
}

void free_http_get_options(struct http_get_options *options)
{
    if (options == NULL) {
        return;
    }
    free(options->accepts);
    options->accepts = NULL;

    free(options->authorization);
    options->authorization = NULL;

    free(options->unix_socket_path);
    options->unix_socket_path = NULL;

    util_free_array(options->custom_headers);
    options->custom_headers = NULL;

    free(options->ca_file);
    options->ca_file = NULL;

    free(options->cert_file);
    options->cert_file = NULL;

    free(options->key_file);
    options->key_file = NULL;

    free(options->errmsg);
    options->errmsg = NULL;

    /* The options->output is a FILE pointer, we should not free it here */
    free(options);
    return;
}

void http_global_init(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
}

void http_global_cleanup(void)
{
    curl_global_cleanup();
}

struct curl_slist *http_get_chunk_header(const struct http_get_options *options)
{
    int ret = 0;
    int nret;
    size_t len = 0;
    struct curl_slist *chunk = NULL;
    char *header = NULL;
    char **custom_headers = NULL;
    int i = 0;

    if (options->with_header_auth && options->authorization) {
        if (strlen(options->authorization) > (SIZE_MAX - strlen("Authorization: ")) - 1) {
            ERROR("Invalid authorization option");
            ret = -1;
            goto out;
        }
        len = strlen(options->authorization) + strlen("Authorization: ") + 1;
        header = util_common_calloc_s(len);
        if (header == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        nret = snprintf(header, len, "Authorization: %s", options->authorization);
        if (nret < 0 || (size_t)nret >= len) {
            ERROR("Failed to print string");
            ret = -1;
            goto out;
        }
        chunk = curl_slist_append(chunk, header);
        free(header);
        header = NULL;
    }

    if (options->with_header_json) {
        chunk = curl_slist_append(chunk, "Content-Type: application/json");
        // Disable "Expect: 100-continue"
        chunk = curl_slist_append(chunk, "Expect:");
    }

    custom_headers = options->custom_headers;
    for (i = 0; custom_headers != NULL && custom_headers[i] != 0; i++) {
        chunk = curl_slist_append(chunk, custom_headers[i]);
    }

    if (options->with_header_accept && options->accepts) {
        if (strlen(options->accepts) > (SIZE_MAX - strlen("Accept: ")) - 1) {
            ERROR("Invalid accepts option");
            ret = -1;
            goto out;
        }
        len = strlen(options->accepts) + strlen("Accept: ") + 1;
        header = util_common_calloc_s(len);
        if (header == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
        nret = snprintf(header, len, "Accept: %s", options->accepts);
        if (nret < 0 || (size_t)nret >= len) {
            ERROR("Failed to print string");
            ret = -1;
            goto out;
        }
        chunk = curl_slist_append(chunk, header);
        free(header);
        header = NULL;
    }
out:
    if (ret) {
        curl_slist_free_all(chunk);
        chunk = NULL;
    }
    free(header);

    return chunk;
}

static int http_custom_options(CURL *curl_handle, const struct http_get_options *options)
{
    int ret = 0;

    if (curl_handle == NULL || options == NULL) {
        return -1;
    }

    if (options->timeout) {
        /* complete connection within 30 seconds */
        curl_easy_setopt(curl_handle, CURLOPT_CONNECTTIMEOUT, 30L);
        /* if less than 1k data is received in 30s, abort */
        curl_easy_setopt(curl_handle, CURLOPT_LOW_SPEED_LIMIT, 1024L);
        curl_easy_setopt(curl_handle, CURLOPT_LOW_SPEED_TIME, 30L);
    }

    if (options->unix_socket_path) {
        curl_easy_setopt(curl_handle, CURLOPT_UNIX_SOCKET_PATH, options->unix_socket_path);
    }

    if (options->with_head) {
        curl_easy_setopt(curl_handle, CURLOPT_HEADER, 1L);
    }

    if (options->with_body == 0) {
        curl_easy_setopt(curl_handle, CURLOPT_NOBODY, 1L);
    }

    /* disable progress meter, set to 0L to enable and disable debug output */
    if (options->show_progress == 0) {
        curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    } else if (options->show_progress && options->progressinfo && options->progress_info_op) {
        curl_easy_setopt(curl_handle, CURLOPT_PROGRESSFUNCTION, options->progress_info_op);
        /* pass the struct pointer into the progress function */
        curl_easy_setopt(curl_handle, CURLOPT_PROGRESSDATA, options->progressinfo);
        curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
    } else {
        curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 0L);
    }

    if (options->input) {
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, options->input);
        curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, options->input_len);
        curl_easy_setopt(curl_handle, CURLOPT_POST, 1L);
    }

    if (options->debug) {
        curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
    }

    if (options->ssl_verify_peer) {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
    } else {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    }
    if (options->ssl_verify_host) {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
    } else {
        curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (options->ca_file != NULL) {
        curl_easy_setopt(curl_handle, CURLOPT_CAINFO, options->ca_file);
    }
    if (options->cert_file != NULL) {
        curl_easy_setopt(curl_handle, CURLOPT_SSLCERT, options->cert_file);
    }
    if (options->key_file != NULL) {
        curl_easy_setopt(curl_handle, CURLOPT_SSLKEY, options->key_file);
    }

    return ret;
}

static void close_file(FILE *pagefile)
{
    if (pagefile != NULL) {
        fclose(pagefile);
    }
}

static void free_rpath(char *rpath)
{
    free(rpath);
}

static void check_buf_len(struct http_get_options *options, char *errbuf, CURLcode curl_result)
{
    int nret = 0;
    size_t len = 0;

    if (options == NULL || options->errmsg != NULL) {
        return;
    }

    len = strlen(errbuf);
    if (len == 0) {
        nret = snprintf(errbuf, CURL_ERROR_SIZE, "curl response error code %d", curl_result);
        if (nret < 0 || (size_t)nret >= CURL_ERROR_SIZE) {
            ERROR("Failed to print string for error buffer, errcode %d", curl_result);
            return;
        }
    }
    ERROR("curl response error code %d, error message: %s", curl_result, errbuf);
    free(options->errmsg);
    options->errmsg = util_strdup_s(errbuf);
    options->errcode = curl_result;

    return;
}

static void buffer_empty_on_condition(struct http_get_options *options)
{
    if (options == NULL) {
        return;
    }
    if (options->output && options->outputtype == HTTP_REQUEST_STRBUF) {
        buffer_empty(options->output);
    }

    if (options->with_header_auth && options->authorization) {
        options->with_header_auth = 0;
    }
}

static void curl_getinfo_on_condition(long *response_code, CURL *curl_handle, char **tmp)
{
    if (response_code != NULL) {
        curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, response_code);
    }
    curl_easy_getinfo(curl_handle, CURLINFO_REDIRECT_URL, tmp);
}

static int ensure_path_file(char **rpath, void *output, bool resume, FILE **pagefile, size_t *fsize)
{
    const char *mode = "w+";
    struct stat st;

    if (util_ensure_path(rpath, output)) {
        return -1;
    }

    if (resume) {
        mode = "a";
        if (stat(*rpath, &st) < 0) {
            ERROR("stat %s failed: %s", *rpath, strerror(errno));
            return -1;
        }
        *fsize = (size_t)st.st_size;
    } else {
        *fsize = 0;
    }

    *pagefile = util_fopen(*rpath, mode);
    if (*pagefile == NULL) {
        ERROR("Failed to open file %s\n", (const char *)output);
        return -1;
    }
    return 0;
}

static struct curl_slist *set_custom_header(CURL *curl_handle, const struct http_get_options *options)
{
    struct curl_slist *chunk = NULL;
    chunk = http_get_chunk_header(options);
    if (chunk) {
        /* set our custom set of headers */
        curl_easy_setopt(curl_handle, CURLOPT_HTTPHEADER, chunk);
    }
    return chunk;
}

static size_t calc_replaced_url_len(const char *url)
{
    size_t i = 0;
    size_t size = 0;
    size_t max = 0;
    size = strlen(url);

    for (i = 0; i < size; i++) {
        if (url[i] != ' ') {
            max++;
            continue;
        }
        max += 3;	/* ' ' to %20 so size should add 3 */
    }

    return max + 1; /* +1 for terminator */
}

static char *replace_url(const char *url)
{
    size_t i = 0;
    size_t pos = 0;
    size_t size = 0;
    size_t max = 0;
    char *replaced_url = NULL;

    size = strlen(url);
    max = calc_replaced_url_len(url);
    replaced_url = util_common_calloc_s(max);
    if (replaced_url == NULL) {
        ERROR("out of memory");
        return NULL;
    }

    for (i = 0; i < size; i++) {
        if (url[i] != ' ') {
            *(replaced_url + pos) = url[i];
            pos++;
            continue;
        }
        (void)strcat(replaced_url + pos, "%20");
        pos += 3; /* ' ' to %20 so multiply 3 */
    }

    return replaced_url;
}

int http_request(const char *url, struct http_get_options *options, long *response_code, int recursive_len)
{
#define MAX_REDIRCT_NUMS 32
    CURL *curl_handle = NULL;
    CURLcode curl_result = CURLE_OK;
    struct curl_slist *chunk = NULL;
    FILE *pagefile = NULL;
    char *rpath = NULL;
    int ret = 0;
    char errbuf[CURL_ERROR_SIZE] = { 0 };
    bool strbuf_args;
    bool file_args;
    char *redir_url = NULL;
    char *tmp = NULL;
    size_t fsize = 0;
    char *replaced_url = 0;

    if (recursive_len + 1 >= MAX_REDIRCT_NUMS) {
        ERROR("reach the max redirect num");
        return -1;
    }

    /* init the curl session */
    curl_handle = curl_easy_init();
    if (curl_handle == NULL) {
        return -1;
    }

    replaced_url = replace_url(url);
    if (replaced_url == NULL) {
        ret = -1;
        goto out;
    }

    /* set URL to get here */
    curl_easy_setopt(curl_handle, CURLOPT_URL, replaced_url);
    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1L);

    /* provide a buffer to store errors in */
    curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl_handle, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
    /* libcurl support option CURLOPT_SUPPRESS_CONNECT_HEADERS when version >= 7.54.0
     * #define CURL_VERSION_BITS(x,y,z) ((x)<<16|(y)<<8|(z))
     * CURL_VERSION_BITS(7,54,0) = 0x073600 */
#if (LIBCURL_VERSION_NUM >= 0x073600)
    curl_easy_setopt(curl_handle, CURLOPT_SUPPRESS_CONNECT_HEADERS, 1L);
#endif

    ret = http_custom_options(curl_handle, options);
    if (ret) {
        goto out;
    }
    chunk = set_custom_header(curl_handle, options);

    strbuf_args = options->output && options->outputtype == HTTP_REQUEST_STRBUF;
    file_args = options->output && options->outputtype == HTTP_REQUEST_FILE;
    if (strbuf_args) {
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, options->output);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, fwrite_buffer);
    } else if (file_args) {
        /* open the file */
        if (ensure_path_file(&rpath, options->output, options->resume, &pagefile, &fsize) != 0) {
            ret = -1;
            goto out;
        }
        if (options->resume) {
            curl_easy_setopt(curl_handle, CURLOPT_RESUME_FROM_LARGE, (curl_off_t)fsize);
        }
        curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);
        curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, fwrite_file);
    } else {
        /* do nothing */
    }

    /* get it! */
    curl_result = curl_easy_perform(curl_handle);

    if (curl_result != CURLE_OK) {
        check_buf_len(options, errbuf, curl_result);
        ret = -1;
    } else {
        curl_getinfo_on_condition(response_code, curl_handle, &tmp);
        if (tmp) {
            redir_url = util_strdup_s(tmp);
        }
    }

out:
    free(replaced_url);
    close_file(pagefile);
    free_rpath(rpath);

    /* cleanup curl stuff */
    curl_easy_cleanup(curl_handle);
    curl_slist_free_all(chunk);

    if (redir_url) {
        buffer_empty_on_condition(options);

        if (http_request(redir_url, options, response_code, recursive_len + 1)) {
            ERROR("Failed to get http request\n");
            ret = -1;
        }
        free(redir_url);
    }

    return ret;
}

int authz_http_request(const char *username, const char *action, char **resp)
{
    char *request_body = NULL;
    char err_msg[AUTHZ_ERROR_MSG_SIZE] = { 0 };
    long response_code = 0;
    int ret = 0;
    int nret = 0;
    size_t length = 0;
    struct http_get_options *options = NULL;
    if (strlen(username) > ((SIZE_MAX - strlen(action)) - strlen(":")) - 1) {
        ERROR("Invalid arguments");
        return -1;
    }
    length = strlen(username) + strlen(":") + strlen(action) + 1;
    request_body = util_common_calloc_s(length);
    if (request_body == NULL) {
        ERROR("Out of memory");
        *resp = util_strdup_s("Inernal server error: Out of memory");
        return -1;
    }
    nret = snprintf(request_body, length, "%s:%s", username, action);
    if (nret < 0 || (size_t)nret >= length) {
        ERROR("Failed to print string");
        free(request_body);
        return -1;
    }
    options = util_common_calloc_s(sizeof(struct http_get_options));
    if (options == NULL) {
        ERROR("Failed to malloc http_get_options");
        *resp = util_strdup_s("Inernal server error: Out of memory");
        free(request_body);
        return -1;
    }

    options->with_head = 1;
    options->with_header_json = 1;
    options->input = request_body;
    options->input_len = strlen(request_body);
    options->unix_socket_path = util_strdup_s(AUTHZ_UNIX_SOCK);

    ret = http_request(AUTHZ_REQUEST_URL, options, &response_code, 0);
    if (ret != 0) {
        ERROR("Failed to request authz plugin. Is server running ?");
        *resp = util_strdup_s("Failed to request authz plugin. Is server running ?");
        ret = -1;
        goto out;
    }
    if (response_code != StatusOK) {
        ret = -1;
        nret = snprintf(err_msg, sizeof(err_msg), "action '%s' for user '%s': permission denied", action, username);
        if (nret < 0 || (size_t)nret >= sizeof(err_msg)) {
            ERROR("Out of memory");
            *resp = util_strdup_s("Inernal server error: Out of memory");
            goto out;
        }
        *resp = util_strdup_s(err_msg);
        goto out;
    }

out:
    free(request_body);
    if (options != NULL) {
        free(options->unix_socket_path);
        free(options);
    }
    return ret;
}
