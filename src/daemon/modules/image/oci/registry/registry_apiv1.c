/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: zhongtao
 * Create: 2022-10-17
 * Description: provide registry api v1 functions
 ******************************************************************************/

#define _GNU_SOURCE /* See feature_test_macros(7) */
#include "registry_apiv1.h"
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <isula_libutils/http_parser.h>
#include <isula_libutils/json_common.h>
#include <stdbool.h>
#include <stdlib.h>
#include <strings.h>

#include "registry_type.h"
#include "isula_libutils/log.h"
#include "http.h"
#include "http_request.h"
#include "utils.h"
#include "parser.h"
#include "mediatype.h"
#include "isula_libutils/oci_image_index.h"
#include "isula_libutils/registry_manifest_list.h"
#include "isula_libutils/imagetool_search_result.h"
#include "auths.h"
#include "err_msg.h"
#include "sha256.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"

#define MAX_ACCEPT_LEN 128
#define DOCKER_V1_HEADER "X-Docker-Token"
#define REGISTRY_V1_PING_URL_FORMAT "%s://%s/v1/_ping"
#define REGISTRY_V1_SEARCH_URL_FORMAT "/v1/search?q=%s&n=%d"
#define REGISTRY_V1_REQUEST_URL_FORMAT "%s://%s%s"

#define RETRY_TIMES 3

static int parse_http_body(char *resp_buf, size_t buf_size, struct parsed_http_message *message)
{
    char *real_message = NULL;
    char *deli = "\r\n\r\n"; // default delimiter, may change in later process
    char *body = NULL;

    // get htttp head and body message by find 'HTTP/1.1'.
    real_message = strstr(resp_buf, "HTTP/1.1");
    if (real_message == NULL) {
        ERROR("Failed to parse response, the response do not have HTTP/1.1");
        return -1;
    }

    // first, get http body message by find head delimiter '/r/n/r/n'.
    body = strstr(real_message, deli);
    if (body == NULL) {
        deli = "\n\n";
        // if body is null, find http body message by find head delimiter '/n/n'.
        body = strstr(real_message, deli);
        if (body == NULL) {
            ERROR("No body found, data=%s", real_message);
            return -1;
        }
    }
    body += strlen(deli);

    message->body = util_strdup_s(body);

    return 0;
}

static void free_parsed_http_message(struct parsed_http_message **message)
{
    if (message == NULL || *message == NULL) {
        return;
    }
    free((*message)->body);
    (*message)->body = NULL;

    free(*message);
    *message = NULL;
}

static struct parsed_http_message *get_parsed_message(char *http_head)
{
    int ret = 0;
    struct parsed_http_message *message = NULL;

    message = (struct parsed_http_message *)util_common_calloc_s(sizeof(struct parsed_http_message));
    if (message == NULL) {
        ERROR("Out of memory");
        return NULL;
    }

    ret = parse_http_body(http_head, strlen(http_head), message);
    if (ret != 0) {
        ERROR("Parse http header failed");
        free_parsed_http_message(&message);
        return NULL;
    }

    return message;
}

static int determine_protocol(pull_descriptor *desc)
{
    int ret = 0;

    if (desc->protocol != NULL) {
        return 0;
    }

    ret = registry_apiv1_ping(desc, "https");
    if (ret == 0) {
        desc->protocol = util_strdup_s("https");
        return ret;
    }

    if (desc->insecure_registry) {
        WARN("Ping %s with https failed, try http", desc->host);

        DAEMON_CLEAR_ERRMSG();
        ret = registry_apiv1_ping(desc, "http");
        if (ret != 0) {
            ERROR("Ping %s with http failed", desc->host);
            return -1;
        }
        desc->protocol = util_strdup_s("http");
    } else {
        ERROR("Ping %s with https failed", desc->host);
    }

    return ret;
}

static int registryv1_request(pull_descriptor *desc, char *path, char **output_buffer, resp_data_type type,
                              CURLcode *errcode)
{
    int ret = 0;
    int sret = 0;
    char url[PATH_MAX] = { 0 };
    char **headers = NULL;

    ret = determine_protocol(desc);
    if (ret != 0) {
        ERROR("No proper protocol");
        return -1;
    }

    sret = snprintf(url, sizeof(url), REGISTRY_V1_REQUEST_URL_FORMAT, desc->protocol, desc->host, path);
    if (sret < 0 || (size_t)sret >= sizeof(url)) {
        ERROR("Failed to sprintf url, path is %s", path);
        ret = -1;
        goto out;
    }

    ret = util_array_append(&headers, DOCKER_V1_HEADER);
    if (ret != 0) {
        ERROR("Append v1 header failed");
        ret = -1;
        goto out;
    }

    DEBUG("Sending url: %s", url);
    ret = http_request_buf(desc, url, (const char **)headers, output_buffer, type);
    if (ret != 0) {
        ERROR("Http request buffer failed, url: %s", url);
        ret = -1;
    }
out:
    util_free_array(headers);

    return ret;
}

int registry_apiv1_ping(pull_descriptor *desc, char *protocol)
{
    int ret = 0;
    int sret = 0;
    char *output = NULL;
    char url[PATH_MAX] = { 0 };

    if (desc == NULL || protocol == NULL) {
        ERROR("Invalid NULL param");
        return -1;
    }

    sret = snprintf(url, sizeof(url), REGISTRY_V1_PING_URL_FORMAT, protocol, desc->host);
    if (sret < 0 || (size_t)sret >= sizeof(url)) {
        ERROR("Failed to sprintf url for ping, host is %s", desc->host);
        return -1;
    }

    INFO("Sending ping url: %s", url);
    ret = http_request_buf(desc, url, NULL, &output, HEAD_BODY);
    if (ret != 0) {
        ERROR("Ping %s request failed", protocol);
        ret = -1;
        goto out;
    }
    DEBUG("Ping resp=%s", output);
out:
    free(output);
    return ret;
}

static int fetch_search_result(pull_descriptor *desc, char *path, imagetool_search_result **result)
{
    int ret = 0;
    char *resp_buffer = NULL;
    CURLcode errcode = CURLE_OK;
    parser_error err = NULL;
    struct parsed_http_message *message = NULL;

    ret = registryv1_request(desc, path, &resp_buffer, HEAD_BODY, &errcode);
    if (ret != 0) {
        ERROR("Registry: Get %s failed, errcode is %d", path, errcode);
        ret = -1;
        goto out;
    }

    message = get_parsed_message(resp_buffer);
    if (message == NULL) {
        ERROR("Get parsed message failed, response:%s", resp_buffer);
        isulad_try_set_error_message("Get search %s result parsed message failed.", desc->search_name);
        ret = -1;
        goto out;
    }

    *result = imagetool_search_result_parse_data(message->body, NULL, &err);
    if (*result == NULL) {
        ERROR("Invalid search result:%s", err);
        ret = -1;
    }
out:
    if (message != NULL) {
        free_parsed_http_message(&message);
    }
    free(err);
    free(resp_buffer);

    return ret;
}

int registry_apiv1_fetch_search_result(pull_descriptor *desc, imagetool_search_result **result)
{
    int ret = 0;
    int sret = 0;
    char path[PATH_MAX] = { 0 };
    int retry_times = RETRY_TIMES;

    if (desc == NULL || result == NULL) {
        ERROR("Invalid NULL pointer");
        return -1;
    }

    sret = snprintf(path, sizeof(path), REGISTRY_V1_SEARCH_URL_FORMAT, desc->search_name, desc->limit);
    if (sret < 0 || (size_t)sret >= sizeof(path)) {
        ERROR("Failed to sprintf path for search");
        return -1;
    }

    while (retry_times > 0) {
        retry_times--;
        ret = fetch_search_result(desc, path, result);
        if (ret == 0) {
            break;
        }
        if (retry_times > 0 && !desc->cancel) {
            continue;
        }
        ERROR("Registry: Fetch search result from %s failed", path);
        ret = -1;
    }

    return ret;
}