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
 * Description: provide container http function definition
 ******************************************************************************/
#ifndef ISULAD_HTTP_H
#define ISULAD_HTTP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int(*progress_info_func)(void *p,
                                 double dltotal, double dlnow,
                                 double ultotal, double ulnow);

struct http_get_options {
    unsigned with_head : 1, /* if set, means write output with response HEADER */
             with_body : 1, /* if set, means write output with response BODY */
             /* if set, means set request with "Authorization:(char *)authorization" */
             with_header_auth : 1,
             /* if set, means set requst with "Content-Type: application/json" */
             with_header_json : 1,
             /* if set, means set request with "Accept:(char *)accepts" */
             with_header_accept : 1,
             /* if set, means show the process progress" */
             show_progress : 1;

    char outputtype;

    /* if set, means connnect to unix socket */
    char *unix_socket_path;

    /*
     * if outputtype is HTTP_REQUEST_STRBUF, the output is a pointer to struct Buffer
     * if outputtype is HTTP_REQUEST_FILE, the output is a pointer to a file name
     */
    void *output;

    /* http method PUT GET POST */
    void *method;
    /* body to be sent to server */
    void *input;
    size_t input_len;

    char *authorization;

    char *accepts;

    char **custom_headers;

    bool debug;
    bool ssl_verify_peer;
    bool ssl_verify_host;

    char *ca_file;
    char *cert_file;
    char *key_file;

    void *progressinfo;
    progress_info_func progress_info_op;
};

#define HTTP_RES_OK                 0
#define HTTP_RES_MISSING_TARGET     1
#define HTTP_RES_ERROR              2
#define HTTP_RES_START_FAILED       3
#define HTTP_RES_REAUTH             4
#define HTTP_RES_NOAUTH             5

/* HTTP Get buffer size */
#define  HTTP_GET_BUFFER_SIZE       1024

/* authz error msg size */
#define  AUTHZ_ERROR_MSG_SIZE       256

/* http_request() targets */
#define HTTP_REQUEST_STRBUF         0
#define HTTP_REQUEST_FILE           1

/* authz unix sock and request url */
#define AUTHZ_UNIX_SOCK             "/run/isulad/plugins/authz-broker.sock"
#define AUTHZ_REQUEST_URL           "http://localhost/isulad.auth"

/* http response code */
enum http_response_code {
    StatusContinue                      = 100, // RFC 7231, 6.2.1
    StatusSwitchingProtocols            = 101, // RFC 7231, 6.2.2
    StatusProcessing                    = 102, // RFC 2518, 10.1

    StatusOK                            = 200, // RFC 7231, 6.3.1
    StatusCreated                       = 201, // RFC 7231, 6.3.2
    StatusAccepted                      = 202, // RFC 7231, 6.3.3
    StatusNonAuthoritativeInfo          = 203, // RFC 7231, 6.3.4
    StatusNoContent                     = 204, // RFC 7231, 6.3.5
    StatusResetContent                  = 205, // RFC 7231, 6.3.6
    StatusPartialContent                = 206, // RFC 7233, 4.1
    StatusMultiStatus                   = 207, // RFC 4918, 11.1
    StatusAlreadyReported               = 208, // RFC 5842, 7.1
    StatusIMUsed                        = 226, // RFC 3229, 10.4.1

    StatusMultipleChoices               = 300, // RFC 7231, 6.4.1
    StatusMovedPermanently              = 301, // RFC 7231, 6.4.2
    StatusFound                         = 302, // RFC 7231, 6.4.3
    StatusSeeOther                      = 303, // RFC 7231, 6.4.4
    StatusNotModified                   = 304, // RFC 7232, 4.1
    StatusUseProxy                      = 305, // RFC 7231, 6.4.5
    _                                   = 306, // RFC 7231, 6.4.6 (Unused)
    StatusTemporaryRedirect             = 307, // RFC 7231, 6.4.7
    StatusPermanentRedirect             = 308, // RFC 7538, 3

    StatusBadRequest                    = 400, // RFC 7231, 6.5.1
    StatusUnauthorized                  = 401, // RFC 7235, 3.1
    StatusPaymentRequired               = 402, // RFC 7231, 6.5.2
    StatusForbidden                     = 403, // RFC 7231, 6.5.3
    StatusNotFound                      = 404, // RFC 7231, 6.5.4
    StatusMethodNotAllowed              = 405, // RFC 7231, 6.5.5
    StatusNotAcceptable                 = 406, // RFC 7231, 6.5.6
    StatusProxyAuthRequired             = 407, // RFC 7235, 3.2
    StatusRequestTimeout                = 408, // RFC 7231, 6.5.7
    StatusConflict                      = 409, // RFC 7231, 6.5.8
    StatusGone                          = 410, // RFC 7231, 6.5.9
    StatusLengthRequired                = 411, // RFC 7231, 6.5.10
    StatusPreconditionFailed            = 412, // RFC 7232, 4.2
    StatusRequestEntityTooLarge         = 413, // RFC 7231, 6.5.11
    StatusRequestURITooLong             = 414, // RFC 7231, 6.5.12
    StatusUnsupportedMediaType          = 415, // RFC 7231, 6.5.13
    StatusRequestedRangeNotSatisfiable  = 416, // RFC 7233, 4.4
    StatusExpectationFailed             = 417, // RFC 7231, 6.5.14
    StatusTeapot                        = 418, // RFC 7168, 2.3.3
    StatusUnprocessableEntity           = 422, // RFC 4918, 11.2
    StatusLocked                        = 423, // RFC 4918, 11.3
    StatusFailedDependency              = 424, // RFC 4918, 11.4
    StatusUpgradeRequired               = 426, // RFC 7231, 6.5.15
    StatusPreconditionRequired          = 428, // RFC 6585, 3
    StatusTooManyRequests               = 429, // RFC 6585, 4
    StatusRequestHeaderFieldsTooLarge   = 431, // RFC 6585, 5
    StatusUnavailableForLegalReasons    = 451, // RFC 7725, 3

    StatusInternalServerError           = 500, // RFC 7231, 6.6.1
    StatusNotImplemented                = 501, // RFC 7231, 6.6.2
    StatusBadGateway                    = 502, // RFC 7231, 6.6.3
    StatusServiceUnavailable            = 503, // RFC 7231, 6.6.4
    StatusGatewayTimeout                = 504, // RFC 7231, 6.6.5
    StatusHTTPVersionNotSupported       = 505, // RFC 7231, 6.6.6
    StatusVariantAlsoNegotiates         = 506, // RFC 2295, 8.1
    StatusInsufficientStorage           = 507, // RFC 4918, 11.5
    StatusLoopDetected                  = 508, // RFC 5842, 7.2
    StatusNotExtended                   = 510, // RFC 2774, 7
    StatusNetworkAuthenticationRequired = 511  // RFC 6585, 6
};

void free_http_get_options(struct http_get_options *options);

int http_request(const char *url, struct http_get_options *options,
                 long *response_code, int recursive_len);

int authz_http_request(const char *username, const char *action, char **resp);

void http_global_init(void);

void http_global_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif

