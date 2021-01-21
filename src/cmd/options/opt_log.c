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
 * Author: haozi007
 * Create: 2020-11-16
 * Description: provide log options parse function
 ******************************************************************************/
#include "opt_log.h"

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include <isula_libutils/log.h>

#include "constants.h"
#include "utils.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_string.h"
#include "buffer.h"

#define DRIVER_MAX 2

typedef int (*log_opt_callback_t)(const char *key, const char *value, char **parsed_val);

typedef struct log_opt_parse {
    const char *key;
    const char *real_key;
    log_opt_callback_t cb;
} log_opt_parse_t;

static int log_opt_common_cb(const char *key, const char *value, char **parsed_val)
{
    *parsed_val = util_strdup_s(value);
    return 0;
}

static int log_opt_max_file_cb(const char *key, const char *value, char **parsed_val)
{
    unsigned int ptr = 0;
    int ret = -1;

    if (util_safe_uint(value, &ptr)) {
        return ret;
    }
    if (ptr == 0) {
        ERROR("Invalid option 'max-file', value:%s", value);
        return ret;
    }

    *parsed_val = util_strdup_s(value);
    return 0;
}

static int log_opt_syslog_facility(const char *key, const char *value, char **parsed_val)
{
    const char *facility_values[] = { "kern",     "user",   "mail",   "daemon", "auth",
                                      "syslog",   "lpr",    "news",   "uucp",   "cron",
                                      "authpriv", "ftp",    "local0", "local1", "local2",
                                      "local3",   "local4", "local5", "local6", "local7"
                                    };
    int i;
    size_t f_len = sizeof(facility_values) / sizeof(const char *);

    for (i = 0; i < f_len; i++) {
        if (strcmp(facility_values[i], value) == 0) {
            break;
        }
    }

    if (i == f_len) {
        ERROR("Invalid option 'syslog-facility', value:%s", value);
        return -1;
    }

    *parsed_val = util_strdup_s(value);
    return 0;
}

static int log_opt_disable_log_cb(const char *key, const char *value, char **parsed_val)
{
    int ret = -1;

    if (strcmp(value, "true") == 0) {
        *parsed_val = util_strdup_s("none");
        ret = 0;
    } else if (strcmp(value, "false") == 0) {
        ret = 0;
    }

    if (ret != 0) {
        ERROR("Invalid option 'disable-log', value:%s", value);
    }

    return ret;
}

bool parse_container_log_opt(const char *key, const char *val, json_map_string_string *opts)
{
#define LOG_PARSER_MAX 5
    size_t i, j;
    log_opt_parse_t support_parsers[LOG_PARSER_MAX] = {
        {
            .key = "max-size",
            .real_key = CONTAINER_LOG_CONFIG_KEY_SIZE,
            .cb = &log_opt_common_cb,
        },
        {
            .key = "max-file",
            .real_key = CONTAINER_LOG_CONFIG_KEY_ROTATE,
            .cb = &log_opt_max_file_cb,
        },
        {
            .key = "disable-log",
            .real_key = CONTAINER_LOG_CONFIG_KEY_FILE,
            .cb = &log_opt_disable_log_cb,
        },
        {
            .key = "syslog-tag",
            .real_key = CONTAINER_LOG_CONFIG_KEY_SYSLOG_TAG,
            .cb = &log_opt_common_cb,
        },
        {
            .key = "syslog-facility",
            .real_key = CONTAINER_LOG_CONFIG_KEY_SYSLOG_FACILITY,
            .cb = &log_opt_syslog_facility,
        },
    };

    if (key == NULL || opts == NULL) {
        return false;
    }

    for (i = 0; i < LOG_PARSER_MAX; i++) {
        if (strcmp(key, support_parsers[i].key) == 0) {
            char *parsed_val = NULL;
            int nret;

            nret = support_parsers[i].cb(support_parsers[i].real_key, val, &parsed_val);
            if (nret != 0) {
                return false;
            }
            if (parsed_val == NULL) {
                return true;
            }

            // check whether seted option, if setted, ust replace
            for (j = 0; j < opts->len; j++) {
                if (strcmp(opts->keys[j], support_parsers[i].real_key) == 0) {
                    free(opts->values[j]);
                    opts->values[j] = parsed_val;
                    return true;
                }
            }
            nret = append_json_map_string_string(opts, support_parsers[i].real_key, parsed_val);
            free(parsed_val);
            return true;
        }
    }
    ERROR("Unknow log opts: %s = %s", key, val);
    return false;
}

bool parse_container_log_opts(json_map_string_string **opts)
{
    size_t i;
    json_map_string_string *result = NULL;

    if (opts == NULL || *opts == NULL) {
        return true;
    }
    result = util_common_calloc_s(sizeof(json_map_string_string));
    if (result == NULL) {
        ERROR("Out of memory");
        return false;
    }

    for (i = 0; i < (*opts)->len; i++) {
        if ((*opts)->values[i] == NULL || strlen((*opts)->values[i]) > OPT_MAX_LEN) {
            ERROR("Too large value: %s for key:%s", (*opts)->values[i], (*opts)->keys[i]);
            free_json_map_string_string(result);
            return false;
        }

        if (!parse_container_log_opt((*opts)->keys[i], (*opts)->values[i], result)) {
            free_json_map_string_string(result);
            return false;
        }
    }

    free_json_map_string_string(*opts);
    *opts = result;
    return true;
}

bool check_opt_container_log_opt(const char *driver, const char *opt_key)
{
#define DRIVER_MAX 2
#define MAX_SUPPORT_KEY_LEN 3
    const char *support_keys[][MAX_SUPPORT_KEY_LEN] = {
        { CONTAINER_LOG_CONFIG_KEY_FILE, CONTAINER_LOG_CONFIG_KEY_ROTATE, CONTAINER_LOG_CONFIG_KEY_SIZE },
        { CONTAINER_LOG_CONFIG_KEY_SYSLOG_TAG, CONTAINER_LOG_CONFIG_KEY_SYSLOG_FACILITY, NULL}
    };
    const char *driver_idx[] = { CONTAINER_LOG_CONFIG_JSON_FILE_DRIVER, CONTAINER_LOG_CONFIG_SYSLOG_DRIVER };
    size_t i, idx;

    if (driver == NULL || opt_key == NULL) {
        return false;
    }
    for (idx = 0; idx < DRIVER_MAX; idx++) {
        if (strcmp(driver_idx[idx], driver) == 0) {
            break;
        }
    }
    if (idx == DRIVER_MAX) {
        ERROR("Unsupport driver: %s", driver);
        return false;
    }

    for (i = 0; i < MAX_SUPPORT_KEY_LEN; i++) {
        if (support_keys[idx][i] == NULL) {
            break;
        }
        if (strcmp(support_keys[idx][i], opt_key) == 0) {
            return true;
        }
    }

    ERROR("driver: %s, unsupport opts: %s", driver, opt_key);
    return false;
}

bool check_raw_log_opt(const char *key)
{
    size_t i;
    const char *support_keys[] = {
        "max-size", "max-file", "disable-log", "syslog-tag", "syslog-facility"
    };

    if (key == NULL) {
        return false;
    }

    for (i = 0; i < sizeof(support_keys) / sizeof(const char *); i++) {
        if (strcmp(key, support_keys[i]) == 0) {
            return true;
        }
    }

    return false;
}

bool check_opt_container_log_driver(const char *driver)
{
    const char *supported_drivers[] = { CONTAINER_LOG_CONFIG_JSON_FILE_DRIVER, CONTAINER_LOG_CONFIG_SYSLOG_DRIVER };
    int i = 0;

    if (driver == NULL) {
        return false;
    }

    for (; i < DRIVER_MAX; i++) {
        if (strcmp(driver, supported_drivers[i]) == 0) {
            return true;
        }
    }

    return false;
}

int parse_container_log_opt_syslog_tag(const char *tag, tag_parser op, map_t *tag_maps, char **parsed_tag)
{
    Buffer *bf = NULL;
    char *work_tag = NULL;
    char *prefix = NULL;
    char *curr = NULL;
    int ret = 0;

    if (tag == NULL || op == NULL || parsed_tag == NULL) {
        ERROR("Invalid arguments");
        return -1;
    }
    bf = buffer_alloc(strlen(tag));
    if (bf == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    work_tag = util_strdup_s(tag);
    prefix = work_tag;
    while (prefix != NULL && strlen(prefix) != 0) {
        char *parsed_item = NULL;
        curr = strstr(prefix, "{{");
        if (curr == NULL) {
            ret = buffer_append(bf, prefix, strlen(prefix));
            break;
        }
        *curr = '\0';
        ret = buffer_append(bf, prefix, strlen(prefix));
        if (ret != 0) {
            ERROR("OUt of memory");
            goto out;
        }
        *curr = '{';

        curr = curr + 2;
        prefix = strstr(curr, "}}");
        if (prefix == NULL) {
            ERROR("invalid tag item: %s", tag);
            ret = -1;
            goto out;
        }
        // get item in '{{' and '}}', to parse to expected string
        *prefix = '\0';
        if (op(curr, tag_maps, &parsed_item) != 0) {
            ERROR("invalid tag item: %s", tag);
            ret = -1;
            goto out;
        }
        DEBUG("parse syslog tag item: %s --> %s", curr, parsed_item);
        *prefix = '}';
        ret = buffer_append(bf, parsed_item, strlen(parsed_item));
        free(parsed_item);
        if (ret != 0) {
            ERROR("OUt of memory");
            goto out;
        }
        prefix = prefix + 2;
    }

    *parsed_tag = util_strdup_s(bf->contents);
out:
    buffer_free(bf);
    free(work_tag);
    return ret;
}