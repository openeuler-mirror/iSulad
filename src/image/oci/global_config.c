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
* Author: liuhao
* Create: 2019-07-16
* Description: provide isula image operator definition
*******************************************************************************/
#include "global_config.h"

#include <stddef.h>

#include "isulad_config.h"
#include "isula_libutils/log.h"
#ifdef ENABLE_OCI_IMAGE
#include "driver.h"

static int pack_global_graph_driver(const char * const *options, bool ignore_storage_opt_size, char *params[],
                                    size_t *count)
{
    return 0;
}
#endif

static char *adapt_log_level()
{
#define LOG_LEVEL_MAX 5
    const char * const log_level_name[] = {
        "FATAL", "ERROR", "WARN", "INFO", "DEBUG"
    };
    int i;
    char *isulad_level = NULL;
    char *adapted_level = NULL;

    isulad_level = conf_get_isulad_loglevel();
    if (isulad_level == NULL) {
        goto out;
    }

    for (i = 0; i < LOG_LEVEL_MAX; i++) {
        if (strcasecmp(log_level_name[i], isulad_level) == 0) {
            adapted_level = isulad_level;
            isulad_level = NULL;
            break;
        }
    }

out:
    if (adapted_level == NULL) {
        adapted_level = util_strdup_s("INFO");
    }
    free(isulad_level);
    return adapted_level;
}

static void pack_global_log_level(const char * const *options, char *params[], size_t *count)
{
    char *level = NULL;
    size_t i = 0;

    i = *count;

    level = adapt_log_level();
    add_array_kv(params, PARAM_NUM, &i, options[GB_OPTION_LOG_LEVEL], level);

    *count = i;

    free(level);
}

static int pack_global_graph_registry(const char * const *options, char *params[], size_t *count)
{
    int ret = -1;
    size_t i = 0;
    char **registry = NULL;
    char **insecure_registry = NULL;
    char **p = NULL;

    i = *count;

    registry = conf_get_registry_list();
    for (p = registry; (p != NULL) && (*p != NULL); p++) {
        add_array_kv(params, PARAM_NUM, &i, options[GB_OPTION_REGISTRY], *p);
    }

    insecure_registry = conf_get_insecure_registry_list();
    for (p = insecure_registry; (p != NULL) && (*p != NULL); p++) {
        add_array_kv(params, PARAM_NUM, &i, options[GB_OPTION_INSEC_REGISTRY], *p);
    }

    ret = 0;
    *count = i;

    util_free_array(registry);
    util_free_array(insecure_registry);
    return ret;
}

static int pack_global_opt_time(const char * const *options, char *params[], size_t *count)
{
    int ret = -1;
    size_t i = 0;
    unsigned int opt_timeout = 0;
    char timeout_str[UINT_LEN + 2] = { 0 }; /* format: XXXs */

    i = *count;

    opt_timeout = conf_get_im_opt_timeout();
    if (opt_timeout != 0) {
        add_array_elem(params, PARAM_NUM, &i, options[GB_OPTION_OPT_TIMEOUT]);
        int nret = snprintf(timeout_str, UINT_LEN + 2, "%us", opt_timeout);
        if (nret < 0 || (size_t)nret >= (UINT_LEN + 2)) {
            COMMAND_ERROR("Failed to print string");
            goto out;
        }
        add_array_elem(params, PARAM_NUM, &i, timeout_str);
    }

    ret = 0;
    *count = i;
out:
    return ret;
}

static inline bool invalid_pack_global_options_args(const char * const *options, char * const *params,
                                                    const size_t *count)
{
    if (options == NULL || params == NULL || count == NULL) {
        return true;
    }
    return false;
}

int pack_global_options(const char * const *options, char *params[], size_t *count, bool ignore_storage_opt_size)
{
    int ret = -1;
    size_t i = 0;

    if (invalid_pack_global_options_args(options, params, count)) {
        ERROR("Invalid global options arguments");
        return -1;
    }

    i = *count;

#ifdef ENABLE_OCI_IMAGE
    if (pack_global_graph_driver(options, ignore_storage_opt_size, params, &i) != 0) {
        goto out;
    }
#endif

    if (pack_global_graph_registry(options, params, &i) != 0) {
        goto out;
    }

    if (pack_global_opt_time(options, params, &i) != 0) {
        goto out;
    }

    pack_global_log_level(options, params, &i);

    ret = 0;
    *count = i;

out:
    return ret;
}
