/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2019. All rights reserved.
 * clibcni licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2019-04-25
 * Description: provide conf functions
 *********************************************************************************/
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "libcni_conf.h"

#include <linux/limits.h>
#include <dirent.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>

#include "utils.h"
#include "isula_libutils/log.h"
#include "isula_libutils/cni_net_conf.h"
#include "isula_libutils/cni_net_conf_list.h"
#include "libcni_api.h"


static int do_conf_from_bytes(const char *conf_str, struct network_config *config)
{
    int ret = 0;
    parser_error jerr = NULL;
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };

    config->network = cni_net_conf_parse_data(conf_str, &ctx, &jerr);
    if (config->network == NULL) {
        ERROR("Error parsing configuration: %s", jerr);
        ret = -1;
        goto out;
    }
    if (config->network->type == NULL || strlen(config->network->type) == 0) {
        ERROR("error parsing configuration: missing 'type'");
        ret = -1;
        goto out;
    }

    config->bytes = util_strdup_s(conf_str);
out:
    free(jerr);
    return ret;
}

int conf_from_bytes(const char *conf_str, struct network_config **config)
{
    int ret = -1;

    if (config == NULL) {
        ERROR("Invalid arguments");
        return ret;
    }
    if (conf_str == NULL) {
        ERROR("Empty json");
        return ret;
    }
    *config = util_common_calloc_s(sizeof(struct network_config));
    if (*config == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    ret = do_conf_from_bytes(conf_str, *config);
free_out:
    if (ret != 0) {
        free_network_config(*config);
        *config = NULL;
    }
    return ret;
}

static char *do_get_cni_net_confs_json(const char *filename)
{
    char *content = NULL;

    content = util_read_text_file(filename);
    if (content == NULL) {
        ERROR("Read file %s failed: %s", filename, strerror(errno));
    }

    return content;
}

static inline bool check_conf_from_file_args(const char *filename, struct network_config * const *config)
{
    return (filename == NULL || config == NULL);
}

int conf_from_file(const char *filename, struct network_config **config)
{
    char *content = NULL;
    int ret = -1;

    if (check_conf_from_file_args(filename, config)) {
        ERROR("Invalid arguments");
        return -1;
    }
    content = do_get_cni_net_confs_json(filename);
    if (content == NULL) {
        ERROR("Parse net conf file: %s failed", filename);
        ret = -1;
        goto free_out;
    }

    ret = conf_from_bytes(content, config);
free_out:
    free(content);
    return ret;
}

static int do_check_cni_net_conf_list_plugins(const cni_net_conf_list *tmp_list)
{
    size_t i = 0;

    if (tmp_list->plugins == NULL) {
        ERROR("Error parsing configuration list: no 'plugins' key");
        return -1;
    }
    if (tmp_list->plugins_len == 0) {
        ERROR("Error parsing configuration list: no plugins in list");
        return -1;
    }
    for (i = 0; i < tmp_list->plugins_len; i++) {
        if (tmp_list->plugins[i]->type == NULL || strlen(tmp_list->plugins[i]->type) == 0) {
            ERROR("failed to parse plugin config: %zd, name: %s", i, tmp_list->plugins[i]->name);
            return -1;
        }
    }
    return 0;
}

static int check_cni_net_conf_list(const cni_net_conf_list *tmp_list)
{
    if (tmp_list->name == NULL) {
        ERROR("Name is NULL");
        return -1;
    }

    return do_check_cni_net_conf_list_plugins(tmp_list);
}

int conflist_from_bytes(const char *json_str, struct network_config_list **list)
{
    int ret = -1;
    parser_error jerr = NULL;
    cni_net_conf_list *tmp_list = NULL;
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };

    if (list == NULL) {
        ERROR("Invalid arguments");
        return ret;
    }
    if (json_str == NULL) {
        ERROR("Empty json");
        return -1;
    }
    *list = util_common_calloc_s(sizeof(struct network_config_list));
    if (*list == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    tmp_list = cni_net_conf_list_parse_data(json_str, &ctx, &jerr);
    if (tmp_list == NULL) {
        ERROR("Error parsing configuration list: %s", jerr);
        ret = -1;
        goto free_out;
    }

    ret = check_cni_net_conf_list(tmp_list);
    if (ret != 0) {
        goto free_out;
    }

    (*list)->bytes = util_strdup_s(json_str);
    (*list)->list = tmp_list;

    ret = 0;
free_out:
    free(jerr);
    if (ret != 0) {
        free_cni_net_conf_list(tmp_list);
        free_network_config_list(*list);
        *list = NULL;
    }
    return ret;
}

static inline bool check_conflist_from_file_args(const char *filename, struct network_config_list * const *list)
{
    return (filename == NULL || list == NULL);
}

int conflist_from_file(const char *filename, struct network_config_list **list)
{
    char *content = NULL;
    int ret = -1;

    if (check_conflist_from_file_args(filename, list)) {
        ERROR("Invalid arguments");
        return -1;
    }
    content = do_get_cni_net_confs_json(filename);
    if (content == NULL) {
        ERROR("Parse net conf file: %s failed", filename);
        ret = -1;
        goto free_out;
    }

    ret = conflist_from_bytes(content, list);
free_out:
    free(content);
    return ret;
}

static int get_ext(const char *fname)
{
    int i = 0;
    int ret = -1;

    if (fname == NULL) {
        ERROR("File is NULL");
        return -1;
    }
    for (i = (int)strlen(fname) - 1; i >= 0; i--) {
        if (fname[i] == '/') {
            break;
        }
        if (fname[i] == '.') {
            ret = i;
            break;
        }
    }

    return ret;
}

/*
 * return 1: check dir success
 * return 0: dir do not exist
 * return -1: check dir failed
 * */
static int check_conf_dir(const char *dir)
{
    DIR *directory = NULL;
    int ret = 1;

    directory = opendir(dir);
    if (directory == NULL) {
        if (errno == ENOENT) {
            ret = 0;
            goto out;
        }
        SYSERROR("Open dir failed");
        ret = -1;
    }
out:
    closedir(directory);
    return ret;
}

static int do_check_file_is_valid(const char *fname)
{
    struct stat tmp_fstat;
    int nret = -1;

    nret = lstat(fname, &tmp_fstat);
    if (nret != 0) {
        SYSERROR("lstat %s failed", fname);
        return -1;
    }

    if (S_ISDIR(tmp_fstat.st_mode)) {
        ERROR("conf file %s is dir", fname);
        return -1;
    }

    if (tmp_fstat.st_size > SIZE_MB) {
        ERROR("Too large config file: %s", fname);
        return -1;
    }

    return 0;
}

struct search_cb_args {
    const char * const *extensions;
    size_t ext_len;
    char ***result;
    size_t result_len;
};

static bool search_conf_files_cb(const char *dir, const struct dirent *pdirent, void *context)
{
#define MAX_FILES 200
    struct search_cb_args *args = (struct search_cb_args *)context;
    char fname[PATH_MAX] = { 0 };
    size_t i = 0;
    const char *ext_name = NULL;
    int nret = -1;

    if (args->result_len > MAX_FILES) {
        ERROR("Too more config files, current support max count of config file is %d, so just ignore others.", MAX_FILES);
        return false;
    }

    nret = snprintf(fname, PATH_MAX, "%s/%s", dir, pdirent->d_name);
    if (nret < 0 || nret >= PATH_MAX) {
        ERROR("Pathname too long");
        return false;
    }

    nret = do_check_file_is_valid(fname);
    if (nret != 0) {
        // ignore invalid file
        return true;
    }

    /* compare extension */
    nret = get_ext(pdirent->d_name);
    if (nret < 0) {
        // ignore this error
        return true;
    }
    ext_name = (pdirent->d_name) + nret;
    for (i = 0; i < args->ext_len; i++) {
        if (args->extensions[i] != NULL && strcmp(ext_name, args->extensions[i]) == 0) {
            if (util_array_append(args->result, fname) != 0) {
                ERROR("Out of memory");
                return false;
            }
            args->result_len += 1;
            break;
        }
    }

    return true;
}

static inline bool check_conf_files_args(const char *dir, const char * const *extensions, char ** const *result)
{
    return (dir == NULL || extensions == NULL || result == NULL);
}

int conf_files(const char *dir, const char * const *extensions, size_t ext_len, char ***result)
{
    int ret = -1;
    int nret = -1;
    struct search_cb_args s_args = { 0 };

    if (check_conf_files_args(dir, extensions, result)) {
        ERROR("Invalid arguments");
        return -1;
    }
    nret = check_conf_dir(dir);
    if (nret != 1) {
        /* dir is not exist, just ignore, do not return error */
        return 0;
    }

    s_args.extensions = extensions;
    s_args.ext_len = ext_len;
    s_args.result = result;
    nret = util_scan_subdirs(dir, search_conf_files_cb, &s_args);
    if (nret != 0) {
        ret = -1;
        goto free_out;
    }

    ret = 0;
free_out:
    if (ret != 0) {
        util_free_array(*result);
        *result = NULL;
    }
    return ret;
}

int cmpstr(const void *a, const void *b)
{
    return strcmp(*((const char **)a), *((const char **)b));
}

static inline bool check_load_conf_args(const char *dir, const char *name, struct network_config * const *conf)

{
    return (dir == NULL || name == NULL || conf == NULL);
}

int load_conf(const char *dir, const char *name, struct network_config **conf)
{
    char **files = NULL;
    const char *exts[] = { ".conf", ".json" };
    int ret = 0;
    size_t len = 0;
    size_t i = 0;

    if (check_load_conf_args(dir, name, conf)) {
        ERROR("Invalid arguments");
        return -1;
    }

    ret = conf_files(dir, exts, sizeof(exts) / sizeof(char *), &files);
    if (ret != 0) {
        return -1;
    }
    len = util_array_len((const char **)files);
    if (len == 0) {
        WARN("no net configurations found in %s", dir);
        goto free_out;
    }

    qsort((void *)files, len, sizeof(char *), cmpstr);

    for (i = 0; i < len; i++) {
        ret = conf_from_file(files[i], conf);
        if (ret != 0) {
            goto free_out;
        }
        if (((*conf)->network->name) != NULL && strcmp((*conf)->network->name, name) == 0) {
            ret = 0;
            goto free_out;
        }
        free_network_config(*conf);
        *conf = NULL;
    }
    ERROR("No net configuration with name \"%s\" in %s", name, dir);
    ret = -1;

free_out:
    util_free_array(files);
    return ret;
}

static int generate_new_conflist(const cni_net_conf_list *list, struct network_config_list **conf_list)
{
    struct parser_context ctx = { OPT_PARSE_FULLKEY | OPT_GEN_SIMPLIFY, 0 };
    parser_error jerr = NULL;
    char *cni_net_conf_json_str = NULL;
    int ret = -1;

    cni_net_conf_json_str = cni_net_conf_list_generate_json(list, &ctx, &jerr);
    if (cni_net_conf_json_str == NULL) {
        ERROR("Generate conf list json failed: %s", jerr);
        goto free_out;
    }
    (*conf_list)->bytes = cni_net_conf_json_str;

    free(jerr);
    jerr = NULL;
    (*conf_list)->list = cni_net_conf_list_parse_data(cni_net_conf_json_str, &ctx, &jerr);
    if ((*conf_list)->list == NULL) {
        ERROR("Parse conf list from json failed: %s", jerr);
        goto free_out;
    }
    ret = 0;
free_out:
    free(jerr);
    return ret;
}

static inline bool check_conflist_from_conf_args(const struct network_config *conf,
                                                 struct network_config_list * const *conf_list)
{
    return (conf == NULL || conf->network == NULL || conf_list == NULL);
}

int conflist_from_conf(const struct network_config *conf, struct network_config_list **conf_list)
{
    int ret = -1;
    cni_net_conf_list *list = NULL;

    if (check_conflist_from_conf_args(conf, conf_list)) {
        ERROR("Invalid arguments");
        return -1;
    }
    *conf_list = util_common_calloc_s(sizeof(struct network_config_list));
    if (*conf_list == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    list = util_common_calloc_s(sizeof(cni_net_conf_list));
    if (list == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    list->plugins = util_common_calloc_s(sizeof(cni_net_conf *) * (1 + 1));
    if (list->plugins == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }
    // do not copy network, just use, so need clear after use;
    list->plugins[0] = conf->network;
    list->plugins_len = 1;

    list->name = util_strdup_s(conf->network->name);
    list->cni_version = util_strdup_s(conf->network->cni_version);

    ret = generate_new_conflist(list, conf_list);

    // clear used network
    list->plugins_len = 0;
    list->plugins[0] = NULL;
free_out:
    free_cni_net_conf_list(list);

    if (ret != 0) {
        free_network_config_list(*conf_list);
        *conf_list = NULL;
    }
    return ret;
}

void free_network_config(struct network_config *config)
{
    if (config != NULL) {
        free_cni_net_conf(config->network);
        config->network = NULL;
        free(config->bytes);
        config->bytes = NULL;
        free(config);
    }
}

void free_network_config_list(struct network_config_list *conf_list)
{
    if (conf_list != NULL) {
        free_cni_net_conf_list(conf_list->list);
        conf_list->list = NULL;
        free(conf_list->bytes);
        conf_list->bytes = NULL;
        free(conf_list);
    }
}

