/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide command functions
 ******************************************************************************/

#define _GNU_SOURCE
#include "command_parser.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <regex.h>
#include <limits.h>
#include "constants.h"

#include "utils.h"
#include "isula_libutils/log.h"

void command_help_isulad_head()
{
    fprintf(stdout, "isulad\n\nlightweight container runtime daemon\n");
}

int compare_options(const void *s1, const void *s2)
{
    return strcmp((*(const command_option_t *)s1).large, (*(const command_option_t *)s2).large);
}
void print_options(int options_len, const command_option_t *options)
{
    int i = 0;
    int max_opt_len = 0;

    for (i = 0; i < options_len; i++) {
        command_option_t option = options[i];
        // -s
        int len = 2;
        // -s, --large, 6 is the length of "-s, --".
        if (option.large != NULL) {
            len = (int)(strlen(option.large) + 6);
        }
        if (len > max_opt_len) {
            max_opt_len = len;
        }
    }

    // format: "  -s, --large    description"
    // 6 is the total length of black before "-s" and "description"
    max_opt_len += 6;

    for (i = 0; i < options_len; i++) {
        command_option_t option = options[i];
        int curindex = 0;
        int space_left = 0;

        curindex = fprintf(stdout, "  ");
        if (option.small) {
            curindex += fprintf(stdout, "-%c", (char)option.small);
        }

        if (option.large != NULL) {
            if (option.small) {
                curindex += fprintf(stdout, ", --%s", option.large);
            } else {
                curindex += fprintf(stdout, "    --%s", option.large);
            }
        }

        if (curindex <= max_opt_len) {
            space_left = max_opt_len - curindex;
        }

        fprintf(stdout, "%*s%s\n", space_left, "", option.description);
    }
    fputc('\n', stdout);
}

void command_help(command_t *self)
{
    const char *progname = strrchr(self->name, '/');
    if (progname == NULL) {
        progname = self->name;
    } else {
        progname++;
    }

    if (self->type != NULL && strcmp(self->type, "isulad") == 0) {
        command_help_isulad_head();
    }
    fprintf(stdout, "\nUsage:  %s %s\n\n", progname, self->usage);
    fprintf(stdout, "%s\n\n", self->description);
    qsort(self->options, (size_t)self->option_count, sizeof(self->options[0]), compare_options);
    print_options(self->option_count, self->options);
}

int command_valid_socket(command_option_t *option, const char *arg)
{
    if (!util_validate_socket(arg)) {
        COMMAND_ERROR("Invalid socket name : %s", arg);
        return -1;
    }
    return 0;
}

void command_init(command_t *self, command_option_t *opts, int opts_len, int argc, const char **argv,
                  const char *description, const char *usage)
{
    (void)memset(self, 0, sizeof(command_t));
    self->name = argv[0];
    self->argc = argc - 2;
    self->argv = argv + 2;
    self->usage = usage;
    self->description = description;
    self->options = opts;
    self->option_count = opts_len;
}

void command_option(command_t *self, command_option_type_t type, void *data, int small, const char *large,
                    const char *desc, command_callback_t cb)
{
    if (self->option_count == COMMANDER_MAX_OPTIONS) {
        COMMAND_ERROR("Maximum option definitions exceeded");
        exit(EINVALIDARGS);
    }
    int n = self->option_count++;
    command_option_t *opt = &self->options[n];
    opt->type = type;
    opt->data = data;
    opt->cb = cb;
    opt->small = small;
    opt->description = desc;
    opt->large = large;
}

static int read_option_arg(command_t *self, command_option_t *opt, const char **opt_arg, const char **readed)
{
    if (self == NULL || opt == NULL || opt_arg == NULL) {
        return -1;
    }
    if (opt->hasdata) {
        *readed = *opt_arg;
        *opt_arg = NULL;
    }
    if (!opt->hasdata && self->argc > 1) {
        opt->hasdata = true;
        *readed = *++self->argv;
        self->argc--;
    }
    if (!opt->hasdata) {
        COMMAND_ERROR("Flag needs an argument: --%s", opt->large);
        return -1;
    }
    return 0;
}

static int command_get_bool_option_data(command_option_t *option, const char **opt_arg)
{
    bool converted_bool = (option->type == CMD_OPT_TYPE_BOOL) ? true : false;

    if (option->hasdata) {
        int ret = util_str_to_bool(*opt_arg, &converted_bool);
        if (ret != 0) {
            COMMAND_ERROR("Invalid boolean value \"%s\" for flag --%s", *opt_arg, option->large);
            return -1;
        }
        *opt_arg = NULL;
    }

    *(bool *)option->data = converted_bool;

    return 0;
}

static int command_get_string_option_data(command_t *self, command_option_t *option, const char **opt_arg)
{
    if (read_option_arg(self, option, opt_arg, (const char **)option->data)) {
        return -1;
    }
    if (option->cb != NULL) {
        return option->cb(option, *(char **)option->data);
    }
    return 0;
}

static int command_get_string_dup_option_data(command_t *self, command_option_t *option, const char **opt_arg)
{
    const char *readed_item = NULL;

    if (read_option_arg(self, option, opt_arg, &readed_item) != 0) {
        return -1;
    }
    if (*(char **)option->data != NULL) {
        free(*(char **)option->data);
    }
    *(char **)option->data = util_strdup_s(readed_item);
    if (option->cb != NULL) {
        return option->cb(option, readed_item);
    }
    return 0;
}

static int command_get_callback_option_data(command_t *self, command_option_t *option, const char **opt_arg)
{
    const char *readed_item = NULL;

    if (read_option_arg(self, option, opt_arg, &readed_item)) {
        return -1;
    }
    if (option->cb == NULL) {
        COMMAND_ERROR("Must specify callback for type array");
        return -1;
    }
    return option->cb(option, readed_item);
}

static int command_get_option_data(command_t *self, command_option_t *option, const char **opt_arg)
{
    if (option == NULL) {
        return -1;
    }
    switch (option->type) {
        case CMD_OPT_TYPE_BOOL:
        case CMD_OPT_TYPE_BOOL_FALSE:
            return command_get_bool_option_data(option, opt_arg);
        case CMD_OPT_TYPE_STRING:
            return command_get_string_option_data(self, option, opt_arg);
        case CMD_OPT_TYPE_STRING_DUP:
            return command_get_string_dup_option_data(self, option, opt_arg);
        case CMD_OPT_TYPE_CALLBACK:
            return command_get_callback_option_data(self, option, opt_arg);
        default:
            COMMAND_ERROR("Unkown command option type:%d", (int)(option->type));
            return -1;
    }
}

int have_short_options(command_t *self, char arg)
{
    int i;

    for (i = 0; i < self->option_count; i++) {
        if (self->options[i].small == arg) {
            return 0;
        }
    }

    return -1;
}

static int command_parse_options(command_t *self, const char **opt_arg, bool *found)
{
    int j = 0;

    for (j = 0; j < self->option_count; ++j) {
        command_option_t *opt = &self->options[j];
        opt->hasdata = false;
        if (opt->small != (*opt_arg)[0]) {
            continue;
        }
        // match flag
        *found = true;
        if ((*opt_arg)[1]) {
            if ((*opt_arg)[1] == '=') {
                *opt_arg = *opt_arg + 2;
                opt->hasdata = true;
            } else {
                *opt_arg = *opt_arg + 1;
            }
        } else {
            *opt_arg = NULL;
        }
        if (command_get_option_data(self, opt, opt_arg)) {
            return -1;
        }
        break;
    }

    return 0;
}

static int command_parse_short_arg(command_t *self, const char *arg)
{
    bool found = false;
    const char *opt_arg = arg;

    do {
        found = false;
        if (command_parse_options(self, &opt_arg, &found)) {
            return -1;
        }
    } while (found && opt_arg != NULL);

    if (opt_arg != NULL) {
        COMMAND_ERROR("Unkown flag found:'%c'", opt_arg[0]);
        exit(EINVALIDARGS);
    }
    return 0;
}

static int command_parse_long_arg(command_t *self, const char *arg)
{
    int j = 0;

    if (strcmp(arg, "help") == 0) {
        command_help(self);
        exit(0);
    }

    for (j = 0; j < self->option_count; ++j) {
        command_option_t *opt = &self->options[j];
        const char *opt_arg = NULL;
        opt->hasdata = false;

        if (opt->large == NULL) {
            continue;
        }

        opt_arg = str_skip_str(arg, opt->large);
        if (opt_arg == NULL) {
            continue;
        }

        if (opt_arg[0]) {
            if (opt_arg[0] != '=') {
                continue;
            }
            opt_arg = opt_arg + 1;
            opt->hasdata = true;
        } else {
            opt_arg = NULL;
        }
        if (command_get_option_data(self, opt, &opt_arg)) {
            return -1;
        }
        return 0;
    }
    COMMAND_ERROR("Unkown flag found:'--%s'\n", arg);
    exit(EINVALIDARGS);
}

int command_parse_args(command_t *self, int *argc, char * const **argv)
{
    int ret = 0;

    for (; self->argc; self->argc--, self->argv++) {
        const char *arg_opt = self->argv[0];
        if (arg_opt[0] != '-' || !arg_opt[1]) {
            break;
        }

        // short option
        if (arg_opt[1] != '-') {
            arg_opt = arg_opt + 1;
            ret = command_parse_short_arg(self, arg_opt);
            if (!ret) {
                continue;
            }
            break;
        }

        // --
        if (!arg_opt[2]) {
            self->argc--;
            self->argv++;
            break;
        }

        // long option
        arg_opt = arg_opt + 2;
        ret = command_parse_long_arg(self, arg_opt);
        if (ret == 0) {
            continue;
        }
        break;
    }
    if (self->argc > 0) {
        *argc = self->argc;
        *argv = (char * const *)self->argv;
    }
    return ret;
}

int command_valid_socket_append_array(command_option_t *option, const char *arg)
{
    int len;
    char **pos = NULL;

    if (option == NULL) {
        return -1;
    }
    if (!util_validate_socket(arg)) {
        COMMAND_ERROR("Invalid socket name : %s", arg);
        return -1;
    }

    for (pos = *(char ***)(option->data), len = 0; pos != NULL && *pos != NULL; pos++, len++) {
        if (strcmp(*pos, arg) == 0) {
            break;
        }
    }
    if (pos != NULL && *pos != NULL) {
        return 0;
    }

    if (util_array_append(option->data, arg) != 0) {
        ERROR("merge hosts config failed");
        return -1;
    }
    len++;
    if (len > MAX_HOSTS) {
        COMMAND_ERROR("Too many hosts, the max number is %d", MAX_HOSTS);
        return -1;
    }

    return 0;
}

static int check_default_ulimit_input(const char *val)
{
    int ret = 0;
    if (val == NULL || strcmp(val, "") == 0) {
        COMMAND_ERROR("ulimit argument can't be empty");
        ret = -1;
        goto out;
    }

    if (val[0] == '=' || val[strlen(val) - 1] == '=') {
        COMMAND_ERROR("Invalid ulimit argument: \"%s\", delimiter '=' can't"
                      " be the first or the last character",
                      val);
        ret = -1;
    }

out:
    return ret;
}

static void get_default_ulimit_split_parts(const char *val, char ***parts, size_t *parts_len, char deli)
{
    *parts = util_string_split_multi(val, deli);
    if (*parts == NULL) {
        ERROR("Out of memory");
        return;
    }
    *parts_len = util_array_len((const char **)(*parts));
}

static int parse_soft_hard_default_ulimit(const char *val, char **limitvals, size_t limitvals_len, int64_t *soft,
                                          int64_t *hard)
{
    int ret = 0;
    // parse soft
    ret = util_safe_llong(limitvals[0], (long long *)soft);
    if (ret < 0) {
        COMMAND_ERROR("Invalid ulimit soft value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
        ret = -1;
        goto out;
    }

    // parse hard if exists
    if (limitvals_len > 1) {
        ret = util_safe_llong(limitvals[1], (long long *)hard);
        if (ret < 0) {
            COMMAND_ERROR("Invalid ulimit hard value: \"%s\", parse int64 failed: %s", val, strerror(-ret));
            ret = -1;
            goto out;
        }

        if (*soft > *hard) {
            COMMAND_ERROR("Ulimit soft limit must be less than or equal to hard limit: %lld > %lld",
                          (long long int)(*soft), (long long int)(*hard));
            ret = -1;
            goto out;
        }
    } else {
        *hard = *soft; // default to soft in case no hard was set
    }
out:
    return ret;
}

int check_default_ulimit_type(const char *type)
{
    int ret = 0;
    char **tmptype = NULL;
    char *ulimit_valid_type[] = {
        // "as", // Disabled since this doesn't seem usable with the way Docker inits a container.
        "core",   "cpu",   "data", "fsize",  "locks",  "memlock",    "msgqueue", "nice",
        "nofile", "nproc", "rss",  "rtprio", "rttime", "sigpending", "stack",    NULL
    };

    for (tmptype = ulimit_valid_type; *tmptype != NULL; tmptype++) {
        if (strcmp(type, *tmptype) == 0) {
            break;
        }
    }

    if (*tmptype == NULL) {
        COMMAND_ERROR("Invalid ulimit type: %s", type);
        ret = -1;
    }
    return ret;
}

static host_config_ulimits_element *parse_default_ulimit(const char *val)
{
    int ret = 0;
    int64_t soft = 0;
    int64_t hard = 0;
    size_t parts_len = 0;
    size_t limitvals_len = 0;
    char **parts = NULL;
    char **limitvals = NULL;
    host_config_ulimits_element *ulimit = NULL;

    ret = check_default_ulimit_input(val);
    if (ret != 0) {
        return NULL;
    }

    get_default_ulimit_split_parts(val, &parts, &parts_len, '=');
    if (parts == NULL) {
        ERROR("Out of memory");
        return NULL;
    } else if (parts_len != 2) {
        COMMAND_ERROR("Invalid ulimit argument: %s", val);
        ret = -1;
        goto out;
    }

    ret = check_default_ulimit_type(parts[0]);
    if (ret != 0) {
        ret = -1;
        goto out;
    }

    if (parts[1][0] == ':' || parts[1][strlen(parts[1]) - 1] == ':') {
        COMMAND_ERROR("Invalid ulimit value: \"%s\", delimiter ':' can't be the first"
                      " or the last character",
                      val);
        ret = -1;
        goto out;
    }

    // parse value
    get_default_ulimit_split_parts(parts[1], &limitvals, &limitvals_len, ':');
    if (limitvals == NULL) {
        ret = -1;
        goto out;
    }

    if (limitvals_len > 2) {
        COMMAND_ERROR("Too many limit value arguments - %s, can only have up to two, `soft[:hard]`", parts[1]);
        ret = -1;
        goto out;
    }

    ret = parse_soft_hard_default_ulimit(val, limitvals, limitvals_len, &soft, &hard);
    if (ret < 0) {
        goto out;
    }

    ulimit = util_common_calloc_s(sizeof(host_config_ulimits_element));
    if (ulimit == NULL) {
        ret = -1;
        goto out;
    }
    ulimit->name = util_strdup_s(parts[0]);
    ulimit->hard = hard;
    ulimit->soft = soft;

out:
    util_free_array(parts);
    util_free_array(limitvals);
    if (ret != 0) {
        free_host_config_ulimits_element(ulimit);
        ulimit = NULL;
    }

    return ulimit;
}

int command_default_ulimit_append(command_option_t *option, const char *arg)
{
    int ret = 0;
    size_t ulimit_len;
    host_config_ulimits_element *tmp = NULL;
    host_config_ulimits_element **pos = NULL;

    if (option == NULL) {
        ret = -1;
        goto out;
    }

    tmp = parse_default_ulimit(arg);
    if (tmp == NULL) {
        ERROR("parse default ulimit from arg failed");
        ret = -1;
        goto out;
    }

    for (pos = *(host_config_ulimits_element ***)(option->data); pos != NULL && *pos != NULL; pos++) {
        if (strcmp((*pos)->name, tmp->name) == 0) {
            break;
        }
    }
    if (pos != NULL && *pos != NULL) {
        (*pos)->hard = tmp->hard;
        (*pos)->soft = tmp->soft;
        goto out;
    }

    ulimit_len = ulimit_array_len(*(host_config_ulimits_element ***)(option->data));
    if (ulimit_array_append(option->data, tmp, ulimit_len) != 0) {
        ERROR("default ulimit append failed");
        ret = -1;
    }

out:
    free_host_config_ulimits_element(tmp);
    return ret;
}

int command_append_array(command_option_t *option, const char *arg)
{
    if (option == NULL) {
        return -1;
    }
    char ***array = option->data;
    return util_array_append(array, arg);
}

int command_convert_u16(command_option_t *option, const char *arg)
{
    int ret = 0;

    if (option == NULL) {
        return -1;
    }
    ret = util_safe_u16(arg, option->data);
    if (ret != 0) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s: %s", arg, option->large, strerror(-ret));
        return EINVALIDARGS;
    }
    return 0;
}

int command_convert_llong(command_option_t *opt, const char *arg)
{
    int ret;

    if (opt == NULL) {
        return -1;
    }
    ret = util_safe_llong(arg, opt->data);
    if (ret != 0) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s: %s", arg, opt->large, strerror(-ret));
        return EINVALIDARGS;
    }
    return 0;
}

int command_convert_uint(command_option_t *opt, const char *arg)
{
    int ret;
    if (opt == NULL) {
        return -1;
    }
    ret = util_safe_uint(arg, opt->data);
    if (ret != 0) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s: %s", arg, opt->large, strerror(-ret));
        return EINVALIDARGS;
    }
    return 0;
}

int command_convert_int(command_option_t *option, const char *arg)
{
    int ret = 0;

    if (option == NULL) {
        return -1;
    }
    ret = util_safe_int(arg, option->data);
    if (ret != 0) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s: %s", arg, option->large, strerror(-ret));
        return EINVALIDARGS;
    }
    return 0;
}

int command_convert_nanoseconds(command_option_t *option, const char *arg)
{
    if (option == NULL) {
        return -1;
    }
    if (util_parse_time_str_to_nanoseconds(arg, option->data)) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s", arg, option->large);
        return EINVALIDARGS;
    }
    return 0;
}

int command_convert_membytes(command_option_t *option, const char *arg)
{
    if (option == NULL) {
        return -1;
    }
    if (util_parse_byte_size_string(arg, option->data) || (*(int64_t *)(option->data)) < 0) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s", arg, option->large);
        return EINVALIDARGS;
    }
    return 0;
}

int command_convert_memswapbytes(command_option_t *option, const char *arg)
{
    if (option == NULL) {
        return -1;
    }
    if (strcmp(arg, "-1") == 0) {
        *(int64_t *)(option->data) = -1;
        return 0;
    }
    if (command_convert_membytes(option, arg)) {
        return EINVALIDARGS;
    }
    return 0;
}

int command_convert_swappiness(command_option_t *option, const char *arg)
{
    if (option == NULL) {
        return -1;
    }
    if (strcmp(arg, "-1") == 0) {
        *(int64_t *)(option->data) = -1;
        return 0;
    }
    if (util_parse_byte_size_string(arg, option->data) || (*(int64_t *)(option->data)) < 0 ||
        (*(int64_t *)(option->data)) > 100) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s. Valid memory swappiness range is 0-100", arg, option->large);
        return EINVALIDARGS;
    }
    return 0;
}

size_t ulimit_array_len(host_config_ulimits_element **default_ulimit)
{
    size_t len = 0;
    host_config_ulimits_element **pos = NULL;

    for (pos = default_ulimit; pos != NULL && *pos != NULL; pos++) {
        len++;
    }

    return len;
}

int ulimit_array_append(host_config_ulimits_element ***ulimit_array, const host_config_ulimits_element *element,
                        const size_t len)
{
    int ret;
    size_t old_size, new_size;
    host_config_ulimits_element *new_element = NULL;
    host_config_ulimits_element **new_ulimit_array = NULL;

    if (ulimit_array == NULL || element == NULL) {
        return -1;
    }

    // let new len to len + 2 for element and null
    if (len > SIZE_MAX / sizeof(host_config_ulimits_element *) - 2) {
        ERROR("Too many ulimit elements!");
        return -1;
    }

    new_size = (len + 2) * sizeof(host_config_ulimits_element *);
    old_size = len * sizeof(host_config_ulimits_element *);

    ret = mem_realloc((void **)(&new_ulimit_array), new_size, (void *)*ulimit_array, old_size);
    if (ret != 0) {
        ERROR("Failed to realloc memory for append ulimit");
        return -1;
    }
    *ulimit_array = new_ulimit_array;

    new_element = util_common_calloc_s(sizeof(host_config_ulimits_element));
    if (new_element == NULL) {
        ERROR("Out of memory");
        free_default_ulimit(*ulimit_array);
        *ulimit_array = NULL;
        return -1;
    }

    new_element->name = util_strdup_s(element->name);
    new_element->hard = element->hard;
    new_element->soft = element->soft;
    new_ulimit_array[len] = new_element;

    return 0;
}

void free_default_ulimit(host_config_ulimits_element **default_ulimit)
{
    host_config_ulimits_element **p = NULL;

    for (p = default_ulimit; p != NULL && *p != NULL; p++) {
        free_host_config_ulimits_element(*p);
    }
    free(default_ulimit);
}
