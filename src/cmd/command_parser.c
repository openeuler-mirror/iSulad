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
#include <regex.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "constants.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_string.h"
#include "utils_verify.h"
#include "utils_timestamp.h"

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
        const command_option_t *option = &(options[i]);
        // -s
        int len = 2;
        // -s, --large, 6 is the length of "-s, --".
        if (option->large != NULL) {
            len = (int)(strlen(option->large) + 6);
        }
        if (len > max_opt_len) {
            max_opt_len = len;
        }
    }

    // format: "  -s, --large    description"
    // 6 is the total length of black before "-s" and "description"
    max_opt_len += 6;

    for (i = 0; i < options_len; i++) {
        const command_option_t *option = &(options[i]);
        int curindex = 0;
        int space_left = 0;

        curindex = fprintf(stdout, "  ");
        if (option->small) {
            curindex += fprintf(stdout, "-%c", (char)option->small);
        }

        if (option->large != NULL) {
            if (option->small) {
                curindex += fprintf(stdout, ", --%s", option->large);
            } else {
                curindex += fprintf(stdout, "    --%s", option->large);
            }
        }

        if (curindex <= max_opt_len) {
            space_left = max_opt_len - curindex;
        }

        fprintf(stdout, "%*s%s\n", space_left, "", option->description);
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

void subcommand_init(command_t *self, command_option_t *opts, int opts_len, int argc, const char **argv,
                     const char *description, const char *usage)
{
    (void)memset(self, 0, sizeof(command_t));
    self->name = util_string_join(" ", argv, 2);
    self->argc = argc - 3;
    self->argv = argv + 3;
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
            COMMAND_ERROR("Unknown command option type:%d", (int)(option->type));
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
        COMMAND_ERROR("Unknown flag found:'%c'", opt_arg[0]);
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

        opt_arg = util_str_skip_str(arg, opt->large);
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
        if (strcmp(opt->large, "help") == 0 && *(bool *)opt->data) {
            command_help(self);
            exit(0);
        }
        return 0;
    }
    COMMAND_ERROR("Unknown flag found:'--%s'\n", arg);
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
    if (util_time_str_to_nanoseconds(arg, option->data)) {
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

int command_convert_nanocpus(command_option_t *option, const char *arg)
{
    int ret = 0;
    char *dup = NULL;

    if (option == NULL) {
        return -1;
    }

    if (!isdigit(arg[0])) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s", arg, option->large);
        return EINVALIDARGS;
    }

    dup = util_strdup_s(arg);
    if (dup == NULL) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s", arg, option->large);
        return EINVALIDARGS;
    }

    if (util_parse_size_int_and_float(arg, 1e9, option->data)) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s", arg, option->large);
        ret = EINVALIDARGS;
        goto out;
    }

out:
    free(dup);
    return ret;
}

int command_convert_device_cgroup_rules(command_option_t *option, const char *arg)
{
    if (option == NULL) {
        return -1;
    }

    if (!util_valid_device_cgroup_rule(arg)) {
        COMMAND_ERROR("Invalid value \"%s\" for flag --%s", arg, option->large);
        return EINVALIDARGS;
    }

    return command_append_array(option, arg);
}
