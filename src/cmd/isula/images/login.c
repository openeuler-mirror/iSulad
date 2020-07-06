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
 * Author: wangfengtu
 * Create: 2019-6-18
 * Description: provide login
 ********************************************************************************/
#include "login.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"
#include "connect.h"
#include "libisula.h"

const char g_cmd_login_desc[] = "Log in to a Docker registry";
const char g_cmd_login_usage[] = "login [OPTIONS] SERVER";

struct client_arguments g_cmd_login_args = {};

/*
 * Login to a docker registry.
 */
int client_login(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_login_request request = { 0 };
    struct isula_login_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_login_response));
    if (response == NULL) {
        ERROR("Out of memory");
        return ECOMMON;
    }

    // Support type oci only currently.
    request.type = "oci";
    request.server = args->server;
    request.username = args->username;
    request.password = args->password;

    ops = get_connect_client_ops();
    if (ops == NULL || ops->image.login == NULL) {
        ERROR("Unimplemented ops");
        ret = ECOMMON;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->image.login(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        ret = ESERVERERROR;
        goto out;
    }

    COMMAND_ERROR("Login Succeeded");

out:
    isula_login_response_free(response);
    return ret;
}

static int get_password_from_notty(struct client_arguments *args)
{
    if (g_cmd_login_args.username == NULL && g_cmd_login_args.password_stdin) {
        COMMAND_ERROR("Must provide --username with --password-stdin");
        return -1;
    }

    if (g_cmd_login_args.password != NULL) {
        printf("WARNING! Using --password via the CLI is insecure. Use --password-stdin.\n");
        if (g_cmd_login_args.password_stdin) {
            printf("--password and --password-stdin are mutually exclusive\n");
            return -1;
        }
    }

    // Try get password from notty input.
    if (g_cmd_login_args.password_stdin) {
        char password[LOGIN_PASSWORD_LEN + 1] = { 0 };
        int n = util_input_readall(password, sizeof(password));
        if (n == 0) {
            COMMAND_ERROR("Error: Password Required");
            return -1;
        }
        if (n < 0) {
            COMMAND_ERROR("Get password from notty stdin failed: %s", strerror(errno));
            return -1;
        }
        args->password = util_strdup_s(password);
        (void)memset(password, 0, sizeof(password));
    }

    return 0;
}

static int get_auth_from_terminal(struct client_arguments *args)
{
    int n;

    if (args->username == NULL) {
        char username[LOGIN_USERNAME_LEN + 1] = { 0 };
        printf("Username: ");
        n = util_input_echo(username, sizeof(username));
        if (n == 0) {
            ERROR("Error: Non-null Username Required\n");
            return -1;
        }
        if (n < 0) {
            if (errno == ENOTTY) {
                COMMAND_ERROR("Error: Cannot perform an interactive login from a non TTY device");
                return -1;
            }
            COMMAND_ERROR("Get username failed: %s", strerror(errno));
            return -1;
        }
        args->username = util_strdup_s(username);
    }

    if (args->password == NULL) {
        char password[LOGIN_PASSWORD_LEN + 1] = { 0 };
        printf("Password: ");
        n = util_input_noecho(password, sizeof(password));
        if (n == 0) {
            ERROR("Error: Password Required\n");
            return -1;
        }
        if (n < 0) {
            if (errno == ENOTTY) {
                COMMAND_ERROR("Error: Cannot perform an interactive login from a non TTY device");
                return -1;
            }
            COMMAND_ERROR("Get password failed: %s", strerror(errno));
            return -1;
        }
        args->password = util_strdup_s(password);
        (void)memset(password, 0, sizeof(password));
    }

    return 0;
}

static int get_auth(struct client_arguments *args)
{
    // Try get password from notty input.
    if (get_password_from_notty(&g_cmd_login_args)) {
        return -1;
    }

    // Try get username and password from terminal.
    if (get_auth_from_terminal(&g_cmd_login_args)) {
        return -1;
    }

    if (args->username == NULL || args->password == NULL) {
        // This should not happen.
        COMMAND_ERROR("Missing username or password");
        return -1;
    }

    return 0;
}

int cmd_login_main(int argc, const char **argv)
{
    int ret = 0;
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = 1; /* exit 1 if failed to login */
    command_t cmd;
    struct command_option options[] = { COMMON_OPTIONS(g_cmd_login_args) LOGIN_OPTIONS(g_cmd_login_args) };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_login_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_login_args.progname = argv[0];

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_login_desc,
                 g_cmd_login_usage);
    if (command_parse_args(&cmd, &g_cmd_login_args.argc, &g_cmd_login_args.argv)) {
        exit(exit_code);
    }

    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("login: log init failed");
        exit(exit_code);
    }

    if (g_cmd_login_args.argc != 1) {
        COMMAND_ERROR("login requires 1 argument.");
        exit(exit_code);
    }

    g_cmd_login_args.server = g_cmd_login_args.argv[0];

    ret = get_auth(&g_cmd_login_args);
    if (ret != 0) {
        exit(exit_code);
    }

    ret = client_login(&g_cmd_login_args);
    if (ret != 0) {
        exit(exit_code);
    }

    exit(EXIT_SUCCESS);
}
