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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container load functions
 ******************************************************************************/
#include "load.h"

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"
#include "connect.h"
#include "libisula.h"

#ifdef ENABLE_EMBEDDED_IMAGE
const char g_cmd_load_desc[] = "load an image from a manifest or a tar archive";
const char g_cmd_load_usage[] = "load [OPTIONS] --input=FILE --type=TYPE";
#else
const char g_cmd_load_desc[] = "load an image from a tar archive";
const char g_cmd_load_usage[] = "load [OPTIONS] --input=FILE";
#endif

struct client_arguments g_cmd_load_args = { 0 };

/*
 * load the image from a manifest or a tar archive
 */
static int client_load_image(const struct client_arguments *args)
{
    isula_connect_ops *ops = NULL;
    struct isula_load_request request = { 0 };
    struct isula_load_response response = { 0 };
    client_connect_config_t config = { 0 };
    int ret = 0;

    request.file = args->file;
    request.type = args->type;
    request.tag = args->tag;

    ops = get_connect_client_ops();
    if (ops == NULL || !ops->image.load) {
        ERROR("Unimplemented ops");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->image.load(&request, &response, &config);
    if (ret) {
        client_print_error(response.cc, response.server_errono, response.errmsg);
        if (response.server_errono) {
            ret = ESERVERERROR;
        }
        goto out;
    }
out:
    return ret;
}

/* Waring: This function may modify image type */
static bool valid_param()
{
    if (g_cmd_load_args.argc > 0) {
        COMMAND_ERROR("%s: \"load\" requires 0 arguments.", g_cmd_load_args.progname);
        return false;
    }

    if (g_cmd_load_args.file == NULL) {
        COMMAND_ERROR("missing image input, use -i,--input option");
        return false;
    }

    if (g_cmd_load_args.type != NULL) {
        if ((strcmp(g_cmd_load_args.type, "docker") != 0) && (strcmp(g_cmd_load_args.type, "embedded") != 0)) {
            COMMAND_ERROR("Invalid image type: image type must be embedded or docker, got %s", g_cmd_load_args.type);
            return false;
        }
    }

#ifdef ENABLE_EMBEDDED_IMAGE
    /* Treat the tar as docker archive if type is empty */
    if (g_cmd_load_args.type == NULL || strncmp(g_cmd_load_args.type, "docker", 7) == 0) {
        /* Docker archive tar is loaded into oci type. */
        /* Do not free type here because type is not a allocated memory. */
        g_cmd_load_args.type = "oci";
    } else {
        if (g_cmd_load_args.tag != NULL) {
            COMMAND_ERROR("Option --tag can be used only when type is docker");
            return false;
        }
    }
#else
    g_cmd_load_args.type = "oci";
#endif

    return true;
}

int cmd_load_main(int argc, const char **argv)
{
    int ret = 0;
    char file[PATH_MAX] = { 0 };
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = ECOMMON;
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf) COMMON_OPTIONS(g_cmd_load_args) LOAD_OPTIONS(g_cmd_load_args)
#ifdef ENABLE_EMBEDDED_IMAGE
        EMBEDDED_OPTIONS(g_cmd_load_args)
#endif
    };

    isula_libutils_default_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_load_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_load_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_load_desc,
                 g_cmd_load_usage);
    if (command_parse_args(&cmd, &g_cmd_load_args.argc, &g_cmd_load_args.argv)) {
        exit(exit_code);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Load: log init failed");
        exit(exit_code);
    }

    if (valid_param() != true) {
        exit(exit_code);
    }

    /* If it's not a absolute path, add cwd to be absolute path */
    if (g_cmd_load_args.file[0] != '/') {
        char cwd[PATH_MAX] = { 0 };
        int len;

        if (!getcwd(cwd, sizeof(cwd))) {
            COMMAND_ERROR("get cwd failed:%s", strerror(errno));
            exit(exit_code);
        }

        len = snprintf(file, sizeof(file), "%s/%s", cwd, g_cmd_load_args.file);
        if (len < 0 || (size_t)len >= sizeof(file)) {
            COMMAND_ERROR("filename too long");
            exit(exit_code);
        }
        g_cmd_load_args.file = file;
    }

    ret = client_load_image(&g_cmd_load_args);
    if (ret) {
        exit(exit_code);
    }

    printf("Load image from \"%s\" success\n", g_cmd_load_args.file);
    exit(EXIT_SUCCESS);
}
