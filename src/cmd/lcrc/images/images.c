/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide container image functions
 ******************************************************************************/
#include "images.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "securec.h"

#include "utils.h"
#include "arguments.h"
#include "lcrc_connect.h"
#include "log.h"

#define IMAGES_OPTIONS(cmdargs)                                                                         \
    { CMD_OPT_TYPE_BOOL, false, "quiet", 'q', &((cmdargs).dispname), "Only display image names", NULL }

#define CREATED_DISPLAY_FORMAT "YYYY-MM-DD HH:MM:SS"
#define SHORT_DIGEST_LEN 12

const char g_cmd_images_desc[] = "List images";
const char g_cmd_images_usage[] = "images";

struct client_arguments g_cmd_images_args = {};
/* keep track of field widths for printing. */
struct lengths {
    unsigned int ref_length;
    unsigned int digest_length;
    unsigned int created_length;
    unsigned int size_length;
};

/* trans time */
static char *trans_time(int64_t created)
{
    struct tm t;
    int nret = 0;
    char formated_time[sizeof(CREATED_DISPLAY_FORMAT)] = { 0 };
    time_t created_time = (time_t)created;

    if (!localtime_r(&created_time, &t)) {
        ERROR("translate time for created failed: %s", strerror(errno));
        return NULL;
    }

    nret = sprintf_s(formated_time, sizeof(formated_time), "%04d-%02d-%02d %02d:%02d:%02d", t.tm_year + 1900,
                     t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    if (nret < 0) {
        ERROR("format created time failed");
        return NULL;
    }

    return util_strdup_s(formated_time);
}

/* list print table */
static void list_print_table(struct lcrc_image_info *images_list, const size_t size, const struct lengths *length)
{
    const struct lcrc_image_info *in = NULL;
    size_t i = 0;
    char *created = NULL;
    char *digest = NULL;
    char *image_size = NULL;
    if (length == NULL) {
        return;
    }
    /* print header */
    printf("%-*s ", (int)length->ref_length, "REF");
    printf("%-*s ", (int)length->digest_length, "IMAGE ID");
    printf("%-*s ", (int)length->created_length, "CREATED");
    printf("%-*s ", (int)length->size_length, "SIZE");
    printf("\n");

    for (i = 0, in = images_list; i < size && in != NULL; i++, in++) {
        printf("%-*s ", (int)length->ref_length, in->imageref ? in->imageref : "-");

        digest = util_short_digest(in->digest);
        printf("%-*s ", (int)length->digest_length, digest ? digest : "-");
        free(digest);

        created = trans_time(in->created);
        printf("%-*s ", (int)length->created_length, created ? created : "-");
        free(created);

        image_size = util_human_size_decimal(in->size);

        printf("%-*s ", (int)length->size_length, image_size ? image_size : "-");
        free(image_size);
        printf("\n");
    }
}

/* list field width */
static void list_field_width(const struct lcrc_image_info *images_list, const size_t size, struct lengths *l)
{
    const struct lcrc_image_info *in = NULL;
    size_t i = 0;
    char tmpbuffer[30];

    for (i = 0, in = images_list; i < size && in != NULL; i++, in++) {
        size_t len;
        int slen;
        if (in->imageref) {
            len = strlen(in->imageref);
            if (len > l->ref_length) {
                l->ref_length = (unsigned int)len;
            }
        }
        if (in->digest) {
            len = SHORT_DIGEST_LEN;
            if (len > l->digest_length) {
                l->digest_length = (unsigned int)len;
            }
        }
        if (in->created) {
            len = strlen(CREATED_DISPLAY_FORMAT);
            if (len > l->created_length) {
                l->created_length = (unsigned int)len;
            }
        }

        slen = sprintf_s(tmpbuffer, sizeof(tmpbuffer), "%.2f", (float)(in->size) / (1024 * 1024));
        if (slen < 0) {
            ERROR("sprintf tmpbuffer failed");
            return;
        }
        if ((unsigned int)slen > l->size_length) {
            l->size_length = (unsigned int)slen;
        }
    }
}

/*
 * list all images from LCRD
 */
static void images_info_print(const struct lcrc_list_images_response *response)
{
    struct lengths max_len = {
        .ref_length = 30, /* ref */
        .digest_length = 20, /* digest */
        .created_length = 20, /* created */
        .size_length = 10, /* size */
    };

    list_field_width(response->images_list, (size_t)response->images_num, &max_len);
    list_print_table(response->images_list, (size_t)response->images_num, &max_len);
}

/* images info print quiet */
static void images_info_print_quiet(const struct lcrc_list_images_response *response)
{
    struct lengths max_len = {
        .ref_length = 30, /* ref */
    };

    const struct lcrc_image_info *in = NULL;
    size_t i = 0;

    for (i = 0, in = response->images_list; in != NULL && i < response->images_num; i++, in++) {
        printf("%-*s ", (int)(max_len.ref_length), in->imageref ? in->imageref : "-");
        printf("\n");
    }
}

/*
* used by qsort function for comparing image created time
*/
static inline int lcrc_image_cmp(struct lcrc_image_info *first, struct lcrc_image_info *second)
{
    if (second->created > first->created) {
        return 1;
    } else if (second->created < first->created) {
        return -1;
    } else {
        return second->created_nanos > first->created_nanos;
    }
}

/*
 * list the images from remote
 */
static int list_images(const struct client_arguments *args)
{
    lcrc_connect_ops *ops = NULL;
    struct lcrc_list_images_request request = { 0 };
    struct lcrc_list_images_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct lcrc_list_images_response));
    if (response == NULL) {
        ERROR("Imagelist: Out of memory");
        return -1;
    }

    ops = get_connect_client_ops();
    if (ops == NULL || ops->image.list == NULL) {
        ERROR("Unimplemented image list op");
        ret = -1;
        goto out;
    }

    config = get_connect_config(args);
    ret = ops->image.list(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

    if (response->images_list != NULL && response->images_num > 0) {
        qsort(response->images_list, (size_t)(response->images_num), sizeof(struct lcrc_image_info),
              (int (*)(const void *, const void *))lcrc_image_cmp);
    }

    if (args->dispname) {
        images_info_print_quiet(response);
    } else {
        images_info_print(response);
    }

out:
    lcrc_list_images_response_free(response);
    return ret;
}

/* cmd images main */
int cmd_images_main(int argc, const char **argv)
{
    struct log_config lconf = { 0 };
    int exit_code = ECOMMON;
    command_t cmd;

    set_default_command_log_config(argv[0], &lconf);
    if (client_arguments_init(&g_cmd_images_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_images_args.progname = argv[0];
    struct command_option options[] = {
        LOG_OPTIONS(lconf),
        IMAGES_OPTIONS(g_cmd_images_args),
        COMMON_OPTIONS(g_cmd_images_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_images_desc,
                 g_cmd_images_usage);
    if (command_parse_args(&cmd, &g_cmd_images_args.argc, &g_cmd_images_args.argv)) {
        exit(exit_code);
    }
    if (log_init(&lconf)) {
        COMMAND_ERROR("Images: log init failed");
        exit(exit_code);
    }

    if (g_cmd_images_args.argc > 0) {
        COMMAND_ERROR("%s: \"images\" requires 0 arguments.", g_cmd_images_args.progname);
        exit(exit_code);
    }

    if (list_images(&g_cmd_images_args)) {
        ERROR("Can not list any images");
        exit(exit_code);
    }

    exit(EXIT_SUCCESS);
}
