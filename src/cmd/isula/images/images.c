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
 * Description: provide container image functions
 ******************************************************************************/
#include "images.h"

#include <stdio.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "utils.h"
#include "client_arguments.h"
#include "isula_connect.h"
#include "isula_libutils/log.h"

#define IMAGES_OPTIONS(cmdargs)                                                                                        \
    { CMD_OPT_TYPE_BOOL, false, "quiet", 'q', &((cmdargs).dispname), "Only display image names", NULL },               \
    {                                                                                                                  \
        CMD_OPT_TYPE_CALLBACK, false, "filter", 'f', &(cmdargs).filters, "Filter output based on conditions provided", \
        command_append_array                                                                                   \
    }

#define CREATED_DISPLAY_FORMAT "YYYY-MM-DD HH:MM:SS"
#define SHORT_DIGEST_LEN 12

const char g_cmd_images_desc[] = "List images";
const char g_cmd_images_usage[] = "images";

struct client_arguments g_cmd_images_args = {};
/* keep track of field widths for printing. */
struct lengths {
    unsigned int registry_length;
    unsigned int tag_length;
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

    nret = snprintf(formated_time, sizeof(formated_time), "%04d-%02d-%02d %02d:%02d:%02d", t.tm_year + 1900,
                    t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
    if (nret < 0 || nret >= sizeof(formated_time)) {
        ERROR("format created time failed");
        return NULL;
    }

    return util_strdup_s(formated_time);
}

/* list print table */
static void list_print_table(struct isula_image_info *images_list, const size_t size, const struct lengths *length)
{
    const struct isula_image_info *in = NULL;
    size_t i = 0;
    char *created = NULL;
    char *digest = NULL;
    char *image_size = NULL;
    if (length == NULL) {
        return;
    }
    /* print header */
    printf("%-*s ", (int)length->registry_length, "REPOSITORY");
    printf("%-*s ", (int)length->tag_length, "TAG");
    printf("%-*s ", (int)length->digest_length, "IMAGE ID");
    printf("%-*s ", (int)length->created_length, "CREATED");
    printf("%-*s ", (int)length->size_length, "SIZE");
    printf("\n");

    for (i = 0, in = images_list; i < size && in != NULL; i++, in++) {
        if (in->imageref == NULL || strcmp(in->imageref, "-") == 0) {
            printf("%-*s ", (int)length->registry_length, "<none>");
            printf("%-*s ", (int)length->tag_length, "<none>");
        } else {
            char *copy_name = util_strdup_s(in->imageref);
            char *tag_pos = util_tag_pos(copy_name);
            if (tag_pos == NULL) {
                printf("%-*s ", (int)length->registry_length, copy_name);
                printf("%-*s ", (int)length->tag_length, "<none>");
            } else {
                *tag_pos = '\0';
                tag_pos++;
                printf("%-*s ", (int)length->registry_length, copy_name);
                printf("%-*s ", (int)length->tag_length, tag_pos);
                tag_pos--;
                *tag_pos = ':';
            }
            free(copy_name);
        }

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

static int update_image_ref_width(const struct isula_image_info *in, struct lengths *l)
{
    size_t len;
    char *copy_name = util_strdup_s(in->imageref);
    char *tag_pos = util_tag_pos(copy_name);
    if (tag_pos == NULL) {
        len = strlen(copy_name);
        if (len > l->registry_length) {
            l->registry_length = (unsigned int)len;
        }
        len = strlen("<none>");
        if (len > l->tag_length) {
            l->tag_length = (unsigned int)len;
        }
    } else {
        *tag_pos = '\0';
        tag_pos++;
        len = strlen(copy_name);
        if (len > l->registry_length) {
            l->registry_length = (unsigned int)len;
        }
        len = strlen(tag_pos);
        if (len > l->tag_length) {
            l->tag_length = (unsigned int)len;
        }
        tag_pos--;
        *tag_pos = ':';
    }
    free(copy_name);

    return 0;
}

/* list field width */
static void list_field_width(const struct isula_image_info *images_list, const size_t size, struct lengths *l)
{
    const struct isula_image_info *in = NULL;
    size_t i = 0;
    char tmpbuffer[30];

    for (i = 0, in = images_list; i < size && in != NULL; i++, in++) {
        size_t len;
        int slen;
        if (in->imageref) {
            if (update_image_ref_width(in, l) != 0) {
                return;
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

        slen = snprintf(tmpbuffer, sizeof(tmpbuffer), "%.2f", (float)(in->size) / (1024 * 1024));
        if (slen < 0 || (size_t)slen >= sizeof(tmpbuffer)) {
            ERROR("sprintf tmpbuffer failed");
            return;
        }
        if ((unsigned int)slen > l->size_length) {
            l->size_length = (unsigned int)slen;
        }
    }
}

/*
 * list all images from isulad
 */
static void images_info_print(const struct isula_list_images_response *response)
{
    struct lengths max_len = {
        .registry_length = 30, /* registry */
        .tag_length = 10, /* tag */
        .digest_length = 20, /* digest */
        .created_length = 20, /* created */
        .size_length = 10, /* size */
    };

    list_field_width(response->images_list, (size_t)response->images_num, &max_len);
    list_print_table(response->images_list, (size_t)response->images_num, &max_len);
}

/* images info print quiet */
static void images_info_print_quiet(const struct isula_list_images_response *response)
{
    const struct isula_image_info *in = NULL;
    size_t i = 0;

    for (i = 0, in = response->images_list; in != NULL && i < response->images_num; i++, in++) {
        char *digest = util_short_digest(in->digest);
        printf("%-*s", SHORT_DIGEST_LEN, digest ? digest : "<none>");
        printf("\n");
        free(digest);
    }
}

/*
* used by qsort function for comparing image created time
*/
static inline int isula_image_cmp(struct isula_image_info *first, struct isula_image_info *second)
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
    isula_connect_ops *ops = NULL;
    struct isula_list_images_request request = { 0 };
    struct isula_list_images_response *response = NULL;
    client_connect_config_t config = { 0 };
    int ret = 0;

    response = util_common_calloc_s(sizeof(struct isula_list_images_response));
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
    if (args->filters != NULL) {
        request.filters =
            isula_filters_parse_args((const char **)args->filters, util_array_len((const char **)(args->filters)));
        if (request.filters == NULL) {
            ERROR("Failed to parse filters args");
            ret = -1;
            goto out;
        }
    }
    config = get_connect_config(args);
    ret = ops->image.list(&request, response, &config);
    if (ret != 0) {
        client_print_error(response->cc, response->server_errono, response->errmsg);
        goto out;
    }

    if (response->images_list != NULL && response->images_num > 0) {
        qsort(response->images_list, (size_t)(response->images_num), sizeof(struct isula_image_info),
              (int (*)(const void *, const void *))isula_image_cmp);
    }

    if (args->dispname) {
        images_info_print_quiet(response);
    } else {
        images_info_print(response);
    }

out:
    isula_filters_free(request.filters);
    isula_list_images_response_free(response);
    return ret;
}

/* cmd images main */
int cmd_images_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    int exit_code = ECOMMON;
    command_t cmd;

    if (client_arguments_init(&g_cmd_images_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_images_args.progname = argv[0];
    struct command_option options[] = { LOG_OPTIONS(lconf), IMAGES_OPTIONS(g_cmd_images_args),
               COMMON_OPTIONS(g_cmd_images_args)
    };

    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_images_desc,
                 g_cmd_images_usage);
    if (command_parse_args(&cmd, &g_cmd_images_args.argc, &g_cmd_images_args.argv)) {
        exit(exit_code);
    }
    isula_libutils_default_log_config(argv[0], &lconf);
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Images: log init failed");
        exit(exit_code);
    }

    if (list_images(&g_cmd_images_args)) {
        ERROR("Can not list any images");
        exit(exit_code);
    }

    exit(EXIT_SUCCESS);
}
