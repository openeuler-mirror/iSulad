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
 * Description: provide container stats functions
 ******************************************************************************/
#define __STDC_FORMAT_MACROS /* Required for PRIu64 to work. */
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#include "client_arguments.h"
#include "stats.h"
#include "utils.h"
#include "isula_libutils/log.h"
#include "isula_connect.h"
#include "connect.h"
#include "libisula.h"

#define ESC "\033"
#define TERMCLEAR ESC "[H" ESC "[J"
#define TERMNORM ESC "[0m"
#define TERMBOLD ESC "[1m"
#define TERMRVRS ESC "[7m"

const char g_cmd_stats_desc[] = "Display a live stream of container(s) resource usage statistics";
const char g_cmd_stats_usage[] = "stats [OPTIONS] [CONTAINER...]";

struct client_arguments g_cmd_stats_args = {
    .showall = false,
    .nostream = false,
    .runtime = "lcr",
};

static struct isula_stats_response *g_oldstats = NULL;

static void isula_size_humanize(unsigned long long val, char *buf, size_t bufsz)
{
    int ret = 0;
    if (val > 1024 * 1024 * 1024) {
        ret = snprintf(buf, bufsz, "%u.%.2u GiB", (unsigned int)(val >> 30),
                       (unsigned int)(val & ((1 << 30) - 1)) / 10737419);
    } else if (val > 1024 * 1024) {
        unsigned long long x = val + 5243; /* for rounding */
        ret = snprintf(buf, bufsz, "%u.%.2u MiB", (unsigned int)(x >> 20),
                       (unsigned int)(((x & ((1 << 20) - 1)) * 100) >> 20));
    } else if (val > 1024) {
        unsigned long long x = val + 5; /* for rounding */
        ret = snprintf(buf, bufsz, "%u.%.2u KiB", (unsigned int)(x >> 10),
                       (unsigned int)(((x & ((1 << 10) - 1)) * 100) >> 10));
    } else {
        ret = snprintf(buf, bufsz, "%u.00 B", (unsigned int)val);
    }
    if (ret < 0 || (size_t)ret >= bufsz) {
        ERROR("Humanize sprintf failed!");
    }
}

static void stats_print_header(void)
{
    printf(TERMRVRS TERMBOLD);
    printf("%-16s %-10s %-26s %-10s %-26s %-10s", "CONTAINER", "CPU %", "MEM USAGE / LIMIT", "MEM %", "BLOCK I / O",
           "PIDS");
    printf("\n");
    printf(TERMNORM);
}

static void stats_print(const struct isula_container_info *stats)
{
#define SHORTIDLEN 12
#define PERCENT 100
    char iosb_str[63];
    char iosb_read_str[20];
    char iosb_write_str[20];
    char mem_str[63];
    char mem_used_str[20];
    char mem_limit_str[20];
    int len;
    double cpu_percent = 0.0;
    char *short_id = NULL;

    isula_size_humanize(stats->blkio_read, iosb_read_str, sizeof(iosb_read_str));
    isula_size_humanize(stats->blkio_write, iosb_write_str, sizeof(iosb_write_str));
    isula_size_humanize(stats->mem_used, mem_used_str, sizeof(mem_used_str));
    isula_size_humanize(stats->mem_limit, mem_limit_str, sizeof(mem_limit_str));

    len = snprintf(iosb_str, sizeof(iosb_str), "%s / %s", iosb_read_str, iosb_write_str);
    if (len < 0 || (size_t)len >= sizeof(iosb_str)) {
        ERROR("Sprintf iosb_str failed");
        return;
    }
    len = snprintf(mem_str, sizeof(mem_str), "%s / %s", mem_used_str, mem_limit_str);
    if (len < 0 || (size_t)len >= sizeof(mem_str)) {
        ERROR("Sprintf mem_str failed");
        return;
    }

    if (g_oldstats != NULL) {
        size_t i;
        uint64_t d_sys_use = 0;
        uint64_t d_cpu_use = 0;
        for (i = 0; i < g_oldstats->container_num; i++) {
            if (strcmp(stats->id, g_oldstats->container_stats[i].id) != 0) {
                continue;
            }
            if (stats->cpu_system_use > g_oldstats->container_stats[i].cpu_system_use) {
                d_sys_use = stats->cpu_system_use - g_oldstats->container_stats[i].cpu_system_use;
            }
            if (stats->cpu_use_nanos > g_oldstats->container_stats[i].cpu_use_nanos) {
                d_cpu_use = stats->cpu_use_nanos - g_oldstats->container_stats[i].cpu_use_nanos;
            }
            if (d_sys_use > 0 && stats->online_cpus > 0) {
                cpu_percent = ((double)d_cpu_use / d_sys_use) * stats->online_cpus * PERCENT;
            }
        }
    }

    short_id = util_strdup_s(stats->id);
    if (strlen(short_id) > SHORTIDLEN) {
        short_id[SHORTIDLEN] = '\0';
    }
    printf("%-16s %-10.2f %-26s %-10.2f %-26s %-10llu", short_id, cpu_percent, mem_str,
           stats->mem_limit ? ((double)stats->mem_used / stats->mem_limit) * PERCENT : 0.00, iosb_str,
           (unsigned long long)stats->pids_current);
    free(short_id);
}

static void stats_output(const struct client_arguments *args, struct isula_stats_response **response)
{
    size_t i;

    printf(TERMCLEAR);
    stats_print_header();
    for (i = 0; i < (*response)->container_num; i++) {
        stats_print(&((*response)->container_stats[i]));
        printf("\n");
    }
    fflush(stdout);

    isula_stats_response_free(g_oldstats);
    g_oldstats = *response;
    *response = NULL;
}

static int client_stats_mainloop(const struct client_arguments *args, const struct isula_stats_request *request)
{
    int ret = 0;
    isula_connect_ops *ops = NULL;
    client_connect_config_t config;

    if (args == NULL) {
        return -1;
    }
    ops = get_connect_client_ops();
    if (ops == NULL || ops->container.stats == NULL) {
        ERROR("Unimplemented ops");
        return -1;
    }
    config = get_connect_config(args);

    while (1) {
        struct isula_stats_response *response = NULL;
        response = util_common_calloc_s(sizeof(struct isula_stats_response));
        if (response == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto err_out;
        }

        ret = ops->container.stats(request, response, &config);
        if (ret) {
            ERROR("Failed to stats containers info");
            client_print_error(response->cc, response->server_errono, response->errmsg);
            isula_stats_response_free(response);
            ret = -1;
            goto err_out;
        }

        stats_output(args, &response);
        isula_stats_response_free(response);
        if (args->nostream) {
            goto err_out;
        }

        sleep(1);
    }

err_out:
    isula_stats_response_free(g_oldstats);
    g_oldstats = NULL;
    return ret;
}

/*
* Create a stats request message and call RPC
*/
static int client_stats(const struct client_arguments *args)
{
    struct isula_stats_request request = { 0 };

    request.all = args->showall;
    request.containers = (char **)(args->argv);
    request.containers_len = (size_t)(args->argc);

    return client_stats_mainloop(args, &request);
}

int cmd_stats_main(int argc, const char **argv)
{
    struct isula_libutils_log_config lconf = { 0 };
    command_t cmd;
    struct command_option options[] = { LOG_OPTIONS(lconf), STATUS_OPTIONS(g_cmd_stats_args),
               COMMON_OPTIONS(g_cmd_stats_args)
    };

    if (client_arguments_init(&g_cmd_stats_args)) {
        COMMAND_ERROR("client arguments init failed");
        exit(ECOMMON);
    }
    g_cmd_stats_args.progname = argv[0];
    command_init(&cmd, options, sizeof(options) / sizeof(options[0]), argc, (const char **)argv, g_cmd_stats_desc,
                 g_cmd_stats_usage);
    isula_libutils_default_log_config(argv[0], &lconf);
    if (command_parse_args(&cmd, &g_cmd_stats_args.argc, &g_cmd_stats_args.argv)) {
        exit(EINVALIDARGS);
    }
    if (isula_libutils_log_enable(&lconf)) {
        COMMAND_ERROR("Stats: log init failed");
        exit(ECOMMON);
    }

    if (client_stats(&g_cmd_stats_args)) {
        ERROR("Can not stats containers");
        exit(ECOMMON);
    }

    exit(EXIT_SUCCESS);
}
