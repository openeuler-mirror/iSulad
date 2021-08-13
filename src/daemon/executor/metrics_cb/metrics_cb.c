/******************************************************************************
 * Copyright (c) KylinSoft  Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.

 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xiapin
 * Create: 2021-08-17
 * Description: provide metric callback function
 ******************************************************************************/
#define _GNU_SOURCE
#include "metrics_cb.h"
#include <stdio.h>
#include <stdlib.h>

#include "callback.h"
#include "utils.h"
#include "isula_libutils/log.h"

typedef enum {
    COUNTER     = 0,
    GAUGE,
    HISTOGRAM,
    SUMMARY,

    METRIC_TYPE_BUTT,
} Isula_Metrics_Type;

typedef struct isula_metrics {
    /* To match request-url type, if url is null, default export. */
    const char *url;
    /* The metric name */
    const char *name;
    Isula_Metrics_Type metrics_type;
    /* The metric help info */
    const char *descripe;
    /* The metric data, the format is independent of the type */
    int (*metrics_data_get)(const char *name, char *buf, int size);
} isula_metrics_t;

#define METRIC_RESPONSE_OK      200
#define METRIC_RESPONSE_FAIL    401

#define ISULA_PREFIX        "isula_"
#define HELP_HEAD           "# HELP "
#define TYPE_HEAD           "# TYPE "
#define METRICS_BUF_SIZE    (1024 * 1024)

/* metric name, no spaces allowed */
#define METRICS_REQUEST_COUNT   ISULA_PREFIX "metrics_http_req_count"
#define ISULA_DAEMON_MEM_STAT   ISULA_PREFIX "daemon_mem_stat"
#define ISULA_CONT_MEM_STAT     ISULA_PREFIX "container_mem_stat"
#define ISULA_CONT_CPU_STAT     ISULA_PREFIX "container_cpu_stat"
#define ISULA_CONT_PIDS         ISULA_PREFIX "container_pids"
#define DAEMON_CALLOC_TOTAL     ISULA_PREFIX "daemon_calloced_memory_total"

/* metric help info */
static const char g_isula_daemon_mem_desc[] = "is isula daemon memory occupied";
static const char g_mem_stat_desc[] = "is containers's memory occupied stats";
static const char g_cpu_stat_desc[] = "is containers's cpu stats";
static const char g_req_count_desc[] = "is metrics server accepted request count";
static const char g_cont_pids_desc[] = "is containers's pid count";
static const char g_daemon_calloc_desc[] = "is isula deamon calloced total";

static unsigned long long g_mem_alloced_total;

const char *get_metric_name(Isula_Metrics_Type e)
{
    if (e < COUNTER || e >= METRIC_TYPE_BUTT) {
        return NULL;
    }

    const char *metric_type_name[] = {
        "counter",
        "gauge",
        "histogram",
        "summary",
    };

    return metric_type_name[e];
}

static int metrics_get_isulad_mem_stat(const char *name, char *buffer, int size)
{
    FILE *fp = NULL;
    int vm_size = 0;
    int vm_rss = 0;
    int share_page = 0;
    int text_size = 0;
    int unused = 0;
    int stack_size = 0;

    fp = util_fopen("/proc/self/statm", "r");
    if (fp == NULL) {
        return -1;
    }

    if (fscanf(fp, "%d %d %d %d %d %d %d", &vm_size, &vm_rss, &share_page, &text_size,
               &unused, &stack_size, &unused) <= 0) {
        fclose(fp);
        return -1;
    }

    int len = snprintf(buffer, size,
                       "%s{section=\"vmsize\"} %d\n"
                       "%s{section=\"vmrss\"} %d\n"
                       "%s{section=\"share_page\"} %d\n"
                       "%s{section=\"text_size\"} %d\n"
                       "%s{section=\"stack_size\"} %d\n",
                       name, vm_size * 4, name, vm_rss * 4, name,
                       share_page * 4, name, text_size * 4, name, stack_size * 4);

    fclose(fp);

    return len;
}

static int metrics_get_container_info(container_stats_response **response)
{
    int ret = -1;
    container_stats_request *request = NULL;

    if (response == NULL) {
        goto out;
    }

    request = (container_stats_request*)util_common_calloc_s(sizeof(container_stats_request));
    if (request == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    ret = get_service_executor()->container.stats((const container_stats_request *)request, response);

    free(request);

out:
    return ret;
}

static int metrics_containers_mem_stats(const char *name, char *buffer, int size)
{
    int ret = 0;
    int i = 0;
    int len = 0;
    container_stats_response *response = NULL;

    if (metrics_get_container_info(&response) != 0 || response == NULL) {
        ret = -1;
        goto out;
    }

    for (i = 0; i < response->container_stats_len; i++) {
        len = snprintf(buffer + ret, size - ret,
                       "%s{container_id=\"%4.4s\",limit=\"%ld Kb\"} %ld\n",
                       name, response->container_stats[i]->id, response->container_stats[i]->mem_limit / 1024,
                       response->container_stats[i]->mem_used);
        if (len < 0 || (size_t)len >= size - ret) {
            break;
        }

        ret += len;
    }

    free_container_stats_response(response);

out:
    return ret;
}

static float generate_cpu_info(container_info *stats, container_stats_response *old_stat)
{
    double cpu_percent = 0.0;
    int i = 0;
    unsigned long long d_sys_use = 0;
    unsigned long long d_cpu_use = 0;

    for (i = 0; i < old_stat->container_stats_len; i++) {
        if (strcmp(stats->id, old_stat->container_stats[i]->id) != 0) {
            continue;
        }
        if (stats->cpu_system_use > old_stat->container_stats[i]->cpu_system_use) {
            d_sys_use = stats->cpu_system_use - old_stat->container_stats[i]->cpu_system_use;
        }
        if (stats->cpu_use_nanos > old_stat->container_stats[i]->cpu_use_nanos) {
            d_cpu_use = stats->cpu_use_nanos - old_stat->container_stats[i]->cpu_use_nanos;
        }

        if (d_sys_use > 0 && stats->online_cpus > 0) {
            cpu_percent = ((double)d_cpu_use / d_sys_use) * stats->online_cpus * 100;
        }
        break;
    }

    return cpu_percent;
}

static int metrics_containers_cpu_stats(const char *name, char *buffer, int size)
{
    int ret = 0;
    int i = 0;
    int len = 0;
    container_stats_response *response = NULL;
    static container_stats_response *old_stat = NULL;

    if (metrics_get_container_info(&response) != 0 || response == NULL) {
        goto out;
    }

    if (old_stat == NULL) {
        old_stat = response;
        goto out;
    }

    for (i = 0; i < response->container_stats_len; i++) {
        len = snprintf(buffer + ret, size - ret, "%s{container_id=\"%4.4s\"} %-10.2f\n",
                       name, response->container_stats[i]->id,
                       generate_cpu_info(response->container_stats[i], old_stat));
        if (len < 0 || (size_t)len >= size - ret) {
            break;
        }

        ret += len;
    }

    free_container_stats_response(old_stat);
    old_stat = response;

out:
    return ret;
}

static int metrics_http_req_count_info(const char *name, char *buffer, int size)
{
    static unsigned int req_count = 0;
    int len = 0;

    req_count++;
    len = snprintf(buffer, size, "%s %u\n", name, req_count);

    return len;
}

static int metrics_containers_pids(const char *name, char *buffer, int size)
{
    int ret = 0;
    int i = 0;
    int len = 0;
    container_stats_response *response = NULL;

    if (metrics_get_container_info(&response) != 0 || response == NULL) {
        goto out;
    }

    for (i = 0; i < response->container_stats_len; i++) {
        len = snprintf(buffer + ret, size - ret,
                       "%s{container_id=\"%4.4s\"} %ld\n",
                       name, response->container_stats[i]->id, response->container_stats[i]->pids_current);
        if (len < 0 || (size_t)len >= size - ret) {
            break;
        }

        ret += len;
    }

    free_container_stats_response(response);

out:
    return ret;
}

void metrics_add_calloced_mem(unsigned size)
{
    g_mem_alloced_total += size;
}

static int metrics_daemon_alloced_mem_total(const char *name, char *buffer, int size)
{
    static unsigned int req_count = 0;
    int len = 0;

    len = snprintf(buffer, size, "%s %llu\n", name, g_mem_alloced_total);
    req_count++;

    return len;
}

static isula_metrics_t g_metrics[] = {
    {NULL, METRICS_REQUEST_COUNT, COUNTER, g_req_count_desc, metrics_http_req_count_info}, /* export default */
    {"sys", ISULA_DAEMON_MEM_STAT, GAUGE, g_isula_daemon_mem_desc, metrics_get_isulad_mem_stat},
    {"mem", ISULA_CONT_MEM_STAT, GAUGE, g_mem_stat_desc, metrics_containers_mem_stats},
    {"cpu", ISULA_CONT_CPU_STAT, GAUGE, g_cpu_stat_desc, metrics_containers_cpu_stats},
    {"pids", ISULA_CONT_PIDS, GAUGE, g_cont_pids_desc, metrics_containers_pids},
    {"sys", DAEMON_CALLOC_TOTAL, COUNTER, g_daemon_calloc_desc, metrics_daemon_alloced_mem_total},
};

static int metrics_msg_get_by_type(const char *url, char **metrics, int *len)
{
#define E_SIZE  (512 * 1024)
    char *msg = NULL;
    char *element = NULL;
    int msg_len = 0;
    int i = 0;
    bool export_all = false;

    if (url == NULL) {
        ERROR("invalid request url");
        return -1;
    }

    export_all = !strcmp(url, "all");
    msg = (char *)util_common_calloc_s(METRICS_BUF_SIZE);
    if (msg == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    element = (char *)util_common_calloc_s(E_SIZE);
    if (element == NULL) {
        ERROR("Out of memory");
        free(msg);
        return -1;
    }

    for (i = 0; i < sizeof(g_metrics) / sizeof(g_metrics[0]); i++) {
        if (g_metrics[i].metrics_data_get == NULL) {
            continue;
        }

        if (g_metrics[i].url != NULL && strcasestr(url, g_metrics[i].url) == NULL && !export_all) {
            continue;
        }

        if (g_metrics[i].metrics_data_get(g_metrics[i].name, element, E_SIZE) <= 0) {
            continue;
        }
        int tmp = snprintf(msg + msg_len, METRICS_BUF_SIZE - msg_len,
                           HELP_HEAD "%s %s\n"
                           TYPE_HEAD "%s %s\n"
                           "%s\n", g_metrics[i].name, g_metrics[i].descripe, g_metrics[i].name,
                           get_metric_name(g_metrics[i].metrics_type), element);
        if (tmp < 0 || (size_t)tmp >= METRICS_BUF_SIZE - msg_len) {
            break;
        }
        msg_len += tmp;
    }

    free(element);
    *len = msg_len;
    *metrics = msg;
    return 0;
}

void metrics_callback_init(service_metrics_callback_t *cb)
{
    cb->export_metrics_by_type = metrics_msg_get_by_type;
}
