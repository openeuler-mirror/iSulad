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
 * Description: provide container configure definition
 ******************************************************************************/
#include "isulad_config.h"
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <limits.h>
#include <fcntl.h>
#include <libgen.h>
#include <errno.h>
#include <isula_libutils/defs.h>
#include <isula_libutils/isulad_daemon_configs.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_runtime_spec.h>
#include <isula_libutils/log.h>

#include "constants.h"
#include "utils.h"
#include "sysinfo.h"
#include "err_msg.h"
#include "daemon_arguments.h"
#include "utils_array.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils_string.h"

#define ENGINE_ROOTPATH_NAME "engines"
#define GRAPH_ROOTPATH_CHECKED_FLAG "NEED_CHECK"

#define INCREMENT_INTREVAL 2
#define BUFFER_ITEM_NUMS 10

static struct isulad_conf g_isulad_conf;
static double g_jiffy = 0.0;

/* tick to ns */
static inline unsigned long long tick_to_ns(uint64_t tick)
{
#define EPSINON 0.0001

    if (g_jiffy < EPSINON && g_jiffy > -EPSINON) {
        g_jiffy = (double)sysconf(_SC_CLK_TCK);
    }

    if ((uint64_t)(tick / g_jiffy) > (UINT64_MAX / Time_Second)) {
        return UINT64_MAX;
    }
    return (uint64_t)((tick / g_jiffy) * Time_Second);
}

/*
 * returns the host system's cpu usage in nanoseconds.
 * Uses /proc/stat defined by POSIX. Looks for the cpu statistics line
 * and then sums up the first seven fields provided.
 * See `man 5 proc` for details on specific field information.
 */
int get_system_cpu_usage(uint64_t *val)
{
    int ret = 0;
    int nret;
    unsigned long long total, usertime, nicetime, systemtime, idletime;
    unsigned long long ioWait, irq, softIrq, steal, guest, guestnice;
    char buffer[BUFSIZ + 1] = { 0 };
    char *tmp = NULL;
    FILE *file = NULL;

    if (val == NULL) {
        return -1;
    }

    file = util_fopen("/proc/stat", "r");
    if (file == NULL) {
        ERROR("Failed to open '/proc/stat'");
        return -1;
    }

    ioWait = irq = softIrq = steal = guest = guestnice = 0;

    /*
     * Depending on your kernel version,
     * 5, 7, 8 or 9 of these fields will be set.
     * The rest will remain at zero.
     */
    tmp = fgets(buffer, BUFSIZ, file);
    if (tmp == NULL) {
        ret = -1;
        goto out;
    }
    nret = sscanf(buffer, "cpu  %16llu %16llu %16llu %16llu %16llu %16llu %16llu %16llu %16llu %16llu", &usertime,
                  &nicetime, &systemtime, &idletime, &ioWait, &irq, &softIrq, &steal, &guest, &guestnice);
    if (nret != BUFFER_ITEM_NUMS) {
        ERROR("sscanf buffer failed");
        ret = -1;
        goto out;
    }

    total = usertime + nicetime + systemtime + idletime + ioWait + irq + softIrq;

    *val = tick_to_ns(total);
out:
    fclose(file);
    return ret;
}

/* isulad server conf wrlock */
int isulad_server_conf_wrlock()
{
    int ret = 0;

    if (pthread_rwlock_wrlock(&g_isulad_conf.isulad_conf_rwlock)) {
        ERROR("Failed to acquire isulad conf write lock");
        ret = -1;
    }

    return ret;
}

/* isulad server conf rdlock */
int isulad_server_conf_rdlock()
{
    int ret = 0;

    if (pthread_rwlock_rdlock(&g_isulad_conf.isulad_conf_rwlock)) {
        ERROR("Failed to acquire isulad conf read lock");
        ret = -1;
    }

    return ret;
}

/* isulad server conf unlock */
int isulad_server_conf_unlock()
{
    int ret = 0;

    if (pthread_rwlock_unlock(&g_isulad_conf.isulad_conf_rwlock)) {
        ERROR("Failed to release isulad conf lock");
        ret = -1;
    }

    return ret;
}

struct service_arguments *conf_get_server_conf()
{
    return g_isulad_conf.server_conf;
}

/* conf get isulad pidfile */
char *conf_get_isulad_pidfile()
{
    char *filename = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs == NULL || conf->json_confs->pidfile == NULL) {
        goto out;
    }

    filename = util_strdup_s(conf->json_confs->pidfile);

out:
    (void)isulad_server_conf_unlock();
    return filename;
}

/* conf get engine rootpath */
char *conf_get_engine_rootpath()
{
    char *epath = NULL;
    char *rootpath = NULL;
    size_t len;

    rootpath = conf_get_isulad_rootdir();
    if (rootpath == NULL) {
        ERROR("Get rootpath failed");
        return epath;
    }
    if (strlen(rootpath) > (SIZE_MAX - strlen(ENGINE_ROOTPATH_NAME)) - 2) {
        ERROR("Root path is too long");
        goto free_out;
    }
    len = strlen(rootpath) + 1 + strlen(ENGINE_ROOTPATH_NAME) + 1;
    if (len > PATH_MAX) {
        ERROR("The size of path exceeds the limit");
        goto free_out;
    }
    epath = util_common_calloc_s(len);
    if (epath == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    int nret = snprintf(epath, len, "%s/%s", rootpath, ENGINE_ROOTPATH_NAME);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Sprintf engine path failed");
        free(epath);
        epath = NULL;
    }

free_out:
    free(rootpath);
    return epath;
}

int conf_get_cgroup_cpu_rt(int64_t *cpu_rt_period, int64_t *cpu_rt_runtime)
{
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return -1;
    }

    conf = conf_get_server_conf();
    if (conf == NULL) {
        (void)isulad_server_conf_unlock();
        return -1;
    }

    *cpu_rt_period = conf->json_confs->cpu_rt_period;
    *cpu_rt_runtime = conf->json_confs->cpu_rt_runtime;

    if (isulad_server_conf_unlock() != 0) {
        return -1;
    }

    return 0;
}

/* conf get graph checked flag file path */
char *conf_get_graph_check_flag_file()
{
    char *epath = NULL;
    char *rootpath = NULL;
    size_t len;

    rootpath = conf_get_isulad_rootdir();
    if (rootpath == NULL) {
        ERROR("Get rootpath failed");
        return epath;
    }
    if (strlen(rootpath) >
        ((SIZE_MAX - strlen(OCI_IMAGE_GRAPH_ROOTPATH_NAME)) - strlen(GRAPH_ROOTPATH_CHECKED_FLAG)) - 3) {
        ERROR("Root path is too long");
        goto free_out;
    }
    len = strlen(rootpath) + 1 + strlen(OCI_IMAGE_GRAPH_ROOTPATH_NAME) + 1 + strlen(GRAPH_ROOTPATH_CHECKED_FLAG) + 1;
    if (len > PATH_MAX) {
        ERROR("The size of path exceeds the limit");
        goto free_out;
    }
    epath = util_common_calloc_s(len);
    if (epath == NULL) {
        ERROR("Out of memory");
        goto free_out;
    }

    int nret = snprintf(epath, len, "%s/%s/%s", rootpath, OCI_IMAGE_GRAPH_ROOTPATH_NAME, GRAPH_ROOTPATH_CHECKED_FLAG);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Sprintf graph checked flag failed");
        free(epath);
        epath = NULL;
    }

free_out:
    free(rootpath);
    return epath;
}

/* conf get routine rootdir */
char *conf_get_routine_rootdir(const char *runtime)
{
    char *path = NULL;
    struct service_arguments *conf = NULL;
    size_t len = 0;

    if (runtime == NULL) {
        ERROR("Runtime is NULL");
        return NULL;
    }

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->graph == NULL) {
        ERROR("Server conf is NULL or rootpath is NULL");
        goto out;
    }

    /* path = conf->rootpath + / + engines + / + runtime + /0 */
    if (strlen(conf->json_confs->graph) > (SIZE_MAX - strlen(ENGINE_ROOTPATH_NAME)) - 3) {
        ERROR("Graph path is too long");
        goto out;
    }
    len = strlen(conf->json_confs->graph) + 1 + strlen(ENGINE_ROOTPATH_NAME) + 1 + strlen(runtime) + 1;
    if (len > PATH_MAX / sizeof(char)) {
        ERROR("The size of path exceeds the limit");
        goto out;
    }
    path = util_common_calloc_s(sizeof(char) * len);
    if (path == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    int nret = snprintf(path, len, "%s/%s/%s", conf->json_confs->graph, ENGINE_ROOTPATH_NAME, runtime);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Failed to sprintf path");
        free(path);
        path = NULL;
    }

out:
    (void)isulad_server_conf_unlock();
    return path;
}

/* conf get routine statedir */
char *conf_get_routine_statedir(const char *runtime)
{
    char *path = NULL;
    struct service_arguments *conf = NULL;
    size_t len = 0;

    if (runtime == NULL) {
        return NULL;
    }

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->state == NULL) {
        goto out;
    }

    /* path = conf->statepath + / + runtime + /0 */
    if (strlen(conf->json_confs->state) > (SIZE_MAX - strlen(runtime)) - 2) {
        ERROR("State path is too long");
        goto out;
    }
    len = strlen(conf->json_confs->state) + 1 + strlen(runtime) + 1;
    if (len > PATH_MAX) {
        goto out;
    }
    path = util_common_calloc_s(sizeof(char) * len);
    if (path == NULL) {
        goto out;
    }

    int nret = snprintf(path, len, "%s/%s", conf->json_confs->state, runtime);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("sprintf path failed");
        free(path);
        path = NULL;
    }

out:
    (void)isulad_server_conf_unlock();
    return path;
}

/* conf get isulad rootdir */
char *conf_get_isulad_rootdir()
{
    char *path = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->graph == NULL) {
        goto out;
    }

    path = util_strdup_s(conf->json_confs->graph);

out:
    (void)isulad_server_conf_unlock();
    return path;
}

/* conf get registry */
char **conf_get_registry_list()
{
    int nret = 0;
    size_t i;
    char **opts = NULL;
    char *p = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->registry_mirrors_len == 0) {
        goto out;
    }

    for (i = 0; i < conf->json_confs->registry_mirrors_len; i++) {
        p = conf->json_confs->registry_mirrors[i];
        if (p == NULL) {
            break;
        }
        nret = util_array_append(&opts, p);
        if (nret != 0) {
            ERROR("Out of memory");
            util_free_array(opts);
            opts = NULL;
            goto out;
        }
    }
out:
    (void)isulad_server_conf_unlock();
    return opts;
}

/* conf get insecure registry */
char **conf_get_insecure_registry_list()
{
    int nret = 0;
    size_t i;
    char **opts = NULL;
    char *p = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->insecure_registries_len == 0) {
        goto out;
    }

    for (i = 0; i < conf->json_confs->insecure_registries_len; i++) {
        p = conf->json_confs->insecure_registries[i];
        if (p == NULL) {
            break;
        }
        nret = util_array_append(&opts, p);
        if (nret != 0) {
            util_free_array(opts);
            opts = NULL;
            ERROR("Out of memory");
            break;
        }
    }
out:
    (void)isulad_server_conf_unlock();
    return opts;
}

/* conf get isulad statedir */
char *conf_get_isulad_statedir()
{
    char *path = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->state == NULL) {
        goto out;
    }

    path = util_strdup_s(conf->json_confs->state);

out:
    (void)isulad_server_conf_unlock();
    return path;
}

/* isulad monitor fifo name */
char *conf_get_isulad_monitor_fifo_path()
{
    int ret;
    char fifo_file_path[PATH_MAX] = { 0 };
    char *rootpath = NULL;
    char *result = NULL;

    rootpath = conf_get_isulad_statedir();
    if (rootpath == NULL) {
        ERROR("Invalid parameter");
        goto out;
    }
    ret = snprintf(fifo_file_path, PATH_MAX, "%s/monitord_fifo", rootpath);
    if (ret < 0 || (size_t)ret >= PATH_MAX) {
        ERROR("Create monitord fifo path failed");
        goto out;
    }

    result = util_strdup_s(fifo_file_path);

out:
    free(rootpath);
    return result;
}

/* conf get isulad mount rootfs */
char *conf_get_isulad_mount_rootfs()
{
    char *path = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->rootfsmntdir == NULL) {
        goto out;
    }

    path = util_strdup_s(conf->json_confs->rootfsmntdir);

out:
    (void)isulad_server_conf_unlock();
    return path;
}

/* conf get isulad umask for containers */
char *conf_get_isulad_native_umask()
{
    char *umask = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->native_umask == NULL) {
        goto out;
    }

    umask = util_strdup_s(conf->json_confs->native_umask);

out:
    (void)isulad_server_conf_unlock();
    return umask;
}

/* conf get isulad cgroup parent for containers */
char *conf_get_isulad_cgroup_parent()
{
    char *cgroup_parent = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->cgroup_parent == NULL) {
        goto out;
    }

    cgroup_parent = util_strdup_s(conf->json_confs->cgroup_parent);

out:
    (void)isulad_server_conf_unlock();
    return cgroup_parent;
}

/* conf get isulad engine */
char *conf_get_isulad_engine()
{
    char *engine = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->engine == NULL) {
        goto out;
    }

    engine = util_strdup_s(conf->json_confs->engine);

out:
    (void)isulad_server_conf_unlock();
    return engine;
}

/* conf get isulad loglevel */
char *conf_get_isulad_loglevel()
{
    char *loglevel = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->log_level == NULL) {
        goto out;
    }

    loglevel = util_strdup_s(conf->json_confs->log_level);

out:
    (void)isulad_server_conf_unlock();
    return loglevel;
}

/* get log file helper */
char *get_log_file_helper(const struct service_arguments *conf, const char *suffix)
{
    char *logfile = NULL;
    size_t len = 0;
    int nret = 0;

    if (suffix == NULL) {
        return NULL;
    }

    // log_file path = parent path + "/" + suffix
    if (strlen(conf->logpath) > (SIZE_MAX - strlen(suffix)) - 2) {
        ERROR("Log path is too long");
        return NULL;
    }
    len = strlen(conf->logpath) + 1 + strlen(suffix) + 1;
    if (len > PATH_MAX) {
        ERROR("The size of path exceeds the limit");
        return NULL;
    }
    logfile = util_common_calloc_s(len * sizeof(char));
    if (logfile == NULL) {
        ERROR("Out of memory");
        goto out;
    }

    nret = snprintf(logfile, len, "%s/%s", conf->logpath, suffix);
    if (nret < 0 || (size_t)nret >= len) {
        free(logfile);
        logfile = NULL;
        ERROR("Failed to sprintf log path");
    }

out:
    return logfile;
}

/* conf get isulad log gather fifo path */
char *conf_get_isulad_log_gather_fifo_path()
{
#define LOG_GATHER_FIFO_NAME "/isulad_log_gather_fifo"
    char *logfile = NULL;
    char *statedir = NULL;
    size_t len = 0;
    int nret;

    statedir = conf_get_isulad_statedir();
    if (statedir == NULL) {
        ERROR("Get isulad statedir failed");
        goto err_out;
    }
    if (strlen(statedir) > (SIZE_MAX - strlen(LOG_GATHER_FIFO_NAME)) - 1) {
        ERROR("State path is too long");
        goto err_out;
    }
    len = strlen(statedir) + strlen(LOG_GATHER_FIFO_NAME) + 1;
    if (len > PATH_MAX) {
        ERROR("Too long path: %s", statedir);
        goto err_out;
    }
    logfile = util_common_calloc_s(len);
    if (logfile == NULL) {
        ERROR("Out of memory");
        goto err_out;
    }
    nret = snprintf(logfile, len, "%s%s", statedir, LOG_GATHER_FIFO_NAME);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Sprintf log file failed");
        goto err_out;
    }
    goto out;

err_out:
    free(logfile);
    logfile = NULL;
out:
    free(statedir);
    return logfile;
}

/* conf get isulad log file */
char *conf_get_isulad_log_file()
{
    char *logfile = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->logpath == NULL) {
        goto out;
    }

    logfile = get_log_file_helper(conf, "isulad.log");

out:
    (void)isulad_server_conf_unlock();
    return logfile;
}

/* conf get engine log file */
char *conf_get_engine_log_file()
{
    char *logfile = NULL;
    char *full_path = NULL;
    char *prefix = "fifo:";
    size_t len = 0;

    logfile = conf_get_isulad_log_gather_fifo_path();
    if (logfile == NULL) {
        ERROR("conf_get_isulad_log_gather_fifo_path failed");
        goto out;
    }
    len = strlen(prefix) + strlen(logfile) + 1;
    if (len > PATH_MAX) {
        ERROR("The size of path exceeds the limit");
        goto out;
    }
    full_path = util_common_calloc_s(len * sizeof(char));
    if (full_path == NULL) {
        FATAL("Out of Memory");
        goto out;
    }
    int nret = snprintf(full_path, len, "%s%s", prefix, logfile);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Failed to sprintf engine log path");
        free(full_path);
        full_path = NULL;
        goto out;
    }

out:
    free(logfile);
    return full_path;
}

int conf_get_daemon_log_config(char **loglevel, char **logdriver, char **engine_log_path)
{
    *loglevel = conf_get_isulad_loglevel();
    if (*loglevel == NULL) {
        ERROR("DoStart: Failed to get log level");
        return -1;
    }
    *logdriver = conf_get_isulad_logdriver();
    if (*logdriver == NULL) {
        ERROR("DoStart: Failed to get log driver");
        return -1;
    }
    *engine_log_path = conf_get_engine_log_file();
    if (strcmp(*logdriver, "file") == 0 && *engine_log_path == NULL) {
        ERROR("DoStart: Log driver is file, but engine log path is NULL");
        return -1;
    }
    return 0;
}

/* conf get isulad logdriver */
char *conf_get_isulad_logdriver()
{
    char *logdriver = NULL;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->log_driver == NULL) {
        goto out;
    }

    logdriver = util_strdup_s(conf->json_confs->log_driver);

out:
    (void)isulad_server_conf_unlock();
    return logdriver;
}

/* conf get default container log opts */
int conf_get_container_log_opts(isulad_daemon_configs_container_log **opts)
{
    struct service_arguments *conf = NULL;
    isulad_daemon_configs_container_log *result = NULL;
    isulad_daemon_configs_container_log *work = NULL;
    size_t i;
    int ret = 0;

    if (isulad_server_conf_rdlock() != 0) {
        return -1;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->container_log == NULL) {
        goto out;
    }
    work = conf->json_confs->container_log;

    result = util_common_calloc_s(sizeof(isulad_daemon_configs_container_log));
    if (result == NULL) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    result->driver = util_strdup_s(work->driver);
    if (work->opts == NULL) {
        *opts = result;
        result = NULL;
        goto out;
    }
    if (work->opts->len > 0) {
        result->opts = util_common_calloc_s(sizeof(json_map_string_string));
        if (result->opts == NULL) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }
    for (i = 0; i < work->opts->len; i++) {
        if (append_json_map_string_string(result->opts, work->opts->keys[i], work->opts->values[i]) != 0) {
            ERROR("Out of memory");
            ret = -1;
            goto out;
        }
    }

    *opts = result;
    result = NULL;
out:
    (void)isulad_server_conf_unlock();
    free_isulad_daemon_configs_container_log(result);
    return ret;
}

/* conf get image layer check flag */
bool conf_get_image_layer_check_flag()
{
    bool check_flag = false;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return false;
    }

    conf = conf_get_server_conf();
    if (conf == NULL) {
        goto out;
    }

    check_flag = conf->json_confs->image_layer_check;

out:
    (void)isulad_server_conf_unlock();
    return check_flag;
}

/* conf get flag of use decrypted key to pull image */
bool conf_get_use_decrypted_key_flag()
{
    bool check_flag = true;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return false;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs->use_decrypted_key == NULL) {
        goto out;
    }

    check_flag = *(conf->json_confs->use_decrypted_key);

out:
    (void)isulad_server_conf_unlock();
    return check_flag;
}

bool conf_get_skip_insecure_verify_flag()
{
    bool check_flag = false;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return false;
    }

    conf = conf_get_server_conf();
    if (conf == NULL) {
        goto out;
    }

    check_flag = conf->json_confs->insecure_skip_verify_enforce;

out:
    (void)isulad_server_conf_unlock();
    return check_flag;
}

#define OCI_STR_ARRAY_DUP(src, dest, srclen, destlen, ret)               \
    do {                                                                 \
        if ((src) != NULL) {                                             \
            (dest) = util_str_array_dup((const char **)(src), (srclen)); \
            if ((dest) == NULL) {                                        \
                (ret) = -1;                                              \
                goto out;                                                \
            }                                                            \
            (destlen) = (srclen);                                        \
        }                                                                \
    } while (0)

#define HOOKS_ELEM_DUP_DEF(item)                                                      \
    defs_hook *hooks_##item##_elem_dup(const defs_hook *src)                          \
    {                                                                                 \
        int ret = 0;                                                                  \
        defs_hook *dest = NULL;                                                       \
        if (src == NULL)                                                              \
            return NULL;                                                              \
        dest = util_common_calloc_s(sizeof(defs_hook));                               \
        if (dest == NULL)                                                             \
            return NULL;                                                              \
        dest->path = util_strdup_s(src->path);                                        \
        OCI_STR_ARRAY_DUP(src->args, dest->args, src->args_len, dest->args_len, ret); \
        OCI_STR_ARRAY_DUP(src->env, dest->env, src->env_len, dest->env_len, ret);     \
        dest->timeout = src->timeout;                                                 \
    out:                                                                              \
        if (ret != 0 && dest != NULL) {                                               \
            free_defs_hook(dest);                                                     \
            dest = NULL;                                                              \
        }                                                                             \
        return dest;                                                                  \
    }

/* HOOKS ELEM DUP DEF */
HOOKS_ELEM_DUP_DEF(prestart)
/* HOOKS ELEM DUP DEF */
HOOKS_ELEM_DUP_DEF(poststart)
/* HOOKS ELEM DUP DEF */
HOOKS_ELEM_DUP_DEF(poststop)

#define HOOKS_ITEM_DUP_DEF(item)                                                            \
    int hooks_##item##_dup(oci_runtime_spec_hooks *dest, const oci_runtime_spec_hooks *src) \
    {                                                                                       \
        int i = 0;                                                                          \
        if (src->item##_len > SIZE_MAX / sizeof(defs_hook *) - 1) {                         \
            return -1;                                                                      \
        }                                                                                   \
        dest->item = util_common_calloc_s(sizeof(defs_hook *) * (src->item##_len + 1));     \
        if (dest->item == NULL)                                                             \
            return -1;                                                                      \
        dest->item##_len = src->item##_len;                                                 \
        for (; (size_t)i < src->item##_len; ++i) {                                          \
            dest->item[i] = hooks_##item##_elem_dup(src->item[i]);                          \
            if (dest->item[i] == NULL)                                                      \
                return -1;                                                                  \
        }                                                                                   \
        return 0;                                                                           \
    }

/* HOOKS ITEM DUP DEF */
HOOKS_ITEM_DUP_DEF(prestart)
/* HOOKS ITEM DUP DEF */
HOOKS_ITEM_DUP_DEF(poststart)
/* HOOKS ITEM DUP DEF */
HOOKS_ITEM_DUP_DEF(poststop)

/* hooks_dup */
oci_runtime_spec_hooks *hooks_dup(const oci_runtime_spec_hooks *src)
{
    int ret = 0;
    oci_runtime_spec_hooks *dest = NULL;

    if (src == NULL) {
        return NULL;
    }
    dest = util_common_calloc_s(sizeof(oci_runtime_spec_hooks));
    if (dest == NULL) {
        return NULL;
    }

    ret = hooks_prestart_dup(dest, src);
    if (ret != 0) {
        goto out;
    }

    ret = hooks_poststart_dup(dest, src);
    if (ret != 0) {
        goto out;
    }

    ret = hooks_poststop_dup(dest, src);

out:
    if (ret != 0) {
        free_oci_runtime_spec_hooks(dest);
        dest = NULL;
    }
    return dest;
}

/* conf get isulad hooks */
int conf_get_isulad_hooks(oci_runtime_spec_hooks **phooks)
{
    int ret = 0;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return -1;
    }

    conf = conf_get_server_conf();
    if (conf != NULL && conf->hooks != NULL) {
        *phooks = hooks_dup(conf->hooks);
        if ((*phooks) == NULL) {
            ret = -1;
            goto out;
        }
    } else {
        *phooks = NULL;
    }
out:
    (void)isulad_server_conf_unlock();
    return ret;
}

/* conf get isulad default ulimit */
int conf_get_isulad_default_ulimit(host_config_ulimits_element ***ulimit)
{
    int ret = 0;
    size_t i, ulimit_len;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return -1;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->default_ulimit_len == 0) {
        *ulimit = NULL;
        goto out;
    }

    for (i = 0; i < conf->default_ulimit_len; i++) {
        ulimit_len = ulimit_array_len(*ulimit);
        if (ulimit_array_append(ulimit, conf->default_ulimit[i], ulimit_len) != 0) {
            ERROR("ulimit append failed");
            ret = -1;
            goto out;
        }
    }
out:
    (void)isulad_server_conf_unlock();
    return ret;
}

/* conf get start timeout */
unsigned int conf_get_start_timeout()
{
    struct service_arguments *conf = NULL;
    unsigned int ret = 0;
    if (isulad_server_conf_rdlock() != 0) {
        return 0;
    }

    conf = conf_get_server_conf();
    if (conf == NULL) {
        goto out;
    }

    ret = conf->start_timeout;

out:
    (void)isulad_server_conf_unlock();
    return ret;
}

char *conf_get_default_runtime()
{
    struct service_arguments *conf = NULL;
    char *result = NULL;

    if (isulad_server_conf_rdlock()) {
        ERROR("BUG conf_rdlock failed");
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs == NULL) {
        goto out;
    }

    result = util_strings_to_lower(conf->json_confs->default_runtime);

out:
    (void)isulad_server_conf_unlock();
    return result;
}

char *conf_get_enable_plugins()
{
    struct service_arguments *conf = NULL;
    char *plugins = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        ERROR("BUG conf_rdlock failed");
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs == NULL || conf->json_confs->enable_plugins == NULL) {
        goto out;
    }

    plugins = util_strdup_s(conf->json_confs->enable_plugins);

out:
    (void)isulad_server_conf_unlock();
    return plugins;
}

/* conf get cni config dir */
char *conf_get_cni_conf_dir()
{
    char *dir = NULL;
    const char *default_conf_dir = "/etc/cni/net.d";
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        ERROR("BUG conf_rdlock failed");
        return NULL;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs == NULL || conf->json_confs->cni_conf_dir == NULL) {
        dir = util_strdup_s(default_conf_dir);
    } else {
        dir = util_strdup_s(conf->json_confs->cni_conf_dir);
    }

    (void)isulad_server_conf_unlock();
    return dir;
}

/* conf get cni binary dir */
int conf_get_cni_bin_dir(char ***dst)
{
    char **dir = NULL;
    const char *default_bin_dir = "/opt/cni/bin";
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        ERROR("BUG conf_rdlock failed");
        return -1;
    }

    conf = conf_get_server_conf();
    if (conf == NULL || conf->json_confs == NULL || conf->json_confs->cni_bin_dir == NULL) {
        (void)util_array_append(&dir, default_bin_dir);
    } else {
        dir = util_string_split(conf->json_confs->cni_bin_dir, ';');
        if (dir == NULL) {
            ERROR("String split failed");
            return -1;
        }
    }

    if (isulad_server_conf_unlock() != 0) {
        ERROR("BUG conf_unlock failed");
        util_free_array(dir);
        return -1;
    }

    *dst = dir;
    return util_array_len((const char **)dir);
}

/* conf get websocket server listening port */
int32_t conf_get_websocket_server_listening_port()
{
    int32_t port = 0;
    struct service_arguments *conf = NULL;

    if (isulad_server_conf_rdlock() != 0) {
        return port;
    }

    conf = conf_get_server_conf();
    if (conf == NULL) {
        goto out;
    }

    port = conf->json_confs->websocket_server_listening_port;

out:
    (void)isulad_server_conf_unlock();
    return port;
}

/* save args to conf */
int save_args_to_conf(struct service_arguments *args)
{
    int ret = 0;

    ret = pthread_rwlock_init(&g_isulad_conf.isulad_conf_rwlock, NULL);
    if (ret != 0) {
        ERROR("Failed to init isulad conf rwlock");
        ret = -1;
        goto out;
    }

    if (pthread_rwlock_wrlock(&g_isulad_conf.isulad_conf_rwlock) != 0) {
        ERROR("Failed to acquire isulad conf write lock");
        ret = -1;
        goto out;
    }

    if (g_isulad_conf.server_conf != NULL) {
        service_arguments_free(g_isulad_conf.server_conf);
        free(g_isulad_conf.server_conf);
    }
    g_isulad_conf.server_conf = args;

    if (pthread_rwlock_unlock(&g_isulad_conf.isulad_conf_rwlock) != 0) {
        ERROR("Failed to release isulad conf write lock");
        ret = -1;
        goto out;
    }
out:
    return ret;
}

/* set socket group */
int set_unix_socket_group(const char *socket, const char *group)
{
    const char *path = NULL;
    char rpath[PATH_MAX + 1] = { 0x00 };
    int ret = 0;
    int nret = 0;

    if (socket == NULL || group == NULL) {
        return -1;
    }

    path = socket + strlen(UNIX_SOCKET_PREFIX);

    if (strlen(path) > PATH_MAX || realpath(path, rpath) == NULL) {
        ERROR("ensure socket path %s failed", path);
        ret = -1;
        goto out;
    }
    INFO("set socket: %s with group: %s", socket, group);
    nret = util_set_file_group(rpath, group);
    if (nret < 0) {
        ERROR("set group of the path: %s failed", rpath);
        ret = -1;
        goto out;
    }

    if (chmod(rpath, SOCKET_GROUP_DIRECTORY_MODE) != 0) {
        DEBUG("Failed to chmod for socket: %s", rpath);
        ret = -1;
        goto out;
    }

out:
    if (ret == 0) {
        DEBUG("Listener created for HTTP on unix (%s)", rpath);
    }

    return ret;
}

#define OVERRIDE_STRING_VALUE(dst, src)            \
    do {                                           \
        if ((src) != NULL && strlen((src)) != 0) { \
            free((dst));                           \
            (dst) = (src);                         \
            (src) = NULL;                          \
        }                                          \
    } while (0)

static int string_array_append(char **suffix, size_t suffix_len, size_t *curr_len, char ***result)
{
    if (suffix_len > 0) {
        size_t new_len = *curr_len + suffix_len;
        size_t work_len = *curr_len;
        size_t i, j;

        if (util_grow_array(result, &work_len, new_len, INCREMENT_INTREVAL) != 0) {
            return -1;
        }
        for (i = *curr_len, j = 0; i < new_len; i++) {
            (*result)[i] = suffix[j];
            suffix[j++] = NULL;
        }
        *curr_len = new_len;
    }

    return 0;
}

int parse_log_opts(struct service_arguments *args, const char *key, const char *value)
{
    int ret = -1;

    if (key == NULL || value == NULL) {
        return 0;
    }
    // support new driver options, add here
    if (strcmp(key, "log-path") == 0) {
        free(args->logpath);
        args->logpath = util_strdup_s(value);
        ret = 0;
    } else if (strcmp(key, "log-file-mode") == 0) {
        unsigned int file_mode = 0;
        if (util_safe_uint(value, &file_mode) == 0) {
            args->log_file_mode = file_mode;
            ret = 0;
        }
    } else if (strcmp(key, "max-file") == 0) {
        int tmaxfile = 0;
        if (util_safe_int(value, &tmaxfile) == 0 && tmaxfile > 0) {
            args->max_file = tmaxfile;
            ret = 0;
        }
    } else if (strcmp(key, "max-size") == 0) {
        int64_t tmaxsize = 0;
        if (util_parse_byte_size_string(value, &tmaxsize) == 0 && tmaxsize > 0) {
            args->max_size = tmaxsize;
            ret = 0;
        }
    } else {
        ERROR("Invalid config: %s = %s", key, value);
    }

    return ret;
}

static inline void override_string_value(char **dst, char **src)
{
    if (*src == NULL || (*src)[0] == '\0') {
        return;
    }
    free(*dst);
    *dst = *src;
    *src = NULL;
}

static inline void override_bool_pointer_value(bool **dst, bool **src)
{
    if (*src == NULL) {
        return;
    }
    free(*dst);
    *dst = *src;
    *src = NULL;
}

static int merge_hosts_conf_into_global(struct service_arguments *args, const isulad_daemon_configs *tmp_json_confs)
{
    size_t i, j;

    for (i = 0; i < tmp_json_confs->hosts_len; i++) {
        for (j = 0; j < args->json_confs->hosts_len; j++) {
            if (strcmp(args->json_confs->hosts[j], tmp_json_confs->hosts[i]) == 0) {
                break;
            }
        }
        if (j != args->json_confs->hosts_len) {
            continue;
        }

        if (util_array_append(&(args->json_confs->hosts), tmp_json_confs->hosts[i]) != 0) {
            ERROR("merge hosts config failed");
            return -1;
        }
        args->json_confs->hosts_len++;
        if (args->json_confs->hosts_len > MAX_HOSTS) {
            isulad_set_error_message("Too many hosts, the max number is %d", MAX_HOSTS);
            return -1;
        }
    }

    return 0;
}

static int do_merge_daemon_logs_conf(struct service_arguments *args, isulad_daemon_configs *tmp_json_confs)
{
    size_t i;

    override_string_value(&args->json_confs->log_level, &tmp_json_confs->log_level);
    override_string_value(&args->json_confs->log_driver, &tmp_json_confs->log_driver);

    for (i = 0; tmp_json_confs->log_opts != NULL && i < tmp_json_confs->log_opts->len; i++) {
        if (parse_log_opts(args, tmp_json_confs->log_opts->keys[i], tmp_json_confs->log_opts->values[i]) != 0) {
            COMMAND_ERROR("Failed to parse log options %s:%s", tmp_json_confs->log_opts->keys[i],
                          tmp_json_confs->log_opts->values[i]);
            return -1;
        }
        if (append_json_map_string_string(args->json_confs->log_opts, tmp_json_confs->log_opts->keys[i],
                                          tmp_json_confs->log_opts->values[i]) != 0) {
            ERROR("Out of memory");
            return -1;
        }
    }

    return 0;
}

// just mask isulad config to args
static int do_merge_container_logs_conf(struct service_arguments *args, isulad_daemon_configs *tmp_json_confs)
{
    if (tmp_json_confs->container_log == NULL) {
        return 0;
    }

    // do not check valid of json log opts at here;
    // while all config ready to do check.
    free_isulad_daemon_configs_container_log(args->json_confs->container_log);
    args->json_confs->container_log = tmp_json_confs->container_log;
    tmp_json_confs->container_log = NULL;

    return 0;
}

static int merge_logs_conf_into_global(struct service_arguments *args, isulad_daemon_configs *tmp_json_confs)
{
    if (do_merge_daemon_logs_conf(args, tmp_json_confs)) {
        return -1;
    }

    return do_merge_container_logs_conf(args, tmp_json_confs);
}

static int merge_authorization_conf_into_global(struct service_arguments *args, isulad_daemon_configs *tmp_json_confs)
{
    args->json_confs->tls = tmp_json_confs->tls;
    args->json_confs->tls_verify = tmp_json_confs->tls_verify;
    if (tmp_json_confs->tls_config != NULL) {
        override_string_value(&args->json_confs->tls_config->ca_file, &tmp_json_confs->tls_config->ca_file);
        override_string_value(&args->json_confs->tls_config->cert_file, &tmp_json_confs->tls_config->cert_file);
        override_string_value(&args->json_confs->tls_config->key_file, &tmp_json_confs->tls_config->key_file);
    }
    if (tmp_json_confs->authorization_plugin != NULL) {
        override_string_value(&args->json_confs->authorization_plugin, &tmp_json_confs->authorization_plugin);
    }

    return 0;
}

static int merge_storage_conf_into_global(struct service_arguments *args, isulad_daemon_configs *tmp_json_confs)
{
    override_string_value(&args->json_confs->storage_driver, &tmp_json_confs->storage_driver);

    if (string_array_append(tmp_json_confs->storage_opts, tmp_json_confs->storage_opts_len,
                            &(args->json_confs->storage_opts_len), &(args->json_confs->storage_opts)) != 0) {
        ERROR("merge graph config failed");
        return -1;
    }

    return 0;
}

static int merge_registry_conf_into_global(struct service_arguments *args, isulad_daemon_configs *tmp_json_confs)
{
    if (string_array_append(tmp_json_confs->registry_mirrors, tmp_json_confs->registry_mirrors_len,
                            &(args->json_confs->registry_mirrors_len), &(args->json_confs->registry_mirrors)) != 0) {
        ERROR("merge registry mirrors config failed");
        return -1;
    }

    if (string_array_append(tmp_json_confs->insecure_registries, tmp_json_confs->insecure_registries_len,
                            &(args->json_confs->insecure_registries_len),
                            &(args->json_confs->insecure_registries)) != 0) {
        ERROR("merge insecure registries config failed");
        return -1;
    }

    return 0;
}

static int merge_default_ulimits_conf_into_global(struct service_arguments *args, isulad_daemon_configs *tmp_json_confs)
{
    if (tmp_json_confs == NULL) {
        return -1;
    }

    if (tmp_json_confs->default_ulimits == NULL) {
        return 0;
    }

    args->json_confs->default_ulimits = tmp_json_confs->default_ulimits;
    tmp_json_confs->default_ulimits = NULL;
    return 0;
}

int merge_json_confs_into_global(struct service_arguments *args)
{
    isulad_daemon_configs *tmp_json_confs;
    parser_error err = NULL;
    int ret = 0;

    tmp_json_confs = isulad_daemon_configs_parse_file(ISULAD_DAEMON_JSON_CONF_FILE, NULL, &err);
    if (tmp_json_confs == NULL) {
        COMMAND_ERROR("Load isulad json config failed: %s", err != NULL ? err : "");
        ret = -1;
        goto out;
    }
    // Daemon socket option
    if (merge_hosts_conf_into_global(args, tmp_json_confs)) {
        ret = -1;
        goto out;
    }

    override_string_value(&args->json_confs->default_runtime, &tmp_json_confs->default_runtime);
    override_string_value(&args->json_confs->group, &tmp_json_confs->group);
    override_string_value(&args->json_confs->graph, &tmp_json_confs->graph);
    override_string_value(&args->json_confs->state, &tmp_json_confs->state);

    if (merge_logs_conf_into_global(args, tmp_json_confs)) {
        ret = -1;
        goto out;
    }

    override_string_value(&args->json_confs->pidfile, &tmp_json_confs->pidfile);
    // iSulad runtime execution options
    override_string_value(&args->json_confs->engine, &tmp_json_confs->engine);
    override_string_value(&args->json_confs->hook_spec, &tmp_json_confs->hook_spec);
    override_string_value(&args->json_confs->enable_plugins, &tmp_json_confs->enable_plugins);
    override_string_value(&args->json_confs->native_umask, &tmp_json_confs->native_umask);
    override_string_value(&args->json_confs->cgroup_parent, &tmp_json_confs->cgroup_parent);
    override_string_value(&args->json_confs->rootfsmntdir, &tmp_json_confs->rootfsmntdir);
    override_string_value(&args->json_confs->start_timeout, &tmp_json_confs->start_timeout);
    override_string_value(&args->json_confs->pod_sandbox_image, &tmp_json_confs->pod_sandbox_image);
    override_string_value(&args->json_confs->network_plugin, &tmp_json_confs->network_plugin);
    override_string_value(&args->json_confs->cni_bin_dir, &tmp_json_confs->cni_bin_dir);
    override_string_value(&args->json_confs->cni_conf_dir, &tmp_json_confs->cni_conf_dir);

    args->json_confs->runtimes = tmp_json_confs->runtimes;
    tmp_json_confs->runtimes = NULL;

    // Daemon storage-driver
    if (merge_storage_conf_into_global(args, tmp_json_confs)) {
        ret = -1;
        goto out;
    }

    if (merge_registry_conf_into_global(args, tmp_json_confs)) {
        ret = -1;
        goto out;
    }

    if (tmp_json_confs->cpu_rt_period > 0) {
        args->json_confs->cpu_rt_period = tmp_json_confs->cpu_rt_period;
    }

    if (tmp_json_confs->cpu_rt_runtime > 0) {
        args->json_confs->cpu_rt_runtime = tmp_json_confs->cpu_rt_runtime;
    }

    if (tmp_json_confs->image_service) {
        args->json_confs->image_service = tmp_json_confs->image_service;
    }
    if (tmp_json_confs->image_layer_check) {
        args->json_confs->image_layer_check = tmp_json_confs->image_layer_check;
    }

    if (tmp_json_confs->websocket_server_listening_port) {
        args->json_confs->websocket_server_listening_port = tmp_json_confs->websocket_server_listening_port;
    }

    override_bool_pointer_value(&args->json_confs->use_decrypted_key, &tmp_json_confs->use_decrypted_key);

    if (tmp_json_confs->insecure_skip_verify_enforce) {
        args->json_confs->insecure_skip_verify_enforce = tmp_json_confs->insecure_skip_verify_enforce;
    }

    if (merge_authorization_conf_into_global(args, tmp_json_confs)) {
        ret = -1;
        goto out;
    }

    if (merge_default_ulimits_conf_into_global(args, tmp_json_confs)) {
        ret = -1;
        goto out;
    }

#ifdef ENABLE_SELINUX
    args->json_confs->selinux_enabled = tmp_json_confs->selinux_enabled;
#endif

out:
    free(err);
    free_isulad_daemon_configs(tmp_json_confs);
    return ret;
}
