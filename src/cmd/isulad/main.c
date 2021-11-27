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
 * Author: lifeng
 * Create: 2017-11-22
 * Description: provide init process of isulad
 ******************************************************************************/

#include <signal.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/resource.h>
#include <malloc.h>
#include <regex.h>
#include <semaphore.h>
#include <locale.h>
#include <isula_libutils/isulad_daemon_configs.h>
#include <isula_libutils/json_common.h>
#include <isula_libutils/oci_runtime_hooks.h>
#include <isula_libutils/oci_runtime_spec.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#ifdef SYSTEMD_NOTIFY
#include <systemd/sd-daemon.h>
#endif

#include "constants.h"
#include "events_collector_api.h"
#include "isulad_commands.h"
#include "isula_libutils/log.h"
#include "utils.h"
#include "isulad_config.h"
#include "image_api.h"
#include "sysinfo.h"
#include "verify.h"
#include "service_common.h"
#include "callback.h"
#include "log_gather_api.h"
#include "container_api.h"
#include "plugin_api.h"
#ifdef ENABLE_SELINUX
#include "selinux_label.h"
#endif
#include "http.h"
#include "runtime_api.h"
#include "daemon_arguments.h"
#include "err_msg.h"
#include "utils_convert.h"
#include "utils_file.h"
#include "utils_string.h"
#include "utils_verify.h"
#include "volume_api.h"
#include "opt_log.h"

#ifdef GRPC_CONNECTOR
#include "clibcni/api.h"
#endif

sem_t g_daemon_shutdown_sem;
sem_t g_daemon_wait_shutdown_sem;

static int create_client_run_path(const char *group)
{
    int ret = 0;
    const char *rundir = "/var/run/isula";

    if (group == NULL) {
        return -1;
    }

    if (util_mkdir_p(rundir, ISULA_CLIENT_DIRECTORY_MODE) < 0) {
        ERROR("Unable to create client run directory %s.", rundir);
        ret = -1;
        goto out;
    }

    if (chmod(rundir, ISULA_CLIENT_DIRECTORY_MODE) < 0) {
        ERROR("Failed to chmod for client run path: %s", rundir);
        ret = -1;
        goto out;
    }

    if (util_set_file_group(rundir, group) != 0) {
        ERROR("set group of the path: %s failed", rundir);
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int mount_rootfs_mnt_dir(const char *mountdir)
{
    int ret = -1;
    char *p = NULL;
    char *rootfsdir = NULL;
    mountinfo_t **minfos = NULL;
    mountinfo_t *info = NULL;
    char *userns_remap = conf_get_isulad_userns_remap();

    if (mountdir == NULL) {
        ERROR("parent mount path is NULL");
        goto out;
    }

    rootfsdir = util_strdup_s(mountdir);

    ret = util_mkdir_p(rootfsdir, ROOTFS_MNT_DIRECTORY_MODE);
    if (ret < 0) {
        ERROR("Failed to create rootfs directory:%s", rootfsdir);
        goto out;
    }

    if (userns_remap != NULL) {
        ret = chmod(rootfsdir, USER_REMAP_DIRECTORY_MODE);
        if (ret != 0) {
            ERROR("Failed to chmod mount dir '%s' for user remap", rootfsdir);
            goto out;
        }
    }

    // find parent directory
    p = strrchr(rootfsdir, '/');
    if (p == NULL) {
        ERROR("Failed to find parent directory for %s", rootfsdir);
        goto out;
    }
    *p = '\0';

    if (userns_remap != NULL) {
        ret = chmod(rootfsdir, USER_REMAP_DIRECTORY_MODE);
        if (ret != 0) {
            ERROR("Failed to chmod mount dir '%s' for user remap", rootfsdir);
            goto out;
        }
    }

    minfos = getmountsinfo();
    if (minfos == NULL) {
        ERROR("Failed to get mounts info");
        goto out;
    }

    info = find_mount_info(minfos, rootfsdir);
    if (info == NULL) {
        ret = mount(rootfsdir, rootfsdir, "bind", MS_BIND | MS_REC, NULL);
        if (ret < 0) {
            ERROR("Failed to mount parent directory %s:%s", rootfsdir, strerror(errno));
            goto out;
        }
    }
    ret = 0;

out:
    free(rootfsdir);
    free(userns_remap);
    free_mounts_info(minfos);
    return ret;
}

static int umount_rootfs_mnt_dir(const char *mntdir)
{
    int ret = -1;
    char *p = NULL;
    char *dir = NULL;

    dir = util_strdup_s(mntdir);

    // find parent directory
    p = strrchr(dir, '/');
    if (p == NULL) {
        ERROR("Failed to find parent directory for %s", dir);
        goto out;
    }
    *p = '\0';

    ret = umount(dir);
    if (ret < 0 && errno != EINVAL) {
        WARN("Failed to umount parent directory %s:%s", dir, strerror(errno));
        goto out;
    }

    ret = 0;

out:
    free(dir);
    return ret;
}

static void umount_daemon_mntpoint()
{
    char *mntdir = NULL;

    mntdir = conf_get_isulad_mount_rootfs();
    if (mntdir == NULL) {
        ERROR("Out of memory");
    } else {
        umount_rootfs_mnt_dir(mntdir);
        free(mntdir);
        mntdir = NULL;
    }
}

static inline bool unlink_ignore_enoent(const char *fname)
{
    return unlink(fname) && errno != ENOENT;
}

static void clean_residual_files()
{
    char *checked_flag = NULL;
    char *fname = NULL;

    /* remove image checked file */
    checked_flag = conf_get_graph_check_flag_file();
    if (checked_flag == NULL) {
        ERROR("Failed to get image checked flag file path");
    } else if (unlink_ignore_enoent(checked_flag)) {
        ERROR("Unlink file: %s error: %s", checked_flag, strerror(errno));
    }
    free(checked_flag);

    /* remove pid file */
    fname = conf_get_isulad_pidfile();
    if (fname == NULL) {
        ERROR("Failed to get isulad pid file path");
    } else if (unlink(fname) && errno != ENOENT) {
        WARN("Unlink file: %s error: %s", fname, strerror(errno));
    }
    free(fname);
}

static void daemon_shutdown()
{
    /* shutdown server */
    server_common_shutdown();

    /* clean resource first, left time to wait finish */
    image_module_exit();

    umount_daemon_mntpoint();

    clean_residual_files();

    sem_post(&g_daemon_wait_shutdown_sem);
}

static void sigint_handler(int x)
{
    INFO("Got SIGINT; exiting");
    sem_post(&g_daemon_shutdown_sem);
}

static void sigterm_handler(int signo)
{
    INFO("Got SIGTERM; exiting");
    sem_post(&g_daemon_shutdown_sem);
}

static int ignore_signals()
{
    struct sigaction sa;

    /*
     * Ignore SIGHUP so isulad process still exists after
     * terminal die.
     */
    (void)memset(&sa, 0, sizeof(struct sigaction));

    sa.sa_handler = SIG_IGN;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGHUP, &sa, NULL) < 0) {
        ERROR("Failed to ignore SIGHUP");
        return -1;
    }

    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        ERROR("Failed to ignore SIGPIPE");
        return -1;
    }

    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        ERROR("Failed to ignore SIGUSR1");
        return -1;
    }
    return 0;
}

static int add_shutdown_signal_handler()
{
    struct sigaction sa;

    (void)memset(&sa, 0, sizeof(struct sigaction));

    if (sem_init(&g_daemon_shutdown_sem, 0, 0) == -1) {
        ERROR("Failed to init daemon shutdown sem");
        return -1;
    }

    if (sem_init(&g_daemon_wait_shutdown_sem, 0, 0) == -1) {
        ERROR("Failed to init wait daemon shutdown sem");
        return -1;
    }

    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        ERROR("Failed to add handler for SIGINT");
        return -1;
    }

    (void)memset(&sa, 0, sizeof(struct sigaction));

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        ERROR("Failed to add handler for SIGTERM");
        return -1;
    }

    return 0;
}

static int add_sighandler()
{
    if (ignore_signals() != 0) {
        ERROR("Failed to ignore signals");
        return -1;
    }

    if (add_shutdown_signal_handler() != 0) {
        ERROR("Failed to add shutdown signals");
        return -1;
    }

    return 0;
}

static int daemonize()
{
    int ret = 0;
    struct service_arguments *args = NULL;

    umask(0000);

    if (isulad_server_conf_rdlock()) {
        ret = -1;
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config");
        ret = -1;
        goto unlock_out;
    }

    if (args->json_confs != NULL && create_client_run_path(args->json_confs->group)) {
        ERROR("Create client run directory failed");
        ret = -1;
        goto unlock_out;
    }

    /*
     * close all file descriptors
     */
    if (util_check_inherited(true, -1)) {
        ERROR("Failed to close fds.");
        ret = -1;
    }
unlock_out:
    if (isulad_server_conf_unlock()) {
        ret = -1;
    }
out:
    umask(0022);
    return ret;
}

int check_and_save_pid(const char *fn)
{
    int fd = -1;
    int ret = 0;
    int len = 0;
    struct flock lk;
    char pidbuf[ISULAD_NUMSTRLEN64] = { 0 };

    if (fn == NULL) {
        ERROR("Input error");
        return -1;
    }

    ret = util_build_dir(fn);
    if (ret) {
        WARN("Failed to create directory for pid file: %s", fn);
        return -1;
    }

    fd = util_open(fn, O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    if (fd < 0) {
        WARN("Failed to open pid file: %s", fn);
        return -1;
    }

    lk.l_type = F_WRLCK;
    lk.l_whence = SEEK_SET;
    lk.l_start = 0;
    lk.l_len = 0;
    if (fcntl(fd, F_SETLK, &lk) != 0) {
        /* another daemonize instance is already running, don't start up */
        COMMAND_ERROR("Pid file found, ensure isulad is not running or delete pid file %s"
                      " or please specify another pid file",
                      fn);
        ret = -1;
        goto out;
    }

    ret = ftruncate(fd, 0);
    if (ret != 0) {
        ERROR("Failed to truncate pid file:%s to 0: %s", fn, strerror(errno));
        ret = -1;
        goto out;
    }

    len = snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long)getpid());
    if (len < 0 || len >= sizeof(pidbuf)) {
        ERROR("failed sprint pidbuf");
        ret = -1;
        goto out;
    }

    len = (int)write(fd, pidbuf, strlen(pidbuf));
    if (len < 0) {
        ERROR("Failed to write pid to file:%s: %s", fn, strerror(errno));
        ret = -1;
    }
out:
    if (ret < 0) {
        close(fd);
    }
    return ret;
}

int check_and_set_default_isulad_log_file(struct service_arguments *args)
{
    if (args == NULL) {
        return -1;
    }
    if (args != NULL && args->json_confs != NULL && args->json_confs->log_driver != NULL &&
        strcasecmp("file", args->json_confs->log_driver) == 0) {
        if ((args->logpath == NULL || strcmp("", args->logpath) == 0) && args->json_confs->graph != NULL) {
            free(args->logpath);
            args->logpath = util_strdup_s(args->json_confs->graph);
        }
    }
    if (args != NULL && util_validate_absolute_path(args->logpath)) {
        ERROR("Daemon log path \"%s\" must be abosulte path.", args->logpath);
        return -1;
    }
    return 0;
}

static int set_parent_mount_dir(struct service_arguments *args)
{
    int ret = -1;
    int nret;
    size_t len;
    char *rootfsdir = NULL;

    if (args->json_confs == NULL) {
        ERROR("Empty json configs");
        goto out;
    }
    if (strlen(args->json_confs->graph) > (SIZE_MAX - strlen("/mnt/rootfs")) - 1) {
        ERROR("Root directory of the isulad runtime is too long");
        goto out;
    }
    len = strlen(args->json_confs->graph) + strlen("/mnt/rootfs") + 1;
    if (len > PATH_MAX) {
        ERROR("The size of path exceeds the limit");
        goto out;
    }
    rootfsdir = util_common_calloc_s(len);
    if (rootfsdir == NULL) {
        ERROR("Out of memory");
        goto out;
    }
    nret = snprintf(rootfsdir, len, "%s/mnt/rootfs", args->json_confs->graph);
    if (nret < 0 || (size_t)nret >= len) {
        ERROR("Failed to print string");
        goto out;
    }

    free(args->json_confs->rootfsmntdir);
    args->json_confs->rootfsmntdir = util_strdup_s(rootfsdir);

    ret = 0;

out:
    free(rootfsdir);
    return ret;
}

static int check_hook_spec_file(const char *hook_spec)
{
    struct stat hookstat = { 0 };

    if (hook_spec == NULL) {
        return 0;
    }
    if (util_validate_absolute_path(hook_spec)) {
        ERROR("Hook path \"%s\" must be an absolute path", hook_spec);
        return -1;
    }
    if (stat(hook_spec, &hookstat)) {
        ERROR("Stat hook spec file failed: %s", strerror(errno));
        return -1;
    }
    if ((hookstat.st_mode & S_IFMT) != S_IFREG) {
        ERROR("Hook spec file must be a regular text file");
        return -1;
    }
    return 0;
}

static int parse_hook_spec(const char *specfile, oci_runtime_spec_hooks **phooks)
{
    int ret = 0;
    parser_error err = NULL;
    oci_runtime_spec_hooks *hooks = NULL;

    if (check_hook_spec_file(specfile)) {
        ret = -1;
        goto out;
    }

    hooks = oci_runtime_spec_hooks_parse_file(specfile, NULL, &err);
    if (hooks == NULL) {
        ERROR("Failed to parse hook-spec file: %s", err);
        isulad_set_error_message("Invalid hook-spec file(%s) in server conf.", specfile);
        ret = -1;
        goto out;
    }

    ret = verify_oci_hook(hooks);
    if (ret) {
        ERROR("Verify hook file failed");
        free_oci_runtime_spec_hooks(hooks);
        goto out;
    }

    *phooks = hooks;

out:
    free(err);
    err = NULL;
    return ret;
}

static void update_isulad_rlimits()
{
#define __ULIMIT_CONFIG_VAL_ 1048576
    struct rlimit limit;

    /* set ulimit of process */
    limit.rlim_cur = __ULIMIT_CONFIG_VAL_;
    limit.rlim_max = __ULIMIT_CONFIG_VAL_;
    if (setrlimit(RLIMIT_NOFILE, &limit)) {
        WARN("Can not set ulimit of RLIMIT_NOFILE: %s", strerror(errno));
    }

    if (setrlimit(RLIMIT_NPROC, &limit)) {
        WARN("Can not set ulimit of RLIMIT_NPROC: %s", strerror(errno));
    }
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &limit)) {
        WARN("Can not set ulimit of RLIMIT_CORE: %s", strerror(errno));
    }
}

static int validate_time_duration(const char *value)
{
    regex_t preg;
    int status = 0;
    regmatch_t regmatch = { 0 };

    if (value == NULL) {
        return -1;
    }

    if (regcomp(&preg, "^([1-9][0-9]*)+([s,m])$", REG_NOSUB | REG_EXTENDED)) {
        ERROR("Failed to compile the regex\n");
        return -1;
    }

    status = regexec(&preg, value, 1, &regmatch, 0);
    regfree(&preg);
    if (status != 0) {
        ERROR("Error start-timeout value: %s\n", value);
        COMMAND_ERROR("Invalid time duration value(%s) in server conf, "
                      "only ^([1-9][0-9]*)+([s,m])$ are allowed.",
                      value);
        return -1;
    }
    return 0;
}

static int parse_time_duration(const char *value, unsigned int *seconds)
{
    int ret = 0;
    unsigned int tmp = 0;
    char unit = 0;
    size_t len = 0;
    char *num_str = NULL;

    if (validate_time_duration(value) != 0) {
        return -1;
    }

    num_str = util_strdup_s(value);

    len = strlen(value);
    unit = *(value + len - 1);
    *(num_str + len - 1) = '\0';
    ret = util_safe_uint(num_str, &tmp);
    if (ret < 0) {
        ERROR("Illegal unsigned integer: %s", num_str);
        COMMAND_ERROR("Illegal unsigned integer:%s:%s", num_str, strerror(-ret));
        ret = -1;
        goto out;
    }

    if (tmp == 0) {
        goto out;
    }

    switch (unit) {
        case 'm':
            if (UINT_MAX / tmp > 60) {
                tmp *= 60;
            } else {
                ERROR("The time duration value(%s) is too large, please reset it!", num_str);
                COMMAND_ERROR("The time duration value(%s) is too large, please reset it!", num_str);
                ret = -1;
            }
            break;
        case 's':
            break;
        default:
            COMMAND_ERROR("Unsupported unit:%c", unit);
            ret = -1;
            break;
    }

    *seconds = tmp;
out:
    free(num_str);
    return ret;
}

static int update_graph_for_userns_remap(struct service_arguments *args)
{
    int ret = 0;
    int nret = 0;
    char graph[PATH_MAX] = { 0 };
    uid_t host_uid = 0;
    gid_t host_gid = 0;
    unsigned int size = 0;

    if (args->json_confs->userns_remap == NULL) {
        goto out;
    }

    if (util_parse_user_remap(args->json_confs->userns_remap, &host_uid, &host_gid, &size)) {
        ERROR("Failed to split string '%s'.", args->json_confs->userns_remap);
        ret = -1;
        goto out;
    }

    nret = snprintf(graph, sizeof(graph), "%s/%d.%d", ISULAD_ROOT_PATH, host_uid, host_gid);
    if (nret < 0 || (size_t)nret >= sizeof(graph)) {
        ERROR("Path is too long");
        ret = -1;
        goto out;
    }

    free(args->json_confs->graph);
    args->json_confs->graph = util_strdup_s(graph);

out:
    return ret;
}
// update values for options after flag parsing is complete
static int update_tls_options(struct service_arguments *args)
{
    int ret = 0;
    char *ca_real_file = NULL;
    char *cert_real_file = NULL;
    char *key_real_file = NULL;

    if (args->json_confs->tls_verify) {
        args->json_confs->tls = true;
    }

    if (!args->json_confs->tls) {
        free_isulad_daemon_configs_tls_config(args->json_confs->tls_config);
        args->json_confs->tls_config = NULL;
    } else {
        if (args->json_confs->tls_verify) {
            ca_real_file = verify_file_and_get_real_path(args->json_confs->tls_config->ca_file);
            if (ca_real_file == NULL) {
                ERROR("Invalid CaFile(%s)!", args->json_confs->tls_config->ca_file);
                COMMAND_ERROR("Invalid CaFile(%s)", args->json_confs->tls_config->ca_file);
                ret = -1;
                goto out;
            }
            free(args->json_confs->tls_config->ca_file);
            args->json_confs->tls_config->ca_file = ca_real_file;
        }
        cert_real_file = verify_file_and_get_real_path(args->json_confs->tls_config->cert_file);
        if (cert_real_file == NULL) {
            ERROR("Invalid CertFile(%s)", args->json_confs->tls_config->cert_file);
            COMMAND_ERROR("Invalid CertFile(%s)", args->json_confs->tls_config->cert_file);
            ret = -1;
            goto out;
        }
        free(args->json_confs->tls_config->cert_file);
        args->json_confs->tls_config->cert_file = cert_real_file;

        key_real_file = verify_file_and_get_real_path(args->json_confs->tls_config->key_file);
        if (key_real_file == NULL) {
            ERROR("Invalid KeyFile(%s)", args->json_confs->tls_config->key_file);
            COMMAND_ERROR("Invalid CertFile(%s)", args->json_confs->tls_config->key_file);
            ret = -1;
            goto out;
        }
        free(args->json_confs->tls_config->key_file);
        args->json_confs->tls_config->key_file = key_real_file;
    }
out:
    return ret;
}

static int update_set_default_log_file(struct service_arguments *args)
{
    int ret = 0;

    if (args->json_confs->log_driver && strcasecmp("stdout", args->json_confs->log_driver) == 0) {
        args->quiet = false;
    }

    if (check_and_set_default_isulad_log_file(args)) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int parse_conf_hooks(struct service_arguments *args)
{
    int ret = 0;

    if (args->json_confs->hook_spec != NULL && parse_hook_spec(args->json_confs->hook_spec, &args->hooks) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int parse_conf_time_duration(struct service_arguments *args)
{
    int ret = 0;

    /* parse start timeout */
    if (args->json_confs->start_timeout != NULL &&
        parse_time_duration(args->json_confs->start_timeout, &args->start_timeout)) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

#ifdef ENABLE_SELINUX
static int overlay_supports_selinux(bool *supported)
{
#define KALLSYMS_ITEM_MAX_LEN 100
    int ret = 0;
    FILE *fp = NULL;
    char *buf = NULL;
    size_t len;
    ssize_t num;

    *supported = false;
    fp = fopen("/proc/kallsyms", "re");
    if (fp == NULL) {
        ERROR("Failed to open /proc/kallsyms: %s", strerror(errno));
        return -1;
    }
    __fsetlocking(fp, FSETLOCKING_BYCALLER);

    for (num = getline(&buf, &len, fp); num != -1; num = getline(&buf, &len, fp)) {
        char sym_addr[KALLSYMS_ITEM_MAX_LEN] = { 0 };
        char sym_type[KALLSYMS_ITEM_MAX_LEN] = { 0 };
        char sym_name[KALLSYMS_ITEM_MAX_LEN] = { 0 };

        if (sscanf(buf, "%99s %99s %99s", sym_addr, sym_type, sym_name) != 3) {
            ERROR("sscanf buffer failed");
            ret = -1;
            goto out;
        }

        // Check for presence of symbol security_inode_copy_up.
        if (strcmp(sym_name, "security_inode_copy_up") == 0) {
            *supported = true;
            goto out;
        }
    }

out:
    free(buf);
    fclose(fp);
    return ret;
}

static int configure_kernel_security_support(const struct service_arguments *args)
{
    if (selinux_state_init() != 0) {
        ERROR("Failed to init selinux state");
        return -1;
    }

    if (args->json_confs->selinux_enabled) {
        if (!selinux_get_enable()) {
            WARN("iSulad could not enable SELinux on the host system");
            return 0;
        }

        if (strcmp(args->json_confs->storage_driver, "overlay") == 0 ||
            strcmp(args->json_confs->storage_driver, "overlay2") == 0) {
            // If driver is overlay or overlay2, make sure kernel
            // supports selinux with overlay.
            bool supported = false;

            if (overlay_supports_selinux(&supported)) {
                return -1;
            }
            if (!supported) {
                WARN("SELinux is not supported with the %s graph driver on this kernel",
                     args->json_confs->storage_driver);
            }
        }
    } else {
        selinux_set_disabled();
    }
    return 0;
}
#endif

static int use_default_log_opts_for_json_file(bool rotate_found, bool size_found,
                                              isulad_daemon_configs_container_log *conf)
{
    int nret = 0;

    if (conf->opts == NULL) {
        conf->opts = util_common_calloc_s(sizeof(json_map_string_string));
    }
    if (conf->opts == NULL) {
        ERROR("Out of memory");
        return -1;
    }

    if (!rotate_found) {
        nret = append_json_map_string_string(conf->opts, CONTAINER_LOG_CONFIG_KEY_ROTATE, "7");
        if (nret != 0) {
            ERROR("Out of memory");
            return -1;
        }
    }

    if (!size_found) {
        nret = append_json_map_string_string(conf->opts, CONTAINER_LOG_CONFIG_KEY_SIZE, "1MB");
        if (nret != 0) {
            ERROR("Out of memory");
            return -1;
        }
    }

    return 0;
}

static int update_container_log_configs(isulad_daemon_configs_container_log *conf)
{
    bool rotate_found = false;
    bool size_found = false;
    size_t i;

    if (conf->driver == NULL) {
        conf->driver = util_strdup_s(CONTAINER_LOG_CONFIG_JSON_FILE_DRIVER);
    }

    if (!parse_container_log_opts(&conf->opts)) {
        return -1;
    }

    /* validate daemon container log configs */
    for (i = 0; conf->opts != NULL && i < conf->opts->len; i++) {
        if (!check_opt_container_log_opt(conf->driver, conf->opts->keys[i])) {
            return -1;
        }

        if (strcmp(CONTAINER_LOG_CONFIG_KEY_ROTATE, conf->opts->keys[i]) == 0) {
            rotate_found = true;
        } else if (strcmp(CONTAINER_LOG_CONFIG_KEY_SIZE, conf->opts->keys[i]) == 0) {
            size_found = true;
        }
    }

    // set default log opts for json file driver
    if (strcmp(conf->driver, CONTAINER_LOG_CONFIG_JSON_FILE_DRIVER) == 0) {
        return use_default_log_opts_for_json_file(rotate_found, size_found, conf);
    }

    return 0;
}

static int update_server_args(struct service_arguments *args)
{
    int ret = 0;

    if (update_graph_for_userns_remap(args) != 0) {
        ret = -1;
        goto out;
    }

    if (update_tls_options(args)) {
        ret = -1;
        goto out;
    }

    if (update_set_default_log_file(args) != 0) {
        ret = -1;
        goto out;
    }

    if (update_hosts(args) != 0) {
        ret = -1;
        goto out;
    }

    if (update_default_ulimit(args) != 0) {
        ret = -1;
        goto out;
    }

    if (update_container_log_configs(args->json_confs->container_log) != 0) {
        ret = -1;
        goto out;
    }

    /* check args */
    if (check_args(args)) {
        ret = -1;
        goto out;
    }

    if (set_parent_mount_dir(args)) {
        ret = -1;
        goto out;
    }

    /* parse hook spec */
    if (parse_conf_hooks(args) != 0) {
        ret = -1;
        goto out;
    }

    /* parse image opt timeout */
    if (parse_conf_time_duration(args) != 0) {
        ret = -1;
        goto out;
    }

#ifdef ENABLE_SELINUX
    // Configure and validate the kernels security support. Note this is a Linux/FreeBSD
    // operation only, so it is safe to pass *just* the runtime OS graphdriver.
    if (configure_kernel_security_support(args)) {
        ret = -1;
        goto out;
    }
#endif

out:
    return ret;
}

static int server_conf_parse_save(int argc, const char **argv)
{
    int ret = 0;
    struct service_arguments *args = NULL;

    args = util_common_calloc_s(sizeof(struct service_arguments));
    if (args == NULL) {
        ERROR("memory out");
        ret = -1;
        goto out;
    }

    /* Step1: set default value to configs */
    if (service_arguments_init(args) != 0) {
        ERROR("Failed to init service arguments");
        ret = -1;
        goto out;
    }

    /* Step2: load json configs and merge into global configs */
    if (merge_json_confs_into_global(args) != 0) {
        ret = -1;
        goto out;
    }

    /* Step3: option from command line override configuration file */
    if (parse_args(args, argc, argv)) {
        ERROR("parse args failed");
        ret = -1;
        goto out;
    }

    if (update_server_args(args) != 0) {
        ret = -1;
        goto out;
    }

    if (save_args_to_conf(args)) {
        ERROR("Failed to save arguments");
        ret = -1;
        goto out;
    }

out:
    if (ret != 0) {
        service_arguments_free(args);
        free(args);
    }
    return ret;
}

static int init_log_gather_thread(const char *log_full_path, struct isula_libutils_log_config *plconf,
                                  const struct service_arguments *args)
{
    pthread_t log_thread = { 0 };
    struct log_gather_conf lgconf = { 0 };
    int log_gather_exitcode = -1;

    lgconf.log_file_mode = args->log_file_mode;
    lgconf.fifo_path = plconf->file;
    lgconf.g_log_driver = plconf->driver;
    lgconf.log_path = log_full_path;
    lgconf.max_size = args->max_size;
    lgconf.max_file = args->max_file;
    lgconf.exitcode = &log_gather_exitcode;
    if (pthread_create(&log_thread, NULL, log_gather, &lgconf)) {
        printf("Failed to create log monitor thread\n");
        return -1;
    }
    while (1) {
        util_usleep_nointerupt(1000);
        if (log_gather_exitcode >= 0) {
            break;
        }
    }

    return log_gather_exitcode;
}

static int isulad_get_log_path(char **log_full_path, char **fifo_full_path)
{
    int ret = 0;

    *log_full_path = conf_get_isulad_log_file();
    if (*log_full_path == NULL) {
        ret = -1;
        goto out;
    }
    *fifo_full_path = conf_get_isulad_log_gather_fifo_path();
    if (*fifo_full_path == NULL) {
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int isulad_server_init_log(const struct service_arguments *args, const char *log_full_path,
                                  const char *fifo_full_path)
{
#define FIFO_DRIVER "fifo"
    int ret = -1;
    struct isula_libutils_log_config lconf = { 0 };

    lconf.name = args->progname;
    lconf.file = fifo_full_path;
    lconf.driver = FIFO_DRIVER;
    lconf.priority = args->json_confs->log_level;
    if (isula_libutils_log_enable(&lconf) != 0) {
        ERROR("Failed to init log");
        goto out;
    }

#ifdef GRPC_CONNECTOR
    /* init clibcni log */
    if (cni_log_init(FIFO_DRIVER, fifo_full_path, args->json_confs->log_level) != 0) {
        ERROR("Failed to init cni log");
        goto out;
    }
#endif

    lconf.driver = args->json_confs->log_driver;
    if (init_log_gather_thread(log_full_path, &lconf, args)) {
        ERROR("Log gather start failed");
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int isulad_server_pre_init(const struct service_arguments *args, const char *log_full_path,
                                  const char *fifo_full_path)
{
    int ret = 0;
    char* userns_remap = conf_get_isulad_userns_remap();

    if (check_and_save_pid(args->json_confs->pidfile) != 0) {
        ERROR("Failed to save pid");
        ret = -1;
        goto out;
    }

    if (isulad_server_init_log(args, log_full_path, fifo_full_path) != 0) {
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(args->json_confs->state, DEFAULT_SECURE_FILE_MODE) != 0) {
        ERROR("Unable to create state directory %s.", args->json_confs->state);
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(args->json_confs->graph, CONFIG_DIRECTORY_MODE) != 0) {
        ERROR("Unable to create root directory %s.", args->json_confs->graph);
        ret = -1;
        goto out;
    }

    if (userns_remap != NULL) {
        if (chmod(ISULAD_ROOT_PATH, USER_REMAP_DIRECTORY_MODE) != 0) {
            ERROR("Failed to chmod isulad root dir '%s' for user remap", ISULAD_ROOT_PATH);
            ret = -1;
            goto out;
        }

        if (set_file_owner_for_userns_remap(args->json_confs->graph, userns_remap) != 0) {
            ERROR("Unable to change root directory %s owner for user remap.", args->json_confs->graph);
            ret = -1;
            goto out;
        }
    }

    if (mount_rootfs_mnt_dir(args->json_confs->rootfsmntdir)) {
        ERROR("Create and mount parent directory failed");
        ret = -1;
        goto out;
    }

    if (service_callback_init()) {
        ERROR("Failed to init service callback");
        ret = -1;
        goto out;
    }

out:
    free(userns_remap);
    return ret;
}

static int isulad_server_init_common()
{
    int ret = -1;
    struct service_arguments *args = NULL;
    char *log_full_path = NULL;
    char *fifo_full_path = NULL;

    if (isulad_get_log_path(&log_full_path, &fifo_full_path) != 0) {
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config");
        goto out;
    }

    if (isulad_server_pre_init(args, log_full_path, fifo_full_path) != 0) {
        goto out;
    }

    if (volume_init(args->json_confs->graph) != 0) {
        ERROR("Failed to init volume");
        goto out;
    }

    if (image_module_init(args->json_confs) != 0) {
        ERROR("Failed to init image manager");
        goto out;
    }

    if (containers_store_init()) {
        ERROR("Failed to init containers store");
        goto out;
    }

    if (container_name_index_init()) {
        ERROR("Failed to init name index");
        goto out;
    }

    ret = 0;

out:
    free(log_full_path);
    free(fifo_full_path);
    return ret;
}

static char *parse_host(bool tls, const char *val)
{
    char *host = NULL;
    char *tmp = util_strdup_s(val);
    tmp = util_trim_space(tmp);
    if (tmp == NULL) {
        if (tls) {
            host = util_strdup_s(DEFAULT_TLS_HOST);
        } else {
            host = util_strdup_s(DEFAULT_UNIX_SOCKET);
        }
    } else {
        host = util_strdup_s(val);
    }
    free(tmp);
    return host;
}

static int listener_init(const char *proto, const char *addr, const char *socket_group)
{
    int ret = 0;

    if (proto == NULL || addr == NULL) {
        FATAL("Invalid input arguments");
        return -1;
    }

    if (strcmp(proto, "unix") == 0) {
        ret = set_unix_socket_group(addr, socket_group);
        if (ret) {
            FATAL("Can't create unix socket %s", addr);
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int load_listener(const struct service_arguments *args)
{
    int ret = 0;
    const char *delim = "://";
    char *proto = NULL;
    char *addr = NULL;
    size_t i;

    for (i = 0; i < args->hosts_len; i++) {
        char *proto_addr = NULL;

        proto_addr = parse_host(args->json_confs->tls, args->hosts[i]);
        proto = strtok_r(proto_addr, delim, &addr);
        if (proto == NULL) {
            ERROR("Failed to get proto");
            ret = -1;
            free(proto_addr);
            goto out;
        }
        addr += strlen("://") - 1;

        if (strncmp(proto, "tcp", strlen("tcp")) == 0 &&
            (args->json_confs->tls_config == NULL || !args->json_confs->tls_verify)) {
            WARN("[!] DON'T BIND ON ANY IP ADDRESS WITHOUT setting"
                 " --tlsverify IF YOU DON'T KNOW WHAT YOU'RE DOING [!]");
        }

        // note: If we're binding to a TCP port, make sure that a container doesn't try to use it.
        ret = listener_init(proto, args->hosts[i], args->json_confs->group);
        free(proto_addr);
        if (ret != 0) {
            ERROR("Failed to init listener");
            ret = -1;
            goto out;
        }
    }
out:
    return ret;
}

static int isulad_server_init_service()
{
    int ret = -1;
    struct service_arguments *args = NULL;

    if (isulad_server_conf_rdlock()) {
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config");
        goto unlock_out;
    }
#ifdef GRPC_CONNECTOR
    INFO("Creating grpc server...");
#else
    INFO("Creating rest server...");
#endif
    if (server_common_init(args, daemon_shutdown)) {
        ERROR("Failed to init service");
        goto unlock_out;
    }

    ret = load_listener(args);
    if (ret != 0) {
        ERROR("Failed to load listener");
        goto unlock_out;
    }

unlock_out:
    if (isulad_server_conf_unlock()) {
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static void set_mallopt()
{
    if (mallopt(M_ARENA_TEST, 8) == 0) {
        fprintf(stderr, "change M_ARENA_TEST to 8\n");
    }
    if (mallopt(M_TOP_PAD, 32 * 1024) == 0) {
        fprintf(stderr, "chagne M_TOP_PAD to 32KB");
    }
    if (mallopt(M_TRIM_THRESHOLD, 64 * 1024) == 0) {
        fprintf(stderr, "change M_TRIM_THRESHOLD to 64KB");
    }
    if (mallopt(M_MMAP_THRESHOLD, 64 * 1024) == 0) {
        fprintf(stderr, "change M_MMAP_THRESHOLD to 64KB");
    }
}

/* shutdown handler */
static void *do_shutdown_handler(void *arg)
{
    int res = 0;

    res = pthread_detach(pthread_self());
    if (res != 0) {
        CRIT("Set thread detach fail");
    }

    prctl(PR_SET_NAME, "Shutdown");

    sem_wait(&g_daemon_shutdown_sem);

    daemon_shutdown();

    return NULL;
}

/* news_shutdown_handler */
int new_shutdown_handler()
{
    int ret = -1;
    pthread_t shutdown_thread;

    INFO("Starting new shutdown handler...");
    ret = pthread_create(&shutdown_thread, NULL, do_shutdown_handler, NULL);
    if (ret != 0) {
        CRIT("Thread creation failed");
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int start_daemon_threads(char **msg)
{
    int ret = -1;

    if (new_shutdown_handler()) {
        *msg = "Create new shutdown handler thread failed";
        goto out;
    }

    if (events_module_init(msg) != 0) {
        goto out;
    }

    if (container_module_init(msg) != 0) {
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int pre_init_daemon_log()
{
    struct isula_libutils_log_config lconf = { 0 };

    lconf.name = "isulad";
    lconf.file = NULL;
    lconf.priority = "ERROR";
    lconf.driver = "stdout";
    if (isula_libutils_log_enable(&lconf)) {
        fprintf(stderr, "log init failed\n");
        return -1;
    }

    return 0;
}

static int pre_init_daemon(int argc, char **argv, char **msg)
{
    int ret = -1;
    /*
     * must call isulad by root
     */
    if (geteuid() != 0) {
        *msg = "iSulad must be called by root";
        goto out;
    }

    if (server_conf_parse_save(argc, (const char **)argv)) {
        *msg = g_isulad_errmsg ? g_isulad_errmsg : "Failed to parse and save server conf";
        goto out;
    }

    if (init_isulad_daemon_constants() != 0) {
        *msg = "Failed to parse isulad daemon constants";
        goto out;
    }

    /* note: daemonize will close all fds */
    if (daemonize()) {
        *msg = "Failed to become a daemon";
        goto out;
    }

    if (runtime_init() != 0) {
        *msg = "Failed to init runtime";
        goto out;
    }

    /*
     * change the current working dir to root.
     */
    if (chdir("/") < 0) {
        *msg = "Failed to change dir to /";
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int set_locale()
{
    int ret = 0;

    /* Change from the standard (C) to en_US.UTF-8 locale, so libarchive can handle filename conversions.*/
    if (setlocale(LC_CTYPE, "en_US.UTF-8") == NULL) {
        COMMAND_ERROR("Could not set locale to en_US.UTF-8:%s", strerror(errno));
        ret = -1;
        goto out;
    }

out:
    return ret;
}

/*
 * Takes socket path as argument
 */
int main(int argc, char **argv)
{
    struct timespec t_start, t_end;
    double use_time = 0;
    char *msg = NULL;

    prctl(PR_SET_NAME, "isulad");

    if (pre_init_daemon_log() != 0) {
        exit(ECOMMON);
    }

    if (set_locale() != 0) {
        exit(ECOMMON);
    }

    http_global_init();

    set_mallopt();

    update_isulad_rlimits();

    (void)get_sys_info(true);

    clock_gettime(CLOCK_MONOTONIC, &t_start);

    if (pre_init_daemon(argc, argv, &msg) != 0) {
        goto failure;
    }

    if (isulad_server_init_common() != 0) {
        goto failure;
    }

    if (add_sighandler()) {
        msg = "Failed to add sig handlers";
        goto failure;
    }

    if (start_daemon_threads(&msg)) {
        goto failure;
    }

    if (isulad_server_init_service()) {
        msg = "Failed to init services";
        goto failure;
    }

    if (start_plugin_manager()) {
        msg = "Failed to init plugin_manager";
        goto failure;
    }

    clock_gettime(CLOCK_MONOTONIC, &t_end);
    use_time = (double)(t_end.tv_sec - t_start.tv_sec) * (double)1000000000 + (double)(t_end.tv_nsec - t_start.tv_nsec);
    use_time /= 1000000000;
    EVENT("iSulad successfully booted in %.3f s", use_time);
#ifdef GRPC_CONNECTOR
    INFO("Starting grpc server...");
#else
    INFO("Starting rest server...");
#endif

#ifdef SYSTEMD_NOTIFY
    if (sd_notify(0, "READY=1") < 0) {
        msg = "Failed to send notify the service manager about state changes";
        goto failure;
    }
#endif

    server_common_start();

    sem_wait(&g_daemon_wait_shutdown_sem);

    DAEMON_CLEAR_ERRMSG();
    return 0;

failure:
    if (msg != NULL) {
        fprintf(stderr, "Start failed: %s\n", msg);
    }
    DAEMON_CLEAR_ERRMSG();
    exit(1);
}
