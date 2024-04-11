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
#ifdef ENABLE_SUP_GROUPS
#include <grp.h>
#endif
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
#include "path.h"
#include "volume_api.h"
#ifndef DISABLE_CLEANUP
#include "leftover_cleanup_api.h"
#endif
#include "opt_log.h"
#ifdef ENABLE_NETWORK
#include "network_api.h"
#endif
#include "id_name_manager.h"
#include "cgroup.h"
#ifdef ENABLE_CDI
#include "cdi_operate_api.h"
#endif /* ENABLE_CDI */

sem_t g_daemon_shutdown_sem;
sem_t g_daemon_wait_shutdown_sem;

static int create_client_run_path(const char *group)
{
    int ret = 0;
    const char *rundir = CLIENT_RUNDIR;

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
#ifdef ENABLE_USERNS_REMAP
    char *userns_remap = conf_get_isulad_userns_remap();
#endif

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

#ifdef ENABLE_USERNS_REMAP
    if (userns_remap != NULL) {
        ret = chmod(rootfsdir, USER_REMAP_DIRECTORY_MODE);
        if (ret != 0) {
            ERROR("Failed to chmod mount dir '%s' for user remap", rootfsdir);
            goto out;
        }
    }
#endif

    // find parent directory
    p = strrchr(rootfsdir, '/');
    if (p == NULL) {
        ERROR("Failed to find parent directory for %s", rootfsdir);
        goto out;
    }
    *p = '\0';

#ifdef ENABLE_USERNS_REMAP
    if (userns_remap != NULL) {
        ret = chmod(rootfsdir, USER_REMAP_DIRECTORY_MODE);
        if (ret != 0) {
            ERROR("Failed to chmod mount dir '%s' for user remap", rootfsdir);
            goto out;
        }
    }
#endif

    minfos = getmountsinfo();
    if (minfos == NULL) {
        ERROR("Failed to get mounts info");
        goto out;
    }

    info = find_mount_info(minfos, rootfsdir);
    if (info == NULL) {
        ret = mount(rootfsdir, rootfsdir, "bind", MS_BIND | MS_REC, NULL);
        if (ret < 0) {
            SYSERROR("Failed to mount parent directory %s.", rootfsdir);
            goto out;
        }
    }
    ret = 0;

out:
    free(rootfsdir);
#ifdef ENABLE_USERNS_REMAP
    free(userns_remap);
#endif
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
        SYSWARN("Failed to umount parent directory %s.", dir);
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
    return unlink(fname) != 0 && errno != ENOENT;
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
        SYSERROR("Unlink file: %s.", checked_flag);
    }
    free(checked_flag);

    /* remove pid file */
    fname = conf_get_isulad_pidfile();
    if (fname == NULL) {
        ERROR("Failed to get isulad pid file path");
    } else if (unlink(fname) != 0 && errno != ENOENT) {
        SYSWARN("Unlink file: %s.", fname);
    }
    free(fname);
}

static void daemon_shutdown()
{
    EVENT("Begin shutdown daemon");

    /* shutdown server */
    server_common_shutdown();

    /* clean resource first, left time to wait finish */
    image_module_exit();
    EVENT("Image module exit completed");

    umount_daemon_mntpoint();
    EVENT("Umount daemon mntpoint completed");

#ifdef ENABLE_NETWORK
    network_module_exit();
    EVENT("Network module exit completed");
#endif

    clean_residual_files();
    EVENT("Clean residual files completed");

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

    // ensure SIGCHLD not be ignore, otherwise waitpid() will failed
    if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
        ERROR("Failed to enable SIGCHLD signal");
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

    if (args->json_confs != NULL && create_client_run_path(args->json_confs->group) != 0) {
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
        SYSERROR("Failed to truncate pid file:%s to 0.", fn);
        ret = -1;
        goto out;
    }

    len = snprintf(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long)getpid());
    if (len < 0 || (size_t)len >= sizeof(pidbuf)) {
        ERROR("failed sprint pidbuf");
        ret = -1;
        goto out;
    }

    len = util_write_nointr(fd, pidbuf, strlen(pidbuf));
    if (len < 0 || (size_t)len != strlen(pidbuf)) {
        SYSERROR("Failed to write pid to file:%s.", fn);
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
    if (args != NULL && util_validate_absolute_path(args->logpath) != 0) {
        ERROR("Daemon log path \"%s\" must be abosulte path.", args->logpath);
        return -1;
    }
    return 0;
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
        SYSERROR("Stat hook spec file failed.");
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
        SYSWARN("Can not set ulimit of RLIMIT_NOFILE");
    }

    if (setrlimit(RLIMIT_NPROC, &limit)) {
        SYSWARN("Can not set ulimit of RLIMIT_NPROC");
    }
    limit.rlim_cur = RLIM_INFINITY;
    limit.rlim_max = RLIM_INFINITY;
    if (setrlimit(RLIMIT_CORE, &limit)) {
        SYSWARN("Can not set ulimit of RLIMIT_CORE.");
    }
}

static int validate_time_duration(const char *value)
{
#define PATTEN_STR "^([1-9][0-9]*)+([s,m])$"
    int status = 0;

    if (value == NULL) {
        return -1;
    }

    status = util_reg_match(PATTEN_STR, value);
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
        errno = -ret;
        SYSERROR("Illegal unsigned integer: %s", num_str);
        COMMAND_ERROR("Illegal unsigned integer:%s", num_str);
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

#ifdef ENABLE_USERNS_REMAP
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

    nret = snprintf(graph, sizeof(graph), "%s/%u.%u", args->json_confs->graph, host_uid, host_gid);
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
#endif

#ifdef ENABLE_GRPC_REMOTE_CONNECT
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
#endif

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
        parse_time_duration(args->json_confs->start_timeout, &args->start_timeout) != 0) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

#ifdef ENABLE_SELINUX
#ifdef ENABLE_OCI_IMAGE
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
        SYSERROR("Failed to open /proc/kallsyms.");
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
#endif

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

#ifdef ENABLE_OCI_IMAGE
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
#endif
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
#ifdef ENABLE_USERNS_REMAP
    if (update_graph_for_userns_remap(args) != 0) {
        return -1;
    }
#endif

#ifdef ENABLE_GRPC_REMOTE_CONNECT
    if (update_tls_options(args)) {
        return -1;
    }
#endif

    if (update_set_default_log_file(args) != 0) {
        return -1;
    }

    if (update_hosts(args) != 0) {
        return -1;
    }

    if (update_default_ulimit(args) != 0) {
        return -1;
    }

    if (update_container_log_configs(args->json_confs->container_log) != 0) {
        return -1;
    }

    /* check args */
    if (check_args(args)) {
        return -1;
    }

    /* parse hook spec */
    if (parse_conf_hooks(args) != 0) {
        return -1;
    }

    /* parse image opt timeout */
    if (parse_conf_time_duration(args) != 0) {
        return -1;
    }

#ifdef ENABLE_SELINUX
    // Configure and validate the kernels security support. Note this is a Linux/FreeBSD
    // operation only, so it is safe to pass *just* the runtime OS graphdriver.
    if (configure_kernel_security_support(args)) {
        return -1;
    }
#endif

    return 0;
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
        ERROR("Failed to merge json conf into global");
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
        ERROR("Failed to update server args");
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
        ERROR("Failed to create log monitor thread");
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
    *log_full_path = conf_get_isulad_log_file();
    if (*log_full_path == NULL) {
        return -1;
    }

    *fifo_full_path = conf_get_isulad_log_gather_fifo_path();
    if (*fifo_full_path == NULL) {
        return -1;
    }

    return 0;
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
    char *rootfs_mnt_dir = NULL;
#ifdef ENABLE_USERNS_REMAP
    char* userns_remap = conf_get_isulad_userns_remap();
    char *isulad_root = NULL;
#endif
    mode_t mode = CONFIG_DIRECTORY_MODE;

#ifdef ENABLE_SUP_GROUPS
    if (args->json_confs->sup_groups_len > 0) {
        if (setgroups(args->json_confs->sup_groups_len, args->json_confs->sup_groups) != 0) {
            SYSERROR("failed to setgroups");
            ret = -1;
            goto out;
        }
    }
#endif

    if (check_and_save_pid(args->json_confs->pidfile) != 0) {
        ERROR("Failed to save pid");
        ret = -1;
        goto out;
    }

    if (isulad_server_init_log(args, log_full_path, fifo_full_path) != 0) {
        ret = -1;
        goto out;
    }

    if (util_mkdir_p(args->json_confs->state, DEFAULT_SECURE_DIRECTORY_MODE) != 0) {
        ERROR("Unable to create state directory %s.", args->json_confs->state);
        ret = -1;
        goto out;
    }

#ifdef ENABLE_USERNS_REMAP
    if (userns_remap != NULL) {
        mode = USER_REMAP_DIRECTORY_MODE;
    }
#endif

    ret = util_mkdir_p(args->json_confs->graph, mode);
    if (ret != 0) {
        ERROR("Unable to create root directory %s.", args->json_confs->graph);
        ret = -1;
        goto out;
    }

#ifdef ENABLE_USERNS_REMAP
    if (userns_remap != NULL) {
        isulad_root = util_path_dir(args->json_confs->graph);
        if (chmod(isulad_root, USER_REMAP_DIRECTORY_MODE) != 0) {
            ERROR("Failed to chmod isulad root dir '%s' for user remap", isulad_root);
            ret = -1;
            goto out;
        }

        if (set_file_owner_for_userns_remap(args->json_confs->graph, userns_remap) != 0) {
            ERROR("Unable to change root directory %s owner for user remap.", args->json_confs->graph);
            ret = -1;
            goto out;
        }
    }
#endif

    rootfs_mnt_dir = conf_get_isulad_mount_rootfs();
    if (rootfs_mnt_dir == NULL) {
        ERROR("Failed to get isulad mount rootfs");
        ret = -1;
        goto out;
    }

    if (mount_rootfs_mnt_dir(rootfs_mnt_dir)) {
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
    free(rootfs_mnt_dir);
#ifdef ENABLE_USERNS_REMAP
    free(isulad_root);
    free(userns_remap);
#endif
    return ret;
}

static int isulad_tmpdir_security_check(const char *tmp_dir)
{
    struct stat st = { 0 };

    if (lstat(tmp_dir, &st) != 0) {
        SYSERROR("Failed to lstat %s", tmp_dir);
        return -1;
    }

    if (!S_ISDIR(st.st_mode)) {
        return -1;
    }

    if ((st.st_mode & 0777) != ISULAD_TEMP_DIRECTORY_MODE) {
        return -1;
    }

    if (st.st_uid != 0) {
        return -1;
    }

    if (S_ISLNK(st.st_mode)) {
        return -1;
    }

    return 0;
}

static int recreate_tmpdir(const char *tmp_dir)
{
    if (util_path_remove(tmp_dir) != 0) {
        ERROR("Failed to remove directory %s", tmp_dir);
        return -1;
    }

    if (util_mkdir_p(tmp_dir, ISULAD_TEMP_DIRECTORY_MODE) != 0) {
        ERROR("Failed to create directory %s", tmp_dir);
        return -1;
    }

    return 0;
}

static int do_ensure_isulad_tmpdir_security(const char *isulad_tmp_dir)
{
    int nret;
    char tmp_dir[PATH_MAX] = { 0 };
    char cleanpath[PATH_MAX] = { 0 };
    char isulad_tmp_cleanpath[PATH_MAX] = { 0 };

    if (util_clean_path(isulad_tmp_dir, isulad_tmp_cleanpath, sizeof(isulad_tmp_cleanpath)) == NULL) {
        ERROR("Failed to clean path for %s", isulad_tmp_dir);
        return -1;
    }

    // Determine whether isulad_tmp_dir exists. If it does not exist, create it
    // to prevent realpath from reporting errors because the folder does not exist.
    if (!util_dir_exists(isulad_tmp_cleanpath)) {
        nret = snprintf(tmp_dir, PATH_MAX, "%s/isulad_tmpdir", isulad_tmp_cleanpath);
        if (nret < 0 || (size_t)nret >= PATH_MAX) {
            ERROR("Failed to snprintf");
            return -1;
        }
        INFO("iSulad tmpdir: %s does not exist, create it", isulad_tmp_dir);
        return recreate_tmpdir(tmp_dir);
    }

    if (realpath(isulad_tmp_cleanpath, cleanpath) == NULL) {
        ERROR("Failed to get real path for %s", tmp_dir);
        return -1;
    }

    nret = snprintf(tmp_dir, PATH_MAX, "%s/isulad_tmpdir", cleanpath);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to snprintf");
        return -1;
    }

    if (isulad_tmpdir_security_check(tmp_dir) == 0) {
        return 0;
    }

    INFO("iSulad tmpdir: %s does not meet security requirements, recreate it", isulad_tmp_dir);
    return recreate_tmpdir(tmp_dir);
}

static int ensure_isulad_tmpdir_security()
{
    char *isulad_tmp_dir = NULL;

    isulad_tmp_dir = getenv("ISULAD_TMPDIR");
    if (!util_valid_isulad_tmpdir(isulad_tmp_dir)) {
        isulad_tmp_dir = DEFAULT_ISULAD_TMPDIR;
    }

    if (do_ensure_isulad_tmpdir_security(isulad_tmp_dir) != 0) {
        ERROR("Failed to ensure the %s directory is a safe directory", isulad_tmp_dir);
        return -1;
    }

    if (strcmp(isulad_tmp_dir, DEFAULT_ISULAD_TMPDIR) == 0) {
        return 0;
    }

    // No matter whether ISULAD_TMPDIR is set or not,
    // ensure the DEFAULT_ISULAD_TMPDIR directory is a safe directory
    // TODO: if isula is no longer tarred in the future, we can delete it.
    if (do_ensure_isulad_tmpdir_security(DEFAULT_ISULAD_TMPDIR) != 0) {
        WARN("Failed to ensure the default ISULAD_TMPDIR : %s directory is a safe directory", DEFAULT_ISULAD_TMPDIR);
    }

    return 0;
}

static int isulad_server_init_common()
{
    int ret = -1;
    struct service_arguments *args = NULL;
    char *log_full_path = NULL;
    char *fifo_full_path = NULL;

    if (isulad_get_log_path(&log_full_path, &fifo_full_path) != 0) {
        ERROR("Get log path failed");
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get isulad server config");
        goto out;
    }

    // starting log server of iSulad
    if (isulad_server_pre_init(args, log_full_path, fifo_full_path) != 0) {
        goto out;
    }

#ifndef DISABLE_CLEANUP
    // to cleanup leftover, init clean module before other modules.
    if (clean_module_init(args->json_confs) != 0) {
        ERROR("Failed to init clean module");
        goto out;
    }
#endif
    // clean tmpdir before image module init
    // because tmpdir will remove failed if chroot mount point exist under tmpdir
    isulad_tmpdir_cleaner();

    if (id_name_manager_init() != 0) {
        ERROR("Failed to init id name manager");
        goto out;
    }

    // preventing the use of insecure isulad tmpdir directory
    if (ensure_isulad_tmpdir_security() != 0) {
        ERROR("Failed to ensure isulad tmpdir security");
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

#ifdef ENABLE_NETWORK
    if (!network_module_init(args->json_confs->network_plugin, NULL, args->json_confs->cni_conf_dir,
                             args->json_confs->cni_bin_dir)) {
        ERROR("Failed to init network module");
        goto out;
    }
#endif

#ifdef ENABLE_CDI
    if (args->json_confs->enable_cdi &&
        cdi_operate_registry_init(args->json_confs->cdi_spec_dirs, args->json_confs->cdi_spec_dirs_len) != 0) {
        ERROR("Failed to init CDI module");
        goto out;
    }
#endif /* ENABLE_CDI */

    if (spec_module_init() != 0) {
        ERROR("Failed to init spec module");
        goto out;
    }

    if (containers_store_init() != 0) {
        ERROR("Failed to init containers store");
        goto out;
    }

    if (container_name_index_init() != 0) {
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

    if (tmp != NULL) {
        host = util_strdup_s(val);
        free(tmp);
        return host;
    }

#ifdef ENABLE_GRPC_REMOTE_CONNECT
    if (tls) {
        return util_strdup_s(DEFAULT_TLS_HOST);
    }
#endif

    return util_strdup_s(DEFAULT_UNIX_SOCKET);
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

#ifdef ENABLE_GRPC_REMOTE_CONNECT
        proto_addr = parse_host(args->json_confs->tls, args->hosts[i]);
#else
        proto_addr = parse_host(false, args->hosts[i]);
#endif
        proto = strtok_r(proto_addr, delim, &addr);
        if (proto == NULL) {
            ERROR("Failed to get proto");
            ret = -1;
            free(proto_addr);
            goto out;
        }
        addr += strlen("://") - 1;

#ifdef ENABLE_GRPC_REMOTE_CONNECT
        if (strncmp(proto, "tcp", strlen("tcp")) == 0 &&
            (args->json_confs->tls_config == NULL || !args->json_confs->tls_verify)) {
            WARN("[!] DON'T BIND ON ANY IP ADDRESS WITHOUT setting"
                 " --tlsverify IF YOU DON'T KNOW WHAT YOU'RE DOING [!]");
        }
#endif

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

static int create_mount_flock_file(const struct service_arguments *args)
{
    int nret = 0;
    int fd = -1;
    char path[PATH_MAX] = { 0 };
    char cleanpath[PATH_MAX] = { 0 };

    nret = snprintf(path, PATH_MAX, "%s/%s", args->json_confs->graph, MOUNT_FLOCK_FILE_PATH);
    if (nret < 0 || (size_t)nret >= PATH_MAX) {
        ERROR("Failed to snprintf");
        return -1;
    }

    if (util_clean_path(path, cleanpath, sizeof(cleanpath)) == NULL) {
        ERROR("clean path for %s failed", path);
        return -1;
    }

    if (util_fileself_exists(cleanpath)) {
        int err = 0;
        // recreate mount flock file
        // and make file uid/gid and permission correct
        if (!util_force_remove_file(cleanpath, &err)) {
            errno = err;
            SYSERROR("Failed to delete %s. Please delete %s manually.", path, path);
            return -1;
        }
    }

    fd = util_open(cleanpath, O_RDWR | O_CREAT, MOUNT_FLOCK_FILE_MODE);
    if (fd < 0) {
        ERROR("Failed to create file %s", cleanpath);
        return -1;
    }
    close(fd);

    nret = util_set_file_group(cleanpath, args->json_confs->group);
    if (nret < 0) {
        ERROR("set group of the path %s failed", cleanpath);
        return -1;
    }

    return 0;
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

    ret = create_mount_flock_file(args);
    if (ret != 0) {
        ERROR("Failed to create mount flock file");
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
        SYSERROR("Failed to change M_ARENA_TEST to 8");
    }
    if (mallopt(M_TOP_PAD, 32 * 1024) == 0) {
        SYSERROR("Failed to chagne M_TOP_PAD to 32KB");
    }
    if (mallopt(M_TRIM_THRESHOLD, 64 * 1024) == 0) {
        SYSERROR("Failed to change M_TRIM_THRESHOLD to 64KB");
    }
    if (mallopt(M_MMAP_THRESHOLD, 64 * 1024) == 0) {
        SYSERROR("Failed to change M_MMAP_THRESHOLD to 64KB");
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
int new_shutdown_handler(void)
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

static int start_daemon_threads()
{
    int ret = -1;

    if (new_shutdown_handler()) {
        ERROR("Create new shutdown handler thread failed");
        goto out;
    }

    if (events_module_init() != 0) {
        goto out;
    }

    if (container_module_init() != 0) {
        goto out;
    }

#ifndef DISABLE_CLEANUP
    clean_module_do_clean();
#endif

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
        COMMAND_ERROR("Enable isula default log failed");
        return -1;
    }

    return 0;
}

static int pre_init_daemon(int argc, char **argv)
{
    int ret = -1;
    /*
     * must call isulad by root
     */
    if (geteuid() != 0) {
        SYSERROR("iSulad must be called by root");
        goto out;
    }

    if (cgroup_ops_init() != 0) {
        ERROR("Failed to init cgroup");
        goto out;
    }

    if (server_conf_parse_save(argc, (const char **)argv)) {
        ERROR("%s", g_isulad_errmsg ? g_isulad_errmsg : "Failed to parse and save server conf");
        goto out;
    }

    if (init_isulad_daemon_constants() != 0) {
        ERROR("Failed to parse isulad daemon constants");
        goto out;
    }

    /* note: daemonize will close all fds */
    if (daemonize()) {
        ERROR("Failed to become a daemon");
        goto out;
    }

    if (runtime_init() != 0) {
        ERROR("Failed to init runtime");
        goto out;
    }

    /*
     * change the current working dir to root.
     */
    if (chdir("/") < 0) {
        SYSERROR("Failed to change dir to /");
        goto out;
    }

    ret = 0;
out:
    return ret;
}

#ifdef ENABLE_OCI_IMAGE
static int set_locale()
{
    int ret = 0;

    /* Change from the standard (C) to en_US.UTF-8 locale, so libarchive can handle filename conversions.*/
    if (setlocale(LC_CTYPE, "en_US.UTF-8") == NULL) {
        SYSERROR("Could not set locale to en_US.UTF-8");
        ret = -1;
        goto out;
    }

out:
    return ret;
}
#endif

/*
 * Takes socket path as argument
 */
int main(int argc, char **argv)
{
    struct timespec t_start, t_end;
    double use_time = 0;

    prctl(PR_SET_NAME, "isulad");

    // set default log driver to stdout, before get config of iSulad log
    if (pre_init_daemon_log() != 0) {
        exit(ECOMMON);
    }

#ifdef ENABLE_OCI_IMAGE
    if (set_locale() != 0) {
        exit(ECOMMON);
    }
#endif

    http_global_init();

    set_mallopt();

    update_isulad_rlimits();

    clock_gettime(CLOCK_MONOTONIC, &t_start);

    if (pre_init_daemon(argc, argv) != 0) {
        goto failure;
    }

    if (isulad_server_init_common() != 0) {
        goto failure;
    }

    if (add_sighandler()) {
        ERROR("Failed to add sig handlers");
        goto failure;
    }

    if (start_daemon_threads()) {
        goto failure;
    }

    if (isulad_server_init_service()) {
        ERROR("Failed to init services");
        goto failure;
    }

#ifdef ENABLE_PLUGIN
    if (start_plugin_manager()) {
        ERROR("Failed to init plugin_manager");
        goto failure;
    }
#endif

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
        SYSERROR("Failed to send notify the service manager about state changes");
        goto failure;
    }
#endif

    server_common_start();

    sem_wait(&g_daemon_wait_shutdown_sem);

    DAEMON_CLEAR_ERRMSG();
    return 0;

failure:
    ERROR("Starting failed...");
    DAEMON_CLEAR_ERRMSG();
    exit(1);
}
