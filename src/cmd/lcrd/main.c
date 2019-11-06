/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2017-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2017-11-22
 * Description: provide init process of lcrd
 ******************************************************************************/

#include <signal.h>
#include <stdio.h>
#include <sys/types.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <lcr/lcrcontainer.h>
#include <sys/resource.h>
#include <malloc.h>
#include <regex.h>
#include <execinfo.h>
#include <sys/syscall.h>
#include <semaphore.h>
#ifdef SYSTEMD_NOTIFY
#include <systemd/sd-daemon.h>
#endif

#include "constants.h"
#include "liblcrd.h"
#include "securec.h"
#include "collector.h"
#include "commands.h"
#include "log.h"
#include "engine.h"
#include "utils.h"
#include "lcrd_config.h"
#include "image.h"
#include "sysinfo.h"
#include "verify.h"
#include "monitord.h"
#include "service_common.h"
#include "callback.h"
#include "log_gather.h"
#include "containers_store.h"
#include "restore.h"
#include "supervisor.h"
#include "containers_gc.h"
#include "plugin.h"


#ifdef ENABLE_OCI_IMAGE
#include "driver.h"
#endif

#ifdef GRPC_CONNECTOR
#include "clibcni/api.h"
#endif

#ifdef ENABLE_EMBEDDED_IMAGE
#include "db_common.h"
#endif

sem_t g_daemon_shutdown_sem;
sem_t g_print_backtrace_sem;
int g_backtrace_log_fd = -1;

static int create_client_run_path(const char *group)
{
    int ret = 0;
    const char *rundir = "/var/run/lcrc";
    if (group == NULL) {
        return -1;
    }
    ret = util_mkdir_p(rundir, DEFAULT_SECURE_DIRECTORY_MODE);
    if (ret < 0) {
        ERROR("Unable to create client run directory %s.", rundir);
        return ret;
    }

    ret = chmod(rundir, DEFAULT_SECURE_DIRECTORY_MODE);
    if (ret < 0) {
        ERROR("Failed to chmod for client run path: %s", rundir);
    }

    return ret;
}

static int mount_rootfs_mnt_dir(const char *mountdir)
{
    int ret = -1;
    char *p = NULL;
    char *rootfsdir = NULL;
    mountinfo_t **minfos = NULL;
    mountinfo_t *info = NULL;

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

    // find parent directory
    p = strrchr(rootfsdir, '/');
    if (p == NULL) {
        ERROR("Failed to find parent directory for %s", rootfsdir);
        goto out;
    }
    *p = '\0';

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
    free_mounts_info(minfos);
    return ret;
}

#ifdef ENABLE_OCI_IMAGE
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

    mntdir = conf_get_lcrd_mount_rootfs();
    if (mntdir == NULL) {
        ERROR("Out of memory");
    } else {
        umount_rootfs_mnt_dir(mntdir);
        free(mntdir);
        mntdir = NULL;
    }

    graphdriver_umount_mntpoint();
}
#endif

static void daemon_shutdown()
{
    char *pidfile = NULL;
    char *checked_flag = NULL;

#ifdef ENABLE_EMBEDDED_IMAGE
    /* shutdown db */
    db_common_finish();
#endif

    /* shutdown server */
    server_common_shutdown();

#ifdef ENABLE_OCI_IMAGE
    umount_daemon_mntpoint();
#endif

    /* remove image checked file */
    checked_flag = conf_get_graph_check_flag_file();
    if (checked_flag == NULL) {
        ERROR("Failed to get image checked flag file path");
    } else if (unlink(checked_flag) && errno != ENOENT) {
        ERROR("Unlink file: %s error: %s", checked_flag, strerror(errno));
    }
    free(checked_flag);
    checked_flag = NULL;

    /* remove pid file */
    pidfile = conf_get_lcrd_pidfile();
    if (pidfile == NULL) {
        ERROR("Failed to get LCRD pid file path");
    } else if (unlink(pidfile) && errno != ENOENT) {
        WARN("Unlink file: %s error: %s", pidfile, strerror(errno));
    }
    free(pidfile);
    pidfile = NULL;
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

#define BT_BUF_SIZE 100
#define MAX_BT_SIZE (3 * 1024)
static void print_callstack(void)
{
    int j = 0;
    int nptrs = 0;
    int nret = 0;
    void *buffer[BT_BUF_SIZE] = { NULL };
    char msg[MAX_BT_SIZE] = { 0 };
    char tname[16] = { 0 };
    char **strings = NULL;
    pid_t tid = 0;
    size_t avalid_size = 0;

    prctl(PR_GET_NAME, tname);
    tid = (pid_t)syscall(__NR_gettid);

    nptrs = backtrace(buffer, BT_BUF_SIZE);
    strings = backtrace_symbols(buffer, nptrs);
    if (strings == NULL) {
        ERROR("backtrace_symbols return nothing");
        goto out;
    }

    nret = sprintf_s(msg, MAX_BT_SIZE, "[%s] tid:%d backtrace:\n", tname, tid);
    if (nret < 0 || nret > MAX_BT_SIZE) {
        ERROR("Failed to print [%s] tid:%d backtrace headinfo", tname, tid);
        goto out;
    }

    for (j = 0; j < nptrs; j++) {
        avalid_size = MAX_BT_SIZE - strlen(msg);
        if ((strlen(strings[j]) + strlen("  \n")) <= (avalid_size - 1)) {
            nret = sprintf_s(msg + strlen(msg), avalid_size, "  %s\n", strings[j]);
            if (nret < 0 || (size_t)nret > avalid_size) {
                ERROR("Failed to print backtrace %s", strings[j]);
                goto out;
            }
        } else {
            break;
        }
    }
    nret = (int)write(g_backtrace_log_fd, msg, strlen(msg));
    if (nret < 0) {
        ERROR("Failed to write backtrace info: %s", strerror(errno));
        goto out;
    }

out:
    if (sem_wait(&g_print_backtrace_sem) == -1) {
        ERROR("Failed to wait");
    }

    free(strings);
    return;
}

static void sigusr1_handler(int signo)
{
    INFO("Got SIGUSER1; print back trace");
    print_callstack();
    return;
}

static int create_isulad_monitor_log_file()
{
    int ret = 0;
    int tmp_fd = -1;
    char *root_dir = NULL;
    struct tm *tm_now = NULL;
    time_t currtime = time(0);
    char log_file[PATH_MAX] = { 0 };
    char fn[PATH_MAX] = { 0 };

    root_dir = conf_get_lcrd_rootdir();
    if (root_dir == NULL) {
        ERROR("Get rootpath failed");
        ret = -1;
        goto out;
    }

    tm_now = localtime(&currtime);
    if (tm_now == NULL) {
        ERROR("Failed to get current time");
        ret = -1;
        goto out;
    }

    if (strftime(log_file, sizeof(log_file), "%Y%m%d%H%M%S", tm_now) == 0) {
        ret = -1;
        goto out;
    }

    ret = sprintf_s(fn, sizeof(fn), "%s/%s/%s", root_dir, "isulad-monitor", log_file);
    if (ret < 0) {
        ERROR("Failed to print string");
        ret = -1;
        goto out;
    }

    ret = util_build_dir(fn);
    if (ret < 0) {
        WARN("Failed to create directory for log file: %s", fn);
        ret = -1;
        goto out;
    }

    tmp_fd = util_open(fn, O_RDWR | O_CREAT, DEFAULT_SECURE_FILE_MODE);
    if (tmp_fd < 0) {
        WARN("Failed to open log file: %s", fn);
        ret = -1;
        goto out;
    }

    if (g_backtrace_log_fd != -1) {
        close(g_backtrace_log_fd);
    }
    g_backtrace_log_fd = tmp_fd;

    ret = 0;

out:
    free(root_dir);
    return ret;
}

static void send_dump_req(void)
{
    int ret = 0;
    size_t subdir_num = 0;
    size_t i = 0;
    char **subdir = NULL;
    pid_t tid = 0;
    pid_t pid = 0;

    ret = create_isulad_monitor_log_file();
    if (ret != 0) {
        goto out;
    }

    ret = util_list_all_subdir("/proc/self/task", &subdir);
    if (ret < 0) {
        ERROR("Failed to read /proc/self/task' subdirectory");
        goto out;
    }
    subdir_num = util_array_len((const char **)subdir);
    if (subdir_num == 0) {
        goto out;
    }

    pid = getpid();
    if (pid < 0) {
        goto out;
    }

    ret = sem_init(&g_print_backtrace_sem, 0, (unsigned int)subdir_num);
    if (ret != 0) {
        goto out;
    }

    for (i = 0; i < subdir_num; i++) {
        ret = util_safe_int(subdir[i], &tid);
        if (ret < 0) {
            (void)sem_wait(&g_print_backtrace_sem);
            continue;
        }
        ret = (int)syscall(SYS_tgkill, pid, tid, SIGUSR1);
        if (ret < 0) {
            ERROR("Failed to send SIGUSR1 to thread id:%d in process:%d", tid, pid);
            (void)sem_wait(&g_print_backtrace_sem);
        }
    }

out:
    util_free_array(subdir);
    return;
}

static void sigrtmin_handler(int signo)
{
    int tmp_sval = 0;

    if (sem_getvalue(&g_print_backtrace_sem, &tmp_sval) == 0) {
        if (tmp_sval == 0) {
            send_dump_req();
        }
    }

    return;
}

static int ignore_signals()
{
    struct sigaction sa;

    /*
     * Ignore SIGHUP so lcrd process still exists after
     * terminal die.
     */
    if (memset_s(&sa, sizeof(struct sigaction), 0, sizeof(struct sigaction)) != EOK) {
        ERROR("Failed to set memory");
        return -1;
    }

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

    return 0;
}

static int add_shutdown_signal_handler()
{
    struct sigaction sa;

    if (memset_s(&sa, sizeof(struct sigaction), 0, sizeof(struct sigaction)) != EOK) {
        ERROR("Failed to set memory");
        return -1;
    }

    if (sem_init(&g_daemon_shutdown_sem, 0, 0) == -1) {
        ERROR("Failed to init daemon shutdown sem");
        return -1;
    }

    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGINT, &sa, NULL) < 0) {
        ERROR("Failed to add handler for SIGINT");
        return -1;
    }

    if (memset_s(&sa, sizeof(struct sigaction), 0, sizeof(struct sigaction)) != EOK) {
        ERROR("Failed to set memory");
        return -1;
    }

    sa.sa_handler = sigterm_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        ERROR("Failed to add handler for SIGTERM");
        return -1;
    }

    return 0;
}

static int add_print_bt_handler()
{
    struct sigaction sa;

    if (memset_s(&sa, sizeof(struct sigaction), 0, sizeof(struct sigaction)) != EOK) {
        ERROR("Failed to set memory");
        return -1;
    }

    if (sem_init(&g_print_backtrace_sem, 0, 0) == -1) {
        ERROR("Failed to init");
        return -1;
    }

    sa.sa_handler = sigusr1_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGUSR1, &sa, NULL) < 0) {
        ERROR("Failed to add handler for SIGUSR1");
        return -1;
    }

    if (memset_s(&sa, sizeof(struct sigaction), 0, sizeof(struct sigaction)) != EOK) {
        ERROR("Failed to set memory");
        return -1;
    }

    sa.sa_handler = sigrtmin_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (sigaction(SIGRTMIN, &sa, NULL) < 0) {
        ERROR("Failed to add handler for SIGRTMIN");
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

    if (add_print_bt_handler() != 0) {
        ERROR("Failed to add print back trace signals");
        return -1;
    }

    return 0;
}

static int daemonize()
{
    int ret = 0;
    struct service_arguments *args = NULL;

    umask(0000);

    if (lcrd_server_conf_rdlock()) {
        ret = -1;
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get lcrd server config");
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
    if (lcrd_server_conf_unlock()) {
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
    char pidbuf[LCRD_NUMSTRLEN64] = { 0 };

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
        COMMAND_ERROR("Pid file found, ensure lcrd is not running or delete pid file %s"
                      " or please specify another pid file", fn);
        ret = -1;
        goto out;
    }

    ret = ftruncate(fd, 0);
    if (ret != 0) {
        ERROR("Failed to truncate pid file:%s to 0: %s", fn, strerror(errno));
        ret = -1;
        goto out;
    }

    len = sprintf_s(pidbuf, sizeof(pidbuf), "%lu\n", (unsigned long)getpid());
    if (len < 0) {
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

int check_and_set_default_lcrd_log_file(struct service_arguments *args)
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
        ERROR("Root directory of the LCRD runtime is too long");
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
    nret = sprintf_s(rootfsdir, len, "%s/mnt/rootfs", args->json_confs->graph);
    if (nret < 0) {
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
        lcrd_set_error_message("Invalid hook-spec file(%s) in server conf.", specfile);
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

    if (check_and_set_default_lcrd_log_file(args)) {
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

    /* parse image opt timeout */
    if (args->json_confs->im_opt_timeout != NULL &&
        parse_time_duration(args->json_confs->im_opt_timeout, &args->im_opt_timeout)) {
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int update_server_args(struct service_arguments *args)
{
    int ret = 0;

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

#ifdef ENABLE_OCI_IMAGE
    args->driver = graphdriver_init(args->json_confs->storage_driver, args->json_confs->storage_opts,
                                    args->json_confs->storage_opts_len);
    if (args->driver == NULL) {
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

static int init_log_gather_thread(const char *log_full_path, struct log_config *plconf,
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
        usleep_nointerupt(1000);
        if (log_gather_exitcode >= 0) {
            break;
        }
    }

    return log_gather_exitcode;
}

static int lcrd_get_log_path(char **log_full_path, char **fifo_full_path)
{
    int ret = 0;

    *log_full_path = conf_get_lcrd_log_file();
    if (*log_full_path == NULL) {
        ret = -1;
        goto out;
    }
    *fifo_full_path = conf_get_lcrd_log_gather_fifo_path();
    if (*fifo_full_path == NULL) {
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int lcrd_server_init_log(const struct service_arguments *args, const char *log_full_path,
                                const char *fifo_full_path)
{
#define FIFO_DRIVER "fifo"
    int ret = -1;
    struct log_config lconf = { 0 };

    lconf.name = args->progname;
    lconf.file = fifo_full_path;
    lconf.driver = FIFO_DRIVER;
    lconf.priority = args->json_confs->log_level;
    if (log_init(&lconf) != 0) {
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

static int lcrd_server_pre_init(const struct service_arguments *args, const char *log_full_path,
                                const char *fifo_full_path)
{
    int ret = 0;

    if (check_and_save_pid(args->json_confs->pidfile) != 0) {
        ERROR("Failed to save pid");
        ret = -1;
        goto out;
    }

    if (lcrd_server_init_log(args, log_full_path, fifo_full_path) != 0) {
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

    if (mount_rootfs_mnt_dir(args->json_confs->rootfsmntdir)) {
        ERROR("Create and mount parent directory failed");
        ret = -1;
        goto out;
    }

#ifdef ENABLE_EMBEDDED_IMAGE
    if (db_common_init(args->json_confs->graph)) {
        ERROR("Failed to init database");
        ret = -1;
        goto out;
    }
#endif

    if (service_callback_init()) {
        ERROR("Failed to init service callback");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int lcrd_server_init_common()
{
    int ret = -1;
    struct service_arguments *args = NULL;
    char *log_full_path = NULL;
    char *fifo_full_path = NULL;

    if (lcrd_get_log_path(&log_full_path, &fifo_full_path) != 0) {
        goto out;
    }

    if (lcrd_server_conf_rdlock()) {
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get lcrd server config");
        goto unlock_out;
    }

    if (lcrd_server_pre_init(args, log_full_path, fifo_full_path) != 0) {
        goto unlock_out;
    }

#ifdef ENABLE_OCI_IMAGE
    /* update status of graphdriver before init image module */
    update_graphdriver_status(&(args->driver));
#endif

    if (image_module_init(args->json_confs->graph)) {
        ERROR("Failed to init image manager");
        goto unlock_out;
    }

    if (containers_store_init()) {
        ERROR("Failed to init containers store");
        goto unlock_out;
    }

    if (name_index_init()) {
        ERROR("Failed to init name index");
        goto unlock_out;
    }

    ret = 0;
unlock_out:
    if (lcrd_server_conf_unlock()) {
        ret = -1;
        goto out;
    }

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
        proto = strtok_s(proto_addr, delim, &addr);
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

static int lcrd_server_init_service()
{
    int ret = -1;
    struct service_arguments *args = NULL;

    if (lcrd_server_conf_rdlock()) {
        goto out;
    }

    args = conf_get_server_conf();
    if (args == NULL) {
        ERROR("Failed to get lcrd server config");
        goto unlock_out;
    }
#ifdef GRPC_CONNECTOR
    INFO("Creating grpc server...");
#else
    INFO("Creating rest server...");
#endif
    if (server_common_init(args)) {
        ERROR("Failed to init service");
        goto unlock_out;
    }

    ret = load_listener(args);
    if (ret != 0) {
        ERROR("Failed to load listener");
        goto unlock_out;
    }

unlock_out:
    if (lcrd_server_conf_unlock()) {
        ret = -1;
        goto out;
    }
out:
    return ret;
}

static int lcrd_server_init_engines()
{
    int ret = 0;
    char *engine = NULL;

    engine = conf_get_lcrd_engine();
    if (engine == NULL) {
        ret = -1;
        goto out;
    }

    if (engines_global_init()) {
        ERROR("Init engines global failed");
        ret = -1;
        goto out;
    }

    /* Init default engine, now is lcr */
    if (engines_discovery(engine)) {
        ERROR("Failed to discovery default engine:%s", engine);
        ret = -1;
    }

out:
    free(engine);
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

static int start_monitord()
{
    int ret = 0;
    int monitord_exitcode = 0;
    sem_t monitord_sem;
    struct monitord_sync_data msync = { 0 };

    msync.monitord_sem = &monitord_sem;
    msync.exit_code = &monitord_exitcode;
    if (sem_init(msync.monitord_sem, 0, 0)) {
        lcrd_set_error_message("Failed to init monitor sem");
        ret = -1;
        goto out;
    }

    if (new_monitord(&msync)) {
        lcrd_set_error_message("Create monitord thread failed");
        ret = -1;
        sem_destroy(msync.monitord_sem);
        goto out;
    }

    sem_wait(msync.monitord_sem);
    sem_destroy(msync.monitord_sem);
    if (monitord_exitcode) {
        lcrd_set_error_message("Monitord start failed");
        ret = -1;
        goto out;
    }

out:
    return ret;
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

    exit(0);
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

    if (newcollector()) {
        *msg = "Create collector thread failed";
        goto out;
    }

    if (start_monitord()) {
        *msg = g_lcrd_errmsg ? g_lcrd_errmsg : "Failed to init cgroups path";
        goto out;
    }

    if (new_gchandler()) {
        *msg = "Create garbage handler thread failed";
        goto out;
    }

    if (new_supervisor()) {
        *msg = "Create supervisor thread failed";
        goto out;
    }

    containers_restore();

    if (start_gchandler()) {
        *msg = "Failed to start garbage collecotor handler";
        goto out;
    }

    ret = 0;
out:
    return ret;
}

static int pre_init_daemon_log()
{
    struct log_config lconf = { 0 };

    lconf.name = "lcrd";
    lconf.quiet = true;
    lconf.file = NULL;
    lconf.priority = "ERROR";
    lconf.driver = "stdout";
    if (log_init(&lconf)) {
        fprintf(stderr, "log init failed\n");
        return -1;
    }

    return 0;
}

static int pre_init_daemon(int argc, char **argv, char **msg)
{
    int ret = -1;
    /*
     * must call lcrd by root
     */
    if (geteuid() != 0) {
        *msg = "LCRD must be called by root";
        goto out;
    }

    if (server_conf_parse_save(argc, (const char **)argv)) {
        *msg = g_lcrd_errmsg ? g_lcrd_errmsg : "Failed to parse and save server conf";
        goto out;
    }

    /* note: daemonize will close all fds */
    if (daemonize()) {
        *msg = "Failed to become a daemon";
        goto out;
    }

    if (lcrd_server_init_engines()) {
        *msg = "Failed to init engines";
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

/*
 * Takes socket path as argument
 */
int main(int argc, char **argv)
{
    struct timespec t_start, t_end;
    double use_time = 0;
    char *msg = NULL;

    prctl(PR_SET_NAME, "lcrd");

    if (pre_init_daemon_log() != 0) {
        exit(ECOMMON);
    }

    set_mallopt();

    update_isulad_rlimits();

    clock_gettime(CLOCK_MONOTONIC, &t_start);

    if (pre_init_daemon(argc, argv, &msg) != 0) {
        goto failure;
    }

    if (lcrd_server_init_common() != 0) {
        goto failure;
    }

    if (init_cgroups_path("/lxc", 0)) {
        msg = g_lcrd_errmsg ? g_lcrd_errmsg : "Failed to init cgroups path";
        goto failure;
    }

    if (add_sighandler()) {
        msg = "Failed to add sig handlers";
        goto failure;
    }

    if (start_daemon_threads(&msg)) {
        goto failure;
    }

    if (lcrd_server_init_service()) {
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
    INFO("Lcrd successfully booted in %.3f s", use_time);
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

    DAEMON_CLEAR_ERRMSG();
    return 0;

failure:
    if (msg != NULL) {
        fprintf(stderr, "Start failed: %s\n", msg);
    }
    DAEMON_CLEAR_ERRMSG();
    exit(1);
}

