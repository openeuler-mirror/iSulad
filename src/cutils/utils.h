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
 * Author: tanyifeng
 * Create: 2018-11-1
 * Description: provide container sha256 functions
 ********************************************************************************/

#ifndef __UTILS_H
#define __UTILS_H

#include <stdio.h>
#include <errno.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/syscall.h>
#include <stdint.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>

#include "utils_string.h"
#include "utils_array.h"
#include "utils_file.h"
#include "utils_convert.h"
#include "utils_verify.h"
#include "utils_regex.h"
#include "utils_fs.h"
#include "utils_base64.h"
#include "utils_aes.h"
//#include "utils_images.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef MS_REC
#define MS_REC 16384
#endif

#if __WORDSIZE == 64
// current max user memory for 64-machine is 2^47 B
#define MAX_MEMORY_SIZE ((size_t)1 << 47)
#else
// current max user memory for 32-machine is 2^31 B
#define MAX_MEMORY_SIZE ((size_t)1 << 31)
#endif

#define MAX_ID_OFFSET 65535
#define HOST_CHANNLE_ARGS 4
#define HOST_CHANNLE_MIN_SIZE (4 * SIZE_KB)
#define MOUNT_PROPERTIES_SIZE 128
#define HOST_PATH_MODE 0700
#define DEFAULT_SHM_SIZE (64 * SIZE_MB)

#define ECOMMON 1

#define PARAM_NUM 100

/* image error start */
#define EIMAGEBUSY 2
#define ENAMECONFLICT 3
#define EIMAGENOTFOUND 20
/* image error end. reserved from 2 to 20 */
#define EINVALIDARGS 125
#define ESERVERERROR 125
#define ERRORACCESS 126
#define ECMDNOTFOUND 127

#define MAX_PATH_DEPTH 1024

#define MAX_BUFFER_SIZE 4096
#define ISULAD_NUMSTRLEN64 21
#define ISULAD_NUMSTRLEN32 11
#define MAXLINE 4096
#define MAX_HOST_NAME_LEN 64
#define MAX_IMAGE_NAME_LEN 255
#define MAX_IMAGE_REF_LEN 384
#define MAX_CONTAINER_NAME_LEN 1024
#define MAX_RUNTIME_NAME_LEN 32

#define LOGIN_USERNAME_LEN 255
#define LOGIN_PASSWORD_LEN 255

#define MAX_SHA256_IDENTIFIER 64
#define SHA256_PREFIX "sha256:"

#define UINT_LEN 10

/* container id max length */
#define CONTAINER_ID_MAX_LEN 64

#define CONTAINER_EXEC_ID_MAX_LEN 64

#define LIST_SIZE_MAX 1000LL
#define LIST_DEVICE_SIZE_MAX 10000LL
#define LIST_ENV_SIZE_MAX 200000LL

#define UNIX_SOCKET_PREFIX "unix://"

#define SIZE_KB 1024LL
#define SIZE_MB (1024LL * SIZE_KB)
#define SIZE_GB (1024LL * SIZE_MB)
#define SIZE_TB (1024LL * SIZE_GB)
#define SIZE_PB (1024LL * SIZE_TB)

#define Time_Nano 1LL
#define Time_Micro (1000LL * Time_Nano)
#define Time_Milli (1000LL * Time_Micro)
#define Time_Second (1000LL * Time_Milli)
#define Time_Minute (60LL * Time_Second)
#define Time_Hour (60LL * Time_Minute)

/* Max regular file size for isula\isulad to open as same as docker */
#define REGULAR_FILE_SIZE (10 * SIZE_MB)

#define rFC339Local "2006-01-02T15:04:05"
#define rFC339NanoLocal "2006-01-02T15:04:05.999999999"
#define dateLocal "2006-01-02"
#define defaultContainerTime "0001-01-01T00:00:00Z"
#define TIME_STR_SIZE 512

#define HOST_NAME_REGEXP                                         \
    "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\\-]*[a-zA-Z0-9])\\.)*" \
    "([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\\-]*[A-Za-z0-9])$"
#define __TagPattern "^:([A-Za-z_0-9][A-Za-z_0-9.-]{0,127})$"
#define __NamePattern                                                                 \
    "^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"                             \
    "((\\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]))+)?(:[0-9]+)?/)?[a-z0-9]" \
    "+((([._]|__|[-]*)[a-z0-9]+)+)?((/[a-z0-9]+((([._]|__|[-]*)[a-z0-9]+)+)?)+)?$"

// native umask value
#define ANNOTATION_UMAKE_KEY "native.umask"
#define UMASK_NORMAL "normal"
#define UMASK_SECURE "secure"

// proxy value
#define HTTP_PROXY "http_proxy"
#define HTTPS_PROXY "https_proxy"
#define NO_PROXY "no_proxy"

#ifndef SIGTRAP
#define SIGTRAP 5
#endif

#ifndef SIGIOT
#define SIGIOT 6
#endif

#ifndef SIGEMT
#define SIGEMT 7
#endif

#ifndef SIGBUS
#define SIGBUS 7
#endif

#ifndef SIGSTKFLT
#define SIGSTKFLT 16
#endif

#ifndef SIGCLD
#define SIGCLD 17
#endif

#ifndef SIGURG
#define SIGURG 23
#endif

#ifndef SIGXCPU
#define SIGXCPU 24
#endif

#ifndef SIGXFSZ
#define SIGXFSZ 25
#endif

#ifndef SIGVTALRM
#define SIGVTALRM 26
#endif

#ifndef SIGPROF
#define SIGPROF 27
#endif

#ifndef SIGWINCH
#define SIGWINCH 28
#endif

#ifndef SIGIO
#define SIGIO 29
#endif

#ifndef SIGPOLL
#define SIGPOLL 29
#endif

#ifndef SIGINFO
#define SIGINFO 29
#endif

#ifndef SIGLOST
#define SIGLOST 37
#endif

#ifndef SIGPWR
#define SIGPWR 30
#endif

#ifndef SIGUNUSED
#define SIGUNUSED 31
#endif

#ifndef SIGSYS
#define SIGSYS 31
#endif

#ifndef SIGRTMIN1
#define SIGRTMIN1 34
#endif

#ifndef SIGRTMAX
#define SIGRTMAX 64
#endif

#define SIGNAL_MAP_DEFAULT                                                                                             \
    {                                                                                                                  \
        { SIGHUP, "HUP" }, { SIGINT, "INT" }, { SIGQUIT, "QUIT" }, { SIGILL, "ILL" }, { SIGABRT, "ABRT" },             \
        { SIGFPE, "FPE" }, { SIGKILL, "KILL" }, { SIGSEGV, "SEGV" }, { SIGPIPE, "PIPE" }, { SIGALRM, "ALRM" }, \
        { SIGTERM, "TERM" }, { SIGUSR1, "USR1" }, { SIGUSR2, "USR2" }, { SIGCHLD, "CHLD" },                    \
        { SIGCONT, "CONT" }, { SIGSTOP, "STOP" }, { SIGTSTP, "TSTP" }, { SIGTTIN, "TTIN" },                    \
        { SIGTTOU, "TTOU" }, { SIGTRAP, "TRAP" }, { SIGIOT, "IOT" }, { SIGEMT, "EMT" }, { SIGBUS, "BUS" },     \
        { SIGSTKFLT, "STKFLT" }, { SIGCLD, "CLD" }, { SIGURG, "URG" }, { SIGXCPU, "XCPU" },                    \
        { SIGXFSZ, "XFSZ" }, { SIGVTALRM, "VTALRM" }, { SIGPROF, "PROF" }, { SIGWINCH, "WINCH" },              \
        { SIGIO, "IO" }, { SIGPOLL, "POLL" }, { SIGINFO, "INFO" }, { SIGLOST, "LOST" }, { SIGPWR, "PWR" },     \
        { SIGUNUSED, "UNUSED" }, { SIGSYS, "SYS" }, { SIGRTMIN, "RTMIN" }, { SIGRTMIN + 1, "RTMIN+1" },        \
        { SIGRTMIN + 2, "RTMIN+2" }, { SIGRTMIN + 3, "RTMIN+3" }, { SIGRTMIN + 4, "RTMIN+4" },                 \
        { SIGRTMIN + 5, "RTMIN+5" }, { SIGRTMIN + 6, "RTMIN+6" }, { SIGRTMIN + 7, "RTMIN+7" },                 \
        { SIGRTMIN + 8, "RTMIN+8" }, { SIGRTMIN + 9, "RTMIN+9" }, { SIGRTMIN + 10, "RTMIN+10" },               \
        { SIGRTMIN + 11, "RTMIN+11" }, { SIGRTMIN + 12, "RTMIN+12" }, { SIGRTMIN + 13, "RTMIN+13" },           \
        { SIGRTMIN + 14, "RTMIN+14" }, { SIGRTMIN + 15, "RTMIN+15" }, { SIGRTMAX - 14, "RTMAX-14" },           \
        { SIGRTMAX - 13, "RTMAX-13" }, { SIGRTMAX - 12, "RTMAX-12" }, { SIGRTMAX - 11, "RTMAX-11" },           \
        { SIGRTMAX - 10, "RTMAX-10" }, { SIGRTMAX - 9, "RTMAX-9" }, { SIGRTMAX - 8, "RTMAX-8" },               \
        { SIGRTMAX - 7, "RTMAX-7" }, { SIGRTMAX - 6, "RTMAX-6" }, { SIGRTMAX - 5, "RTMAX-5" },                 \
        { SIGRTMAX - 4, "RTMAX-4" }, { SIGRTMAX - 3, "RTMAX-3" }, { SIGRTMAX - 2, "RTMAX-2" },                 \
        { SIGRTMAX - 1, "RTMAX-1" }, { SIGRTMAX, "RTMAX" },                                                    \
    }

/* Basic data structure which holds all information we can get about a process.
 * (unless otherwise specified, fields are read from /proc/#/stat)
 *
 * Most of it comes from task_struct in linux/sched.h
 */
typedef struct _proc_t {
    // 1st 16 bytes
    int pid; /* process id */
    int ppid; /* pid of parent process */

    char state; /* single-char code for process state (S=sleeping) */

    unsigned long long utime, /* user-mode CPU time accumulated by process */
             stime, /* kernel-mode CPU time accumulated by process */
             // and so on...
             cutime, /* cumulative utime of process and reaped children */
             cstime, /* cumulative stime of process and reaped children */
             start_time; /* start time of process -- seconds since 1-1-70 */

    long priority, /* kernel scheduling priority */
         timeout, /* ? */
         nice, /* standard unix nice level of process */
         rss, /* resident set size from /proc/#/stat (pages) */
         it_real_value; /* ? */
    unsigned long rtprio, /* real-time priority */
             sched, /* scheduling class */
             vsize, /* number of pages of virtual memory ... */
             rss_rlim, /* resident set size limit? */
             flags, /* kernel flags for the process */
             min_flt, /* number of minor page faults since process start */
             maj_flt, /* number of major page faults since process start */
             cmin_flt, /* cumulative min_flt of process and child processes */
             cmaj_flt, /* cumulative maj_flt of process and child processes */
             nswap, /* ? */
             cnswap, /* cumulative nswap ? */
             start_code, /* address of beginning of code segment */
             end_code, /* address of end of code segment */
             start_stack, /* address of the bottom of stack for the process */
             kstk_esp, /* kernel stack pointer */
             kstk_eip, /* kernel instruction pointer */
             wchan; /* address of kernel wait channel proc is sleeping in */

    char cmd[16]; /* basename of executable file in call to exec(2) */
    int pgrp, /* process group id */
        session, /* session id */
        tty, /* full device number of controlling terminal */
        tpgid, /* terminal process group id */
        exit_signal, /* might not be SIGCHLD */
        processor; /* current (or most recent?) CPU */
} proc_t;

struct signame {
    int num;
    const char *name;
};

#define UTIL_FREE_AND_SET_NULL(p) \
    do {                          \
        if ((p) != NULL) {        \
            free((void *)(p));    \
            (p) = NULL;           \
        }                         \
    } while (0)

int mem_realloc(void **newptr, size_t newsize, void *oldptr, size_t oldsize);

int util_check_inherited(bool closeall, int fd_to_ignore);

int util_sig_parse(const char *sig_name);

void *util_smart_calloc_s(size_t unit_size, size_t count);

void *util_common_calloc_s(size_t size);

char *util_strdup_s(const char *src);

int wait_for_pid(pid_t pid);

void util_contain_errmsg(const char *errmsg, int *exit_code);

char *util_short_digest(const char *digest);

char *util_full_digest(const char *digest);

proc_t *util_stat2proc(const char *s, size_t len);

bool util_process_alive(pid_t pid, unsigned long long start_time);

int wait_for_pid_status(pid_t pid);

typedef void (*exec_func_t)(void *args);
bool util_exec_cmd(exec_func_t cb_func, void *args, const char *stdin_msg, char **stdout_msg, char **stderr_msg);

typedef void (*exec_top_func_t)(char **args, const char *pid_args, size_t args_len);
bool util_exec_top_cmd(exec_top_func_t cb_func, char **args, const char *pid_args, size_t args_len, char **stdout_msg,
                       char **stderr_msg);

char **get_backtrace(void);

int util_parse_time_str_to_nanoseconds(const char *value, int64_t *nanoseconds);

proc_t *util_get_process_proc_info(pid_t pid);

int util_parse_user_remap(const char *user_remap, unsigned int *host_uid, unsigned int *host_gid, unsigned int *size);

int util_env_insert(char ***penv, size_t *penv_len, const char *key, size_t key_len, const char *newkv);
int util_env_set_val(char ***penv, const size_t *penv_len, const char *key, size_t key_len, const char *newkv);
char *util_env_get_val(char **env, size_t env_len, const char *key, size_t key_len);

char *util_str_token(char **input, const char *delimiter);
bool check_sysctl_valid(const char *sysctl_key);
bool pid_max_kernel_namespaced();
void free_sensitive_string(char *str);
void memset_sensitive_string(char *str);

int util_input_readall(char *buf, size_t maxlen);
int util_input_echo(char *buf, size_t maxlen);
int util_input_noecho(char *buf, size_t maxlen);

bool util_check_signal_valid(int sig);

void usleep_nointerupt(unsigned long usec);

int util_generate_random_str(char *id, size_t len);

void add_array_elem(char **array, size_t total, size_t *pos, const char *elem);

void add_array_kv(char **array, size_t total, size_t *pos, const char *k, const char *v);

typedef int (*mount_info_call_back_t)(const char *, const char *);
bool util_deal_with_mount_info(mount_info_call_back_t cb, const char *);

int util_validate_env(const char *env, char **dst);

int util_check_inherited_exclude_fds(bool closeall, int *fds_to_ignore, size_t len_fds);

int get_cpu_num_cores(void);

char *util_uint_to_string(long long unsigned int data);

char *util_int_to_string(long long int data);

char *without_sha256_prefix(char *digest);

int normalized_host_os_arch(char **host_os, char **host_arch, char **host_variant);

char *util_full_digest_str(char *str);

#ifdef __cplusplus
}
#endif

#endif /* __UTILS_H */
