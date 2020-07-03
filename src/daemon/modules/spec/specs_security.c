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
 * Author: tanyifeng
 * Create: 2017-11-22
 * Description: provide container specs functions
 ******************************************************************************/
#include "specs_security.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/utsname.h>
#include <sched.h>
#include <ctype.h>
#ifdef HAVE_LIBCAP_H
#include <sys/capability.h>
#endif

#include "error.h"
#include "isula_libutils/log.h"
#include "isula_libutils/oci_runtime_spec.h"
#include "isula_libutils/docker_seccomp.h"
#include "isula_libutils/host_config.h"
#include "utils.h"
#include "config.h"
#include "isulad_config.h"
#include "isula_libutils/parse_common.h"
#include "err_msg.h"
#include "specs_extend.h"
#include "selinux_label.h"
#include "specs_api.h"
#include "constants.h"

#define MAX_CAP_LEN 32

static const char * const g_system_caps[] = { "SYS_BOOT",     "SETPCAP", "NET_RAW", "NET_BIND_SERVICE",
#ifdef CAP_AUDIT_WRITE
                                              "AUDIT_WRITE",
#endif
                                              "DAC_OVERRIDE", "SETFCAP", "SETGID",  "SETUID",           "MKNOD", "CHOWN",
                                              "FOWNER",       "FSETID",  "KILL",    "SYS_CHROOT"
                                            };

static int append_capability(char ***dstcaps, size_t *dstcaps_len, const char *cap)
{
    int ret = 0;
    char **tmp = NULL;

    if (*dstcaps_len > SIZE_MAX / sizeof(char *) - 1) {
        ERROR("Too many capabilities to append!");
        ret = -1;
        goto out;
    }
    ret = mem_realloc((void **)&tmp, sizeof(char *) * (*dstcaps_len + 1), *dstcaps, sizeof(char *) * (*dstcaps_len));
    if (ret != 0) {
        ERROR("Out of memory");
        ret = -1;
        goto out;
    }
    *dstcaps = tmp;
    (*dstcaps_len)++;

    (*dstcaps)[*dstcaps_len - 1] = util_strdup_s(cap);
out:
    return ret;
}

static int copy_capabilities(char ***dstcaps, size_t *dstcaps_len, const char **srccaps, size_t srccaps_len)
{
    size_t i;
    int ret = 0;

    if (srccaps == NULL || srccaps_len == 0) {
        *dstcaps = NULL;
        *dstcaps_len = 0;
        return ret;
    }
    if (srccaps_len > SIZE_MAX / sizeof(char *)) {
        ERROR("Too many capabilities to copy!");
        return -1;
    }

    *dstcaps = util_common_calloc_s(srccaps_len * sizeof(char *));
    if (*dstcaps == NULL) {
        ret = -1;
        goto out;
    }

    *dstcaps_len = srccaps_len;

    for (i = 0; i < srccaps_len; i++) {
        (*dstcaps)[i] = util_strdup_s(srccaps[i]);
    }
out:
    return ret;
}

static int tweak_drops_capabilities(char ***new_caps, size_t *new_caps_len, char **basic_caps, size_t basic_caps_len,
                                    const char **drops, size_t drops_len)
{
    size_t i = 0;
    int ret = 0;

    if (strings_in_slice((const char **)drops, drops_len, "all")) {
        goto out;
    }

    for (i = 0; (basic_caps != NULL && i < basic_caps_len); i++) {
        // skip `all` already handled above
        if (!basic_caps[i] || !strcasecmp(basic_caps[i], "all")) {
            continue;
        }

        // if we don't drop `all`, add back all the non-dropped caps
        if (!strings_in_slice((const char **)drops, drops_len, basic_caps[i] + strlen("CAP_"))) {
            ret = append_capability(new_caps, new_caps_len, basic_caps[i]);
            if (ret != 0) {
                ERROR("Failed to append capabilities");
                ret = -1;
                goto out;
            }
        }
    }

out:
    return ret;
}

static int tweak_adds_capabilities(char ***new_caps, size_t *new_caps_len, const char **adds, size_t adds_len)
{
    size_t i = 0;
    int ret = 0;
    int nret = 0;
    size_t all_caps_len = 0;
    char tmpcap[MAX_CAP_LEN] = { 0 };

    all_caps_len = util_get_all_caps_len();

    for (i = 0; i < adds_len; i++) {
        // skip `all` already handled above
        if (strcasecmp(adds[i], "all") == 0) {
            continue;
        }

        nret = snprintf(tmpcap, sizeof(tmpcap), "CAP_%s", adds[i]);
        if (nret < 0 || (size_t)nret >= sizeof(tmpcap)) {
            ERROR("Failed to print string");
            ret = -1;
            goto out;
        }
        if (!strings_in_slice(g_all_caps, all_caps_len, tmpcap)) {
            ERROR("Unknown capability to add: '%s'", tmpcap);
            ret = -1;
            goto out;
        }

        // add cap if not already in the list
        if (!strings_in_slice((const char **)*new_caps, *new_caps_len, tmpcap)) {
            ret = append_capability(new_caps, new_caps_len, tmpcap);
            if (ret != 0) {
                ERROR("Failed to append capabilities");
                ret = -1;
                goto out;
            }
        }
    }

out:
    return ret;
}

static bool valid_drops_cap(const char **drops, size_t drops_len)
{
    int nret = 0;
    size_t i;
    size_t all_caps_len = 0;
    char tmpcap[MAX_CAP_LEN] = { 0 };

    all_caps_len = util_get_all_caps_len();
    // look for invalid cap in the drop list
    for (i = 0; i < drops_len; i++) {
        if (strcasecmp(drops[i], "all") == 0) {
            continue;
        }

        nret = snprintf(tmpcap, sizeof(tmpcap), "CAP_%s", drops[i]);
        if (nret < 0 || (size_t)nret >= sizeof(tmpcap)) {
            ERROR("Failed to print string");
            return false;
        }
        if (!strings_in_slice(g_all_caps, all_caps_len, tmpcap)) {
            ERROR("Unknown capability to drop: '%s'", drops[i]);
            return false;
        }
    }

    return true;
}

// tweak_capabilities can tweak capabilities by adding or dropping capabilities
// based on the basic capabilities.
static int tweak_capabilities(char ***caps, size_t *caps_len, const char **adds, size_t adds_len, const char **drops,
                              size_t drops_len)
{
    size_t i;
    size_t all_caps_len = 0;
    int ret = 0;
    char **new_caps = NULL;
    char **basic_caps = NULL;
    size_t new_caps_len = 0;
    size_t basic_caps_len = 0;

    all_caps_len = util_get_all_caps_len();
    if (!valid_drops_cap(drops, drops_len)) {
        return -1;
    }

    if (strings_in_slice((const char **)adds, adds_len, "all")) {
        ret = copy_capabilities(&basic_caps, &basic_caps_len, g_all_caps, all_caps_len);
    } else {
        ret = copy_capabilities(&basic_caps, &basic_caps_len, (const char **)*caps, *caps_len);
    }
    if (ret != 0) {
        ERROR("Failed to copy capabilities");
        ret = -1;
        goto free_out;
    }

    ret = tweak_drops_capabilities(&new_caps, &new_caps_len, basic_caps, basic_caps_len, drops, drops_len);
    if (ret != 0) {
        ret = -1;
        goto free_out;
    }

    ret = tweak_adds_capabilities(&new_caps, &new_caps_len, adds, adds_len);
    if (ret != 0) {
        ret = -1;
        goto free_out;
    }

free_out:
    for (i = 0; i < basic_caps_len; i++) {
        free(basic_caps[i]);
    }
    free(basic_caps);

    // free old caps
    for (i = 0; i < *caps_len; i++) {
        free((*caps)[i]);
        (*caps)[i] = NULL;
    }
    free(*caps);

    // set new caps
    *caps = new_caps;
    *caps_len = new_caps_len;

    return ret;
}

int refill_oci_process_capabilities(defs_process_capabilities **caps, const char **src_caps, size_t src_caps_len)
{
    int ret = 0;
    size_t i = 0;

    if (*caps == NULL) {
        *caps = util_common_calloc_s(sizeof(defs_process_capabilities));
        if (*caps == NULL) {
            ret = -1;
            goto out;
        }
    }

    if ((*caps)->bounding != NULL) {
        // free current capabilities
        for (i = 0; i < ((*caps)->bounding_len); i++) {
            free((*caps)->bounding[i]);
            (*caps)->bounding[i] = NULL;
        }
        free((*caps)->bounding);
        (*caps)->bounding = NULL;
    }
    (*caps)->bounding_len = 0;

    // copy capabilities
    ret = copy_capabilities(&((*caps)->bounding), &((*caps)->bounding_len), src_caps, src_caps_len);
    if (ret != 0) {
        ERROR("Failed to copy all capabilities");
    }
out:
    return ret;
}

static char *seccomp_trans_arch_for_docker(const char *arch)
{
    size_t i = 0;
    char *arch_map[][2] = { { "SCMP_ARCH_X86", "x86" },
        { "SCMP_ARCH_X86_64", "amd64" },
        { "SCMP_ARCH_X32", "x32" },
        { "SCMP_ARCH_ARM", "arm" },
        { "SCMP_ARCH_AARCH64", "arm64" },
        { "SCMP_ARCH_MIPS", "mips" },
        { "SCMP_ARCH_MIPS64", "mips64" },
        { "SCMP_ARCH_MIPS64N32", "mips64n32" },
        { "SCMP_ARCH_MIPSEL", "mipsel" },
        { "SCMP_ARCH_MIPSEL64", "mipsel64" },
        { "SCMP_ARCH_MIPSEL64N32", "mipsel64n32" },
        { "SCMP_ARCH_PPC", "ppc" },
        { "SCMP_ARCH_PPC64", "ppc64" },
        { "SCMP_ARCH_PPC64LE", "ppc64le" },
        { "SCMP_ARCH_S390", "s390" },
        { "SCMP_ARCH_S390X", "s390x" },
        { "SCMP_ARCH_PARISC", "parisc" },
        { "SCMP_ARCH_PARISC64", "parisc64" },
        { "SCMP_ARCH_ALL", "all" }
    };
    for (i = 0; i < sizeof(arch_map) / sizeof(arch_map[0]); i++) {
        if (strcmp(arch, arch_map[i][0]) == 0) {
            return util_strdup_s(arch_map[i][1]);
        }
    }

    return NULL;
}

static bool is_arch_in_seccomp(const docker_seccomp *seccomp, const char *arch)
{
    size_t i, j;
    char *arch_for_docker = NULL;

    for (i = 0; i < seccomp->arch_map_len; i++) {
        int nret = 0;
        arch_for_docker = seccomp_trans_arch_for_docker(seccomp->arch_map[i]->architecture);
        if (arch_for_docker == NULL) {
            return false;
        }
        nret = strcmp(arch_for_docker, arch);
        free(arch_for_docker);
        if (nret == 0) {
            return true;
        }
        for (j = 0; j < seccomp->arch_map[i]->sub_architectures_len; j++) {
            arch_for_docker = seccomp_trans_arch_for_docker(seccomp->arch_map[i]->sub_architectures[j]);
            if (arch_for_docker == NULL) {
                return false;
            }
            nret = strcmp(arch_for_docker, arch);
            free(arch_for_docker);
            if (nret == 0) {
                return true;
            }
        }
    }
    return false;
}

static bool is_cap_in_seccomp(const defs_process_capabilities *capabilites, const char *cap)
{
    size_t i = 0;

    if (capabilites == NULL) {
        return false;
    }

    for (i = 0; i < capabilites->bounding_len; i++) {
        if (strcasecmp(capabilites->bounding[i], cap) == 0) {
            return true;
        }
    }
    return false;
}

static void meet_include(const docker_seccomp *seccomp, const docker_seccomp_syscalls_element *syscall,
                         const defs_process_capabilities *capabilites, bool *meet_include_arch, bool *meet_include_cap)
{
    size_t i;

    if (syscall->includes == NULL) {
        *meet_include_arch = true;
        *meet_include_cap = true;
        return;
    }
    if (syscall->includes->arches == NULL) {
        *meet_include_arch = true;
    } else {
        for (i = 0; i < syscall->includes->arches_len; i++) {
            if (is_arch_in_seccomp(seccomp, syscall->includes->arches[i])) {
                *meet_include_arch = true;
                break;
            }
        }
    }
    if (syscall->includes->caps == NULL) {
        *meet_include_cap = true;
    } else {
        for (i = 0; i < syscall->includes->caps_len; i++) {
            if (is_cap_in_seccomp(capabilites, syscall->includes->caps[i])) {
                *meet_include_cap = true;
                break;
            }
        }
    }
}

static void meet_exclude(const docker_seccomp *seccomp, const docker_seccomp_syscalls_element *syscall,
                         const defs_process_capabilities *capabilites, bool *meet_exclude_arch, bool *meet_exclude_cap)
{
    size_t i;

    if (syscall->excludes == NULL) {
        *meet_exclude_arch = true;
        *meet_exclude_cap = true;
        return;
    }

    if (syscall->excludes->arches == NULL) {
        *meet_exclude_arch = true;
    } else {
        for (i = 0; i < syscall->excludes->arches_len; i++) {
            if (is_arch_in_seccomp(seccomp, syscall->excludes->arches[i])) {
                *meet_exclude_arch = false;
                break;
            }
        }
    }
    if (syscall->excludes->caps == NULL) {
        *meet_exclude_cap = true;
    } else {
        for (i = 0; i < syscall->excludes->caps_len; i++) {
            if (is_cap_in_seccomp(capabilites, syscall->excludes->caps[i])) {
                *meet_exclude_cap = false;
                break;
            }
        }
    }
}

static bool meet_filtering_rules(const docker_seccomp *seccomp, const docker_seccomp_syscalls_element *syscall,
                                 const defs_process_capabilities *capabilites)
{
    bool meet_include_arch = false;
    bool meet_include_cap = false;
    bool meet_exclude_arch = true;
    bool meet_exclude_cap = true;

    meet_include(seccomp, syscall, capabilites, &meet_include_arch, &meet_include_cap);
    meet_exclude(seccomp, syscall, capabilites, &meet_exclude_arch, &meet_exclude_cap);

    return meet_include_arch && meet_include_cap && meet_exclude_arch && meet_exclude_cap;
}

static size_t docker_seccomp_arches_count(const docker_seccomp *docker_seccomp_spec)
{
    size_t count = 0;
    size_t i = 0;
    for (i = 0; i < docker_seccomp_spec->arch_map_len; i++) {
        count += docker_seccomp_spec->arch_map[i]->sub_architectures_len + 1;
    }
    return count;
}

static int dup_architectures_to_oci_spec(const docker_seccomp *docker_seccomp_spec,
                                         oci_runtime_config_linux_seccomp *oci_seccomp_spec)
{
    size_t arch_size = 0;

    arch_size = docker_seccomp_arches_count(docker_seccomp_spec);
    if (arch_size != 0) {
        size_t i;
        size_t j;
        if (arch_size > (SIZE_MAX / sizeof(char *))) {
            return -1;
        }
        oci_seccomp_spec->architectures = util_common_calloc_s(arch_size * sizeof(char *));
        if (oci_seccomp_spec->architectures == NULL) {
            return -1;
        }
        for (i = 0; i < docker_seccomp_spec->arch_map_len; i++) {
            oci_seccomp_spec->architectures[oci_seccomp_spec->architectures_len++] =
                util_strdup_s(docker_seccomp_spec->arch_map[i]->architecture);
            for (j = 0; j < docker_seccomp_spec->arch_map[i]->sub_architectures_len; j++) {
                oci_seccomp_spec->architectures[oci_seccomp_spec->architectures_len++] =
                    util_strdup_s(docker_seccomp_spec->arch_map[i]->sub_architectures[j]);
            }
        }
    }

    return 0;
}

static int dup_syscall_args_to_oci_spec(const docker_seccomp_syscalls_element *docker_syscall,
                                        defs_syscall *oci_syscall)
{
    size_t i = 0;

    if (docker_syscall->args_len == 0) {
        return 0;
    }

    if (docker_syscall->args_len > (SIZE_MAX / sizeof(defs_syscall_arg *))) {
        return -1;
    }

    oci_syscall->args = util_common_calloc_s(docker_syscall->args_len * sizeof(defs_syscall_arg *));
    if (oci_syscall->args == NULL) {
        return -1;
    }
    for (i = 0; i < docker_syscall->args_len; i++) {
        oci_syscall->args[i] = util_common_calloc_s(sizeof(defs_syscall_arg));
        if (oci_syscall->args[i] == NULL) {
            return -1;
        }
        defs_syscall_arg *args_element = oci_syscall->args[i];
        args_element->index = docker_syscall->args[i]->index;
        args_element->value = docker_syscall->args[i]->value;
        args_element->value_two = docker_syscall->args[i]->value_two;
        args_element->op = util_strdup_s(docker_syscall->args[i]->op);
        oci_syscall->args_len++;
    }

    return 0;
}

static int dup_syscall_to_oci_spec(const docker_seccomp *docker_seccomp_spec,
                                   oci_runtime_config_linux_seccomp *oci_seccomp_spec,
                                   const defs_process_capabilities *capabilites)
{
    int ret = 0;
    size_t i, j, k;
    size_t new_size, old_size;
    defs_syscall **tmp_syscalls = NULL;

    if (docker_seccomp_spec->syscalls_len == 0) {
        return 0;
    }

    if (docker_seccomp_spec->syscalls_len > (SIZE_MAX / sizeof(defs_syscall *))) {
        return -1;
    }

    oci_seccomp_spec->syscalls = util_common_calloc_s(docker_seccomp_spec->syscalls_len * sizeof(defs_syscall *));
    if (oci_seccomp_spec->syscalls == NULL) {
        return -1;
    }
    for (i = 0; i < docker_seccomp_spec->syscalls_len; i++) {
        if (!meet_filtering_rules(docker_seccomp_spec, docker_seccomp_spec->syscalls[i], capabilites)) {
            continue;
        }
        k = oci_seccomp_spec->syscalls_len;
        oci_seccomp_spec->syscalls[k] = util_common_calloc_s(sizeof(defs_syscall));
        if (oci_seccomp_spec->syscalls[k] == NULL) {
            return -1;
        }
        oci_seccomp_spec->syscalls_len++;

        if (docker_seccomp_spec->syscalls[i]->names_len > (SIZE_MAX / sizeof(char *))) {
            return -1;
        }

        oci_seccomp_spec->syscalls[k]->names =
            util_common_calloc_s(docker_seccomp_spec->syscalls[i]->names_len * sizeof(char *));
        if (oci_seccomp_spec->syscalls[k]->names == NULL) {
            return -1;
        }
        for (j = 0; j < docker_seccomp_spec->syscalls[i]->names_len; j++) {
            oci_seccomp_spec->syscalls[k]->names[j] = util_strdup_s(docker_seccomp_spec->syscalls[i]->names[j]);
            oci_seccomp_spec->syscalls[k]->names_len++;
        }
        oci_seccomp_spec->syscalls[k]->action = util_strdup_s(docker_seccomp_spec->syscalls[i]->action);
        if (dup_syscall_args_to_oci_spec(docker_seccomp_spec->syscalls[i], oci_seccomp_spec->syscalls[k])) {
            return -1;
        }
    }

    new_size = sizeof(defs_syscall *) * oci_seccomp_spec->syscalls_len;
    old_size = sizeof(defs_syscall *) * docker_seccomp_spec->syscalls_len;
    ret = mem_realloc((void **)&tmp_syscalls, new_size, oci_seccomp_spec->syscalls, old_size);
    if (ret < 0) {
        ERROR("Out of memory");
        return -1;
    }
    oci_seccomp_spec->syscalls = tmp_syscalls;

    return 0;
}

static oci_runtime_config_linux_seccomp *
trans_docker_seccomp_to_oci_format(const docker_seccomp *docker_seccomp_spec,
                                   const defs_process_capabilities *capabilites)
{
    oci_runtime_config_linux_seccomp *oci_seccomp_spec = NULL;

    oci_seccomp_spec = util_common_calloc_s(sizeof(oci_runtime_config_linux_seccomp));
    if (oci_seccomp_spec == NULL) {
        goto out;
    }

    // default action
    oci_seccomp_spec->default_action = util_strdup_s(docker_seccomp_spec->default_action);

    // architectures
    if (dup_architectures_to_oci_spec(docker_seccomp_spec, oci_seccomp_spec)) {
        goto out;
    }

    // syscalls
    if (dup_syscall_to_oci_spec(docker_seccomp_spec, oci_seccomp_spec, capabilites)) {
        goto out;
    }

    goto done;
out:
    if (oci_seccomp_spec != NULL) {
        free_oci_runtime_config_linux_seccomp(oci_seccomp_spec);
    }
    return NULL;

done:
    return oci_seccomp_spec;
}

int merge_default_seccomp_spec(oci_runtime_spec *oci_spec, const defs_process_capabilities *capabilites)
{
    oci_runtime_config_linux_seccomp *oci_seccomp_spec = NULL;
    docker_seccomp *docker_seccomp_spec = NULL;

    if (oci_spec->process == NULL || oci_spec->process->capabilities == NULL) {
        return 0;
    }

    docker_seccomp_spec = get_seccomp_security_opt_spec(SECCOMP_DEFAULT_PATH);
    if (docker_seccomp_spec == NULL) {
        ERROR("Failed to parse docker format seccomp specification file \"%s\"", SECCOMP_DEFAULT_PATH);
        isulad_set_error_message("failed to parse seccomp file: %s", SECCOMP_DEFAULT_PATH);
        return -1;
    }
    oci_seccomp_spec = trans_docker_seccomp_to_oci_format(docker_seccomp_spec, capabilites);
    free_docker_seccomp(docker_seccomp_spec);
    if (oci_seccomp_spec == NULL) {
        ERROR("Failed to trans docker format seccomp profile to oci standard");
        isulad_set_error_message("Failed to trans docker format seccomp profile to oci standard");
        return -1;
    }

    oci_spec->linux->seccomp = oci_seccomp_spec;

    return 0;
}

static int append_systemcall_to_seccomp(oci_runtime_config_linux_seccomp *seccomp, defs_syscall *element)
{
    int nret = 0;
    size_t old_size, new_size;
    defs_syscall **tmp_syscalls = NULL;
    if (seccomp == NULL || element == NULL) {
        return -1;
    }

    if (seccomp->syscalls_len > SIZE_MAX / sizeof(defs_syscall *) - 1) {
        CRIT("Too many syscalls to append!");
        return -1;
    }
    new_size = (seccomp->syscalls_len + 1) * sizeof(defs_syscall *);
    old_size = new_size - sizeof(defs_syscall *);
    nret = mem_realloc((void **)&tmp_syscalls, new_size, seccomp->syscalls, old_size);
    if (nret < 0) {
        CRIT("Memory allocation error.");
        return -1;
    }
    tmp_syscalls[seccomp->syscalls_len++] = element;
    seccomp->syscalls = tmp_syscalls;

    return 0;
}

static defs_syscall *make_seccomp_syscalls_element(const char **names, size_t names_len, const char *action,
                                                   size_t args_len, defs_syscall_arg **args)
{
    size_t i = 0;
    defs_syscall *ret = NULL;
    ret = util_common_calloc_s(sizeof(defs_syscall));
    if (ret == NULL) {
        CRIT("Memory allocation error.");
        goto out;
    }
    ret->action = util_strdup_s(action ? action : "");
    ret->args_len = args_len;
    if (args_len) {
        if (args_len > SIZE_MAX / sizeof(defs_syscall_arg *)) {
            CRIT("Too many seccomp syscalls!");
            goto out;
        }
        ret->args = util_common_calloc_s(args_len * sizeof(defs_syscall_arg *));
        if (ret->args == NULL) {
            CRIT("Memory allocation error.");
            goto out;
        }
        for (i = 0; i < args_len; i++) {
            ret->args[i] = util_common_calloc_s(sizeof(defs_syscall_arg));
            if (ret->args[i] == NULL) {
                CRIT("Memory allocation error.");
                goto out;
            }
            ret->args[i]->index = args[i]->index;
            ret->args[i]->value = args[i]->value;
            ret->args[i]->value_two = args[i]->value_two;
            ret->args[i]->op = util_strdup_s(args[i]->op);
        }
    }

    ret->names_len = names_len;
    if (names_len > SIZE_MAX / sizeof(char *)) {
        CRIT("Too many syscalls!");
        goto out;
    }
    ret->names = util_common_calloc_s(names_len * sizeof(char *));
    if (ret->names == NULL) {
        CRIT("Memory allocation error.");
        goto out;
    }
    for (i = 0; i < names_len; i++) {
        ret->names[i] = util_strdup_s(names[i]);
    }

    return ret;

out:
    free_defs_syscall(ret);
    ret = NULL;
    return ret;
}

static int make_sure_oci_spec_process_capabilities(oci_runtime_spec *oci_spec)
{
    int ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->process->capabilities == NULL) {
        oci_spec->process->capabilities = util_common_calloc_s(sizeof(defs_process_capabilities));
        if (oci_spec->process->capabilities == NULL) {
            return -1;
        }
    }
    return 0;
}

int merge_caps(oci_runtime_spec *oci_spec, const char **adds, size_t adds_len, const char **drops, size_t drops_len)
{
    int ret = 0;

    if (adds == NULL && drops == NULL) {
        return 0;
    }

    ret = make_sure_oci_spec_process_capabilities(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (adds_len > LIST_SIZE_MAX || drops_len > LIST_SIZE_MAX) {
        ERROR("Too many capabilities to add or drop, the limit is %lld", LIST_SIZE_MAX);
        isulad_set_error_message("Too many capabilities to add or drop, the limit is %d", LIST_SIZE_MAX);
        ret = -1;
        goto out;
    }

    ret = tweak_capabilities(&oci_spec->process->capabilities->bounding, &oci_spec->process->capabilities->bounding_len,
                             adds, adds_len, drops, drops_len);
    if (ret != 0) {
        ERROR("Failed to tweak capabilities");
        ret = -1;
        goto out;
    }

out:
    return ret;
}

static int make_sure_oci_spec_linux_sysctl(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->sysctl == NULL) {
        oci_spec->linux->sysctl = util_common_calloc_s(sizeof(json_map_string_string));
        if (oci_spec->linux->sysctl == NULL) {
            return -1;
        }
    }
    return 0;
}

int merge_sysctls(oci_runtime_spec *oci_spec, const json_map_string_string *sysctls)
{
    int ret = 0;
    size_t i;

    if (sysctls == NULL || sysctls->len == 0) {
        return 0;
    }

    ret = make_sure_oci_spec_linux_sysctl(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (sysctls->len > LIST_SIZE_MAX) {
        ERROR("Too many sysctls to add, the limit is %lld", LIST_SIZE_MAX);
        isulad_set_error_message("Too many sysctls to add, the limit is %d", LIST_SIZE_MAX);
        ret = -1;
        goto out;
    }

    for (i = 0; i < sysctls->len; i++) {
        if (append_json_map_string_string(oci_spec->linux->sysctl, sysctls->keys[i], sysctls->values[i]) != 0) {
            ERROR("Append string failed");
            goto out;
        }
    }
out:
    return ret;
}

int merge_no_new_privileges(oci_runtime_spec *oci_spec, bool value)
{
    int ret = 0;

    ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    oci_spec->process->no_new_privileges = value;

out:
    return ret;
}

int merge_selinux(oci_runtime_spec *oci_spec, container_config_v2_common_config *v2_spec, const char **label_opts,
                  size_t label_opts_len)
{
    char *process_label = NULL;
    char *mount_label = NULL;

    int ret = make_sure_oci_spec_process(oci_spec);
    if (ret < 0) {
        goto out;
    }

    if (init_label(label_opts, label_opts_len, &process_label, &mount_label) != 0) {
        ERROR("Failed to append label");
        ret = -1;
        goto out;
    }

    if (mount_label != NULL) {
        oci_spec->linux->mount_label = util_strdup_s(mount_label);
        v2_spec->mount_label = util_strdup_s(mount_label);
    }

    if (process_label != NULL) {
        oci_spec->process->selinux_label = util_strdup_s(process_label);
        v2_spec->process_label = util_strdup_s(process_label);
    }

out:
    free(process_label);
    free(mount_label);
    return ret;
}

static int get_adds_cap_for_system_container(const host_config *host_spec, char ***adds, size_t *adds_len)
{
    size_t i = 0;
    int ret = 0;
    char **drops = NULL;
    size_t drops_len = 0;
    size_t system_caps_len = sizeof(g_system_caps) / sizeof(char *);

    if (host_spec == NULL || adds == NULL || adds_len == NULL) {
        return -1;
    }

    if (host_spec->cap_drop != NULL) {
        drops = host_spec->cap_drop;
        drops_len = host_spec->cap_drop_len;
    }

    // if cap_drop in g_system_caps, move it from g_system_caps
    for (i = 0; i < system_caps_len; i++) {
        if (!strings_in_slice((const char **)drops, drops_len, g_system_caps[i])) {
            ret = append_capability(adds, adds_len, g_system_caps[i]);
            if (ret != 0) {
                ERROR("Failed to append capabilities");
                ret = -1;
                goto out;
            }
        }
    }

out:
    return ret;
}

static void free_adds_cap_for_system_container(char **adds, size_t adds_len)
{
    size_t i = 0;

    if (adds == NULL) {
        return;
    }

    for (i = 0; i < adds_len; i++) {
        free(adds[i]);
    }
    free(adds);
}

static int make_sure_oci_spec_linux_seccomp(oci_runtime_spec *oci_spec)
{
    int ret = 0;

    ret = make_sure_oci_spec_linux(oci_spec);
    if (ret < 0) {
        return -1;
    }

    if (oci_spec->linux->seccomp == NULL) {
        oci_spec->linux->seccomp = util_common_calloc_s(sizeof(oci_runtime_config_linux_seccomp));
        if (oci_spec->linux->seccomp == NULL) {
            return -1;
        }
    }

    return 0;
}

int adapt_settings_for_system_container(oci_runtime_spec *oci_spec, const host_config *host_spec)
{
    int ret = 0;
    char *unblocked_systemcall_for_system_container[] = { "mount", "umount2", "reboot", "name_to_handle_at",
                                                          "unshare"
                                                        };
    char **adds = NULL;
    size_t adds_len = 0;
    bool no_new_privileges = false;
    char **label_opts = NULL;
    size_t label_opts_len = 0;
    char *seccomp_profile = NULL;

    ret = get_adds_cap_for_system_container(host_spec, &adds, &adds_len);
    if (ret != 0) {
        ERROR("Failed to get adds cap for system container");
        ret = -1;
        goto out;
    }

    ret = merge_caps(oci_spec, (const char **)adds, adds_len, NULL, 0);
    if (ret != 0) {
        ERROR("Failed to merge capabilities");
        ret = -1;
        goto out;
    }

    ret = parse_security_opt(host_spec, &no_new_privileges, &label_opts, &label_opts_len, &seccomp_profile);
    if (ret != 0) {
        ERROR("Failed to parse security opt");
        goto out;
    }
    /* do not append to seccomp if seccomp profile unconfined */
    if (seccomp_profile != NULL && strcmp(seccomp_profile, "unconfined") == 0) {
        goto out;
    }

    ret = make_sure_oci_spec_linux(oci_spec);
    if (ret < 0) {
        goto out;
    }

    ret = make_sure_oci_spec_linux_seccomp(oci_spec);
    if (ret < 0) {
        goto out;
    }

    ret = append_systemcall_to_seccomp(
              oci_spec->linux->seccomp,
              make_seccomp_syscalls_element((const char **)unblocked_systemcall_for_system_container,
                                            sizeof(unblocked_systemcall_for_system_container) /
                                            sizeof(unblocked_systemcall_for_system_container[0]),
                                            "SCMP_ACT_ALLOW", 0, NULL));
    if (ret != 0) {
        ERROR("Failed to append systemcall to seccomp file");
        ret = -1;
        goto out;
    }
out:
    util_free_array(label_opts);
    free(seccomp_profile);
    free_adds_cap_for_system_container(adds, adds_len);
    return ret;
}

int merge_seccomp(oci_runtime_spec *oci_spec, const char *seccomp_profile)
{
    int ret = 0;
    parser_error err = NULL;
    docker_seccomp *docker_seccomp = NULL;

    if (seccomp_profile == NULL) {
        return 0;
    }

    ret = make_sure_oci_spec_linux(oci_spec);
    if (ret < 0) {
        goto out;
    }
    // free default seccomp
    free_oci_runtime_config_linux_seccomp(oci_spec->linux->seccomp);
    oci_spec->linux->seccomp = NULL;

    if (strcmp(seccomp_profile, "unconfined") == 0) {
        goto out;
    }
    docker_seccomp = docker_seccomp_parse_data((const char *)seccomp_profile, NULL, &err);
    if (docker_seccomp == NULL) {
        ERROR("Failed to parse host config data:%s", err);
        ret = -1;
        goto out;
    }
    oci_spec->linux->seccomp = trans_docker_seccomp_to_oci_format(docker_seccomp, oci_spec->process->capabilities);
    if (oci_spec->linux->seccomp == NULL) {
        ERROR("Failed to trans docker seccomp format to oci profile");
        ret = -1;
        goto out;
    }

out:
    free(err);
    free_docker_seccomp(docker_seccomp);
    return ret;
}
