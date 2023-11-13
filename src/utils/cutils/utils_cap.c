/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2022. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: xuxuepeng
 * Create: 2023-11-08
 * Description: provide capbilities utils functions
 *******************************************************************************/

#define _GNU_SOURCE

#include "utils_cap.h"

#include <stdint.h>
#include <stdio.h>
#include <isula_libutils/log.h>

#include "utils_string.h"

const char *g_all_caps[] = {
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_DAC_READ_SEARCH",
    "CAP_FOWNER",
    "CAP_FSETID",
    "CAP_KILL",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SETPCAP",
    "CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE",
    "CAP_NET_BROADCAST",
    "CAP_NET_ADMIN",
    "CAP_NET_RAW",
    "CAP_IPC_LOCK",
    "CAP_IPC_OWNER",
    "CAP_SYS_MODULE",
    "CAP_SYS_RAWIO",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
    "CAP_SYS_PACCT",
    "CAP_SYS_ADMIN",
    "CAP_SYS_BOOT",
    "CAP_SYS_NICE",
    "CAP_SYS_RESOURCE",
    "CAP_SYS_TIME",
    "CAP_SYS_TTY_CONFIG",
    "CAP_MKNOD",
    "CAP_LEASE",
#ifdef CAP_AUDIT_WRITE
    "CAP_AUDIT_WRITE",
#endif
#ifdef CAP_AUDIT_CONTROL
    "CAP_AUDIT_CONTROL",
#endif
    "CAP_SETFCAP",
    "CAP_MAC_OVERRIDE",
    "CAP_MAC_ADMIN",
#ifdef CAP_SYSLOG
    "CAP_SYSLOG",
#endif
#ifdef CAP_WAKE_ALARM
    "CAP_WAKE_ALARM",
#endif
#ifdef CAP_BLOCK_SUSPEND
    "CAP_BLOCK_SUSPEND",
#endif
#ifdef CAP_AUDIT_READ
    "CAP_AUDIT_READ",
#endif
#ifdef CAP_PERFMON
    "CAP_PERFMON",
#endif
#ifdef CAP_BPF
    "CAP_BPF",
#endif
#ifdef CAP_CHECKPOINT_RESTORE
    "CAP_CHECKPOINT_RESTORE",
#endif
};

static inline size_t util_get_all_caps_len()
{
    return sizeof(g_all_caps) / sizeof(char *);
}

bool util_valid_cap(const char *cap)
{
    int nret = 0;
    char tmpcap[32] = { 0 };
    size_t all_caps_len = util_get_all_caps_len();

    if (cap == NULL) {
        return false;
    }

    nret = snprintf(tmpcap, sizeof(tmpcap), "CAP_%s", cap);
    if (nret < 0 || (size_t)nret >= sizeof(tmpcap)) {
        ERROR("Failed to print string");
        return false;
    }
    if (!util_strings_in_slice(g_all_caps, all_caps_len, tmpcap)) {
        return false;
    }

    return true;
}

const char **util_get_all_caps(size_t *cap_len)
{
    *cap_len = util_get_all_caps_len();
    return g_all_caps;
}
