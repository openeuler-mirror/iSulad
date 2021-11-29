/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-02-14
 * Description: provide namespace mock
 ******************************************************************************/

#include "isulad_config_mock.h"

static isulad_daemon_constants g_isulad_daemon_constants = {0};

namespace {
MockIsuladConf *g_isulad_conf_mock = nullptr;
}

void MockIsuladConf_SetMock(MockIsuladConf *mock)
{
    g_isulad_conf_mock = mock;
}

char *conf_get_routine_rootdir(const char *runtime)
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetRuntimeDir(runtime);
    }
    return nullptr;
}

char *conf_get_isulad_monitor_fifo_path()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetMonitordPath();
    }
    return nullptr;
}

int parse_log_opts(struct service_arguments *args, const char *key, const char *value)
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ParseLogopts(args, key, value);
    }
    return -1;
}

int conf_get_isulad_default_ulimit(host_config_ulimits_element ***ulimit)
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetUlimit(ulimit);
    }
    return -1;
}

int conf_get_isulad_hooks(oci_runtime_spec_hooks **phooks)
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetHooks(phooks);
    }
    return -1;
}

/* conf get isulad mount rootfs */
char *conf_get_isulad_mount_rootfs()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetMountrootfs();
    }
    return nullptr;
}

/* conf get isulad cgroup parent for containers */
char *conf_get_isulad_cgroup_parent()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetCgroupParent();
    }
    return nullptr;
}

char *conf_get_isulad_native_umask()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetUmask();
    }
    return nullptr;
}

char *conf_get_graph_rootpath()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ConfGetGraphRootpath();
    }
    return nullptr;
}

char *conf_get_isulad_storage_driver()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ConfGetIsuladStorageDriver();
    }
    return nullptr;
}

int isulad_server_conf_rdlock()
{
    return 0;
}

int isulad_server_conf_unlock()
{
    return 0;
}

struct service_arguments *conf_get_server_conf()
{
    return nullptr;
}

int get_system_cpu_usage(uint64_t *val)
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetSystemCpuUsage(val);
    }
    return 0;
}

char *conf_get_isulad_storage_driver_backing_fs()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ConfGetIsuladStorageDriverBackingFs();
    }
    return nullptr;
}

char *conf_get_isulad_rootdir()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ConfGetISuladRootDir();
    }
    return nullptr;
}

bool conf_get_use_decrypted_key_flag()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ConfGetUseDecryptedKeyFlag();
    }
    return true;
}

int init_isulad_daemon_constants()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->InitIsuladDaemonConstants();
    }
    return 0;
}

isulad_daemon_constants *get_isulad_daemon_constants()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->GetIsuladDaemonConstants();
    }
    return &g_isulad_daemon_constants;
}

char *conf_get_isulad_userns_remap()
{
    if (g_isulad_conf_mock != nullptr) {
        return g_isulad_conf_mock->ConfGetIsuladUsernsRemap();
    }
    return nullptr;
}