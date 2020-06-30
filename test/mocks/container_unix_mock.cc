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
 * Author: lifeng
 * Create: 2020-02-14
 * Description: provide container unix mock
 ******************************************************************************/

#include "container_unix_mock.h"

namespace {
MockContainerUnix *g_container_unix_mock = NULL;
}

void MockContainerUnix_SetMock(MockContainerUnix *mock)
{
    g_container_unix_mock = mock;
}

/* container unref */
void container_unref(container_t *cont)
{
    if (g_container_unix_mock != nullptr) {
        return g_container_unix_mock->ContainerUnref(cont);
    }
    return;
}

bool container_has_mount_for(container_t *cont, const char *mpath)
{
    if (g_container_unix_mock != nullptr) {
        return g_container_unix_mock->HasMountFor(cont, mpath);
    }
    return false;
}

int container_to_disk(const container_t *cont)
{
    if (g_container_unix_mock != nullptr) {
        return g_container_unix_mock->ContainerToDisk(cont);
    }
    return 0;
}

void container_unlock(container_t *cont)
{
    if (g_container_unix_mock != nullptr) {
        return g_container_unix_mock->ContainerUnlock(cont);
    }
}

void container_lock(container_t *cont)
{
    if (g_container_unix_mock != nullptr) {
        return g_container_unix_mock->ContainerLock(cont);
    }
}

void container_update_restart_manager(container_t *cont, const host_config_restart_policy *policy)
{
    if (g_container_unix_mock != nullptr) {
        return g_container_unix_mock->ContainerUpdateRestartManager(cont, policy);
    }
}
