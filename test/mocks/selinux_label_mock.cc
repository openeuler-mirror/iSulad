/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2020-2020. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: wujing
 * Create: 2020-02-11
 * Description: provide selinux label mock
 ******************************************************************************/

#include "selinux_label_mock.h"

namespace {
MockSelinuxLabel *g_selinux_label_mock = nullptr;
}

void SelinuxLabel_SetMock(MockSelinuxLabel* mock)
{
    g_selinux_label_mock = mock;
}

int selinux_state_init(void)
{
    if (g_selinux_label_mock != nullptr) {
        return g_selinux_label_mock->SelinuxStateInit();
    }
    return 0;
}

void selinux_set_disabled()
{
    if (g_selinux_label_mock != nullptr) {
        g_selinux_label_mock->SelinuxSetDisabled();
    }
}


bool selinux_get_enable()
{
    if (g_selinux_label_mock != nullptr) {
        return g_selinux_label_mock->SelinuxGetEnable();
    }
    return false;
}

int init_label(const char **label_opts, size_t label_opts_len, char **process_label, char **mount_label)
{
    if (g_selinux_label_mock != nullptr) {
        return g_selinux_label_mock->InitLabel(label_opts, label_opts_len, process_label, mount_label);
    }
    return 0;
}

int relabel(const char *path, const char *file_label, bool shared)
{
    if (g_selinux_label_mock != nullptr) {
        return g_selinux_label_mock->Relabel(path, file_label, shared);
    }
    return 0;
}

int get_disable_security_opt(char ***labels, size_t *labels_len)
{
    if (g_selinux_label_mock != nullptr) {
        return g_selinux_label_mock->GetDisableSecurityOpt(labels, labels_len);
    }
    return 0;
}

int dup_security_opt(const char *src, char ***dst, size_t *len)
{
    if (g_selinux_label_mock != nullptr) {
        return g_selinux_label_mock->DupSecurityOpt(src, dst, len);
    }
    return 0;
}
