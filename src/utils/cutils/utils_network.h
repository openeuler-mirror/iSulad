/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2021. All rights reserved.
 * iSulad licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *     http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v2 for more details.
 * Author: chengzeruizhi
 * Create: 2021-11-17
 * Description: provide common network functions
 ********************************************************************************/

#ifndef UTILS_CUTILS_UTILS_NETWORK_H
#define UTILS_CUTILS_UTILS_NETWORK_H

#ifdef __cplusplus
extern "C" {
#endif

int util_create_netns_file(const char *netns_path);

int util_mount_namespace(const char *netns_path);

int util_umount_namespace(const char *netns_path);

#ifdef __cplusplus
}
#endif

#endif // UTILS_CUTILS_UTILS_NETWORK_H