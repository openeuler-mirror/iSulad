/******************************************************************************
 * Copyright (c) Huawei Technologies Co., Ltd. 2018-2019. All rights reserved.
 * iSulad licensed under the Mulan PSL v1.
 * You can use this software according to the terms and conditions of the Mulan PSL v1.
 * You may obtain a copy of Mulan PSL v1 at:
 *     http://license.coscl.org.cn/MulanPSL
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND, EITHER EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT, MERCHANTABILITY OR FIT FOR A PARTICULAR
 * PURPOSE.
 * See the Mulan PSL v1 for more details.
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide macro definition
 ******************************************************************************/

#ifndef _LCRD_CONSTANTS_H
#define _LCRD_CONSTANTS_H

/* mode of file and directory */

#define DEFAULT_SECURE_FILE_MODE 0640

#define DEFAULT_SECURE_DIRECTORY_MODE 0750

#define USER_REMAP_DIRECTORY_MODE 0751

#define ROOTFS_MNT_DIRECTORY_MODE 0640

#define CONFIG_DIRECTORY_MODE 0750

#define CONFIG_FILE_MODE 0640

#define ARCH_LOG_FILE_MODE 0440

#define WORKING_LOG_FILE_MODE 0640

#define LOG_DIRECTORY_MODE 0750

#define TEMP_DIRECTORY_MODE 0750

#define CONSOLE_FIFO_DIRECTORY_MODE 0770

#define SOCKET_GROUP_DIRECTORY_MODE 0660

#define DEBUG_FILE_MODE 0640

#define DEBUG_DIRECTORY_MODE 0750

#define ISULAD_CONFIG "/etc/isulad"

#define ISULAD_DAEMON_JSON_CONF_FILE ISULAD_CONFIG "/daemon.json"

#define DEFAULT_CA_FILE "ca.pem"
#define DEFAULT_KEY_FILE "key.pem"
#define DEFAULT_CERT_FILE "cert.pem"


#define LOG_MAX_RETRIES 10

#define MAX_MSG_BUFFER_SIZE (32 * 1024)

#endif
