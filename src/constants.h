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
 * Author: lifeng
 * Create: 2018-11-08
 * Description: provide macro definition
 ******************************************************************************/

#ifndef _ISULAD_CONSTANTS_H
#define _ISULAD_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/* mode of file and directory */

#define DEFAULT_SECURE_FILE_MODE 0640

#define DEFAULT_SECURE_DIRECTORY_MODE 0750

#define USER_REMAP_DIRECTORY_MODE 0751

#define ROOTFS_MNT_DIRECTORY_MODE 0640

#define CONFIG_DIRECTORY_MODE 0750

#define CONFIG_FILE_MODE 0640

#define SECURE_CONFIG_FILE_MODE 0600

#define ARCH_LOG_FILE_MODE 0440

#define WORKING_LOG_FILE_MODE 0640

#define LOG_DIRECTORY_MODE 0750

#define TEMP_DIRECTORY_MODE 0750

#define CONSOLE_FIFO_DIRECTORY_MODE 0770

#define SOCKET_GROUP_DIRECTORY_MODE 0660

#define DEBUG_FILE_MODE 0640

#define DEBUG_DIRECTORY_MODE 0750

#define NETWORK_MOUNT_FILE_MODE 0644

#define ETC_FILE_MODE 0755

#define IMAGE_STORE_PATH_MODE 0700

#define ROOTFS_STORE_PATH_MODE 0700

#define ISULAD_CONFIG "/etc/isulad"

#define ISULAD_DAEMON_JSON_CONF_FILE ISULAD_CONFIG "/daemon.json"

#define DEFAULT_CA_FILE "ca.pem"
#define DEFAULT_KEY_FILE "key.pem"
#define DEFAULT_CERT_FILE "cert.pem"
#define OCI_CONFIG_JSON "config.json"
#define OCI_CONFIG_JSON_V1 "ociconfig.json"

#define LOG_MAX_RETRIES 10

#define MAX_MSG_BUFFER_SIZE (32 * 1024)

#define DEFAULT_WEBSOCKET_SERVER_LISTENING_PORT 10350

#define CONTAINER_LOG_CONFIG_JSON_FILE_DRIVER "json-file"
#define CONTAINER_LOG_CONFIG_SYSLOG_DRIVER "syslog"
#define CONTAINER_LOG_CONFIG_KEY_DRIVER "log.console.driver"
#define CONTAINER_LOG_CONFIG_KEY_FILE "log.console.file"
#define CONTAINER_LOG_CONFIG_KEY_ROTATE "log.console.filerotate"
#define CONTAINER_LOG_CONFIG_KEY_SIZE "log.console.filesize"
#define CONTAINER_LOG_CONFIG_KEY_SYSLOG_TAG "log.console.tag"
#define CONTAINER_LOG_CONFIG_KEY_SYSLOG_FACILITY "log.console.facility"

#ifndef DEFAULT_UNIX_SOCKET
#define DEFAULT_UNIX_SOCKET "unix:///var/run/isulad.sock"
#endif
#ifndef DEFAULT_ROOTFS_PATH
#define DEFAULT_ROOTFS_PATH "/dev/ram0"
#endif
#ifndef OCICONFIG_PATH
#define OCICONFIG_PATH "/etc/default/isulad/config.json"
#endif
#ifndef OCI_SYSTEM_CONTAINER_CONFIG_PATH
#define OCI_SYSTEM_CONTAINER_CONFIG_PATH "/etc/default/isulad/systemcontainer_config.json"
#endif
#ifndef SECCOMP_DEFAULT_PATH
#define SECCOMP_DEFAULT_PATH "/etc/isulad/seccomp_default.json"
#endif
#ifndef OCI_VERSION
#define OCI_VERSION "1.0.1"
#endif

#define DEFAULT_TCP_HOST "tcp://localhost:2375"
#define DEFAULT_TLS_HOST "tcp://localhost:2376"

#define AUTH_PLUGIN "authz-broker"

#define ISULAD_ISULA_ADAPTER "isula-adapter"
#define ISULAD_ISULA_ACCEL_ARGS "isulad.accel.args"
#define ISULAD_ISULA_ACCEL_ARGS_SEPERATOR ";"
#define ISULAD_ENABLE_PLUGINS "ISULAD_ENABLE_PLUGINS"
#define ISULAD_ENABLE_PLUGINS_SEPERATOR ","
#define ISULAD_ENABLE_PLUGINS_SEPERATOR_CHAR ','

#define MAX_HOSTS 10

#ifdef __cplusplus
}
#endif

#endif
