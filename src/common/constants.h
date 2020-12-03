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

#ifndef COMMON_CONSTANTS_H
#define COMMON_CONSTANTS_H

#ifdef __cplusplus
extern "C" {
#endif

/* mode of file and directory */

#define DEFAULT_SECURE_FILE_MODE 0640

#define DEFAULT_SECURE_DIRECTORY_MODE 0750

#define ISULA_CLIENT_DIRECTORY_MODE 0770

#define USER_REMAP_DIRECTORY_MODE 0751

#define ROOTFS_MNT_DIRECTORY_MODE 0640

#define CONFIG_DIRECTORY_MODE 0750

#define CONFIG_FILE_MODE 0640

#define SECURE_CONFIG_FILE_MODE 0600

#define ARCH_LOG_FILE_MODE 0440

#define WORKING_LOG_FILE_MODE 0640

#define LOG_DIRECTORY_MODE 0750

#define TEMP_DIRECTORY_MODE 0700

#define CONSOLE_FIFO_DIRECTORY_MODE 0770

#define SOCKET_GROUP_DIRECTORY_MODE 0660

#define DEBUG_FILE_MODE 0640

#define DEBUG_DIRECTORY_MODE 0750

#define NETWORK_MOUNT_FILE_MODE 0644

#define ETC_FILE_MODE 0755

#define IMAGE_STORE_PATH_MODE 0700

#define ROOTFS_STORE_PATH_MODE 0700

#define DEFAULT_HIGHEST_DIRECTORY_MODE 0755

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

#define CONTAINER_LOG_CONFIG_KEY_PREFIX "log.console."
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

#define OCI_IMAGE_GRAPH_ROOTPATH_NAME "storage"

#define DEFAULT_TCP_HOST "tcp://localhost:2375"
#define DEFAULT_TLS_HOST "tcp://localhost:2376"

#define AUTH_PLUGIN "authz-broker"

#define ISULAD_ENABLE_PLUGINS "ISULAD_ENABLE_PLUGINS"
#define ISULAD_ENABLE_PLUGINS_SEPERATOR ","
#define ISULAD_ENABLE_PLUGINS_SEPERATOR_CHAR ','

#define MAX_HOSTS 10

#define OPT_MAX_LEN 255

#define EVENT_ARGS_MAX 255
#define EVENT_EXTRA_ANNOTATION_MAX 255

/* container id max length */
#define CONTAINER_ID_MAX_LEN 64

#define CONTAINER_EXEC_ID_MAX_LEN 64

typedef enum {
    CONTAINER_STATUS_UNKNOWN = 0,
    CONTAINER_STATUS_CREATED = 1,
    CONTAINER_STATUS_STARTING = 2,
    CONTAINER_STATUS_RUNNING = 3,
    CONTAINER_STATUS_STOPPED = 4,
    CONTAINER_STATUS_PAUSED = 5,
    CONTAINER_STATUS_RESTARTING = 6,
    CONTAINER_STATUS_MAX_STATE = 7
} Container_Status;

typedef enum {
    HEALTH_SERVING_STATUS_UNKNOWN = 0,
    HEALTH_SERVING_STATUS_SERVING = 1,
    HEALTH_SERVING_STATUS_NOT_SERVING = 2,
    HEALTH_SERVING_STATUS_MAX = 3
} Health_Serving_Status;

typedef enum { WAIT_CONDITION_STOPPED = 0, WAIT_CONDITION_REMOVED = 1 } wait_condition_t;

#ifdef __cplusplus
}
#endif

#endif
