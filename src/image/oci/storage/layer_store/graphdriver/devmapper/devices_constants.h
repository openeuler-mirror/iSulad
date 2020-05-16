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
* Author: gaohuatao
* Create: 2020-01-19
* Description: wrap libdevmapper function to manuplite devicemapper
******************************************************************************/

#ifndef __DEVICES_CONSTANTS_
#define __DEVICES_CONSTANTS_

#define DEVICE_FILE_DIR "/var/lib/isulad/storage/devicemapper/metadata"
#define DEVICE_SET_METAFILE "deviceset-metadata"
#define TRANSACTION_METADATA "transaction-metadata"
#define DEVICE_DIRECTORY "/dev"
#define DEVMAPPER_DECICE_DIRECTORY "/dev/mapper/"
#define DEFAULT_THIN_BLOCK_SIZE 128
#define DEFAULT_METADATA_LOOPBACK_SIZE (2 * 1024 * 1024 * 1024)
// #define DEFAULT_BASE_FS_SIZE (10 * 1024 * 1024 * 1024)
#define DEFAULT_UDEV_SYNC_OVERRIDE false
#define MAX_DEVICE_ID (0xffffff) // 24 bit, pool limit

#define DEFAULT_UDEV_WAITTIMEOUT 185
#define DEFAULT_MIN_FREE_SPACE_PERCENT 10

#define DEFAULT_DEVICE_SET_MODE 0700





#endif