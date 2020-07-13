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
 * Author: wangfengtu
 * Create: 2020-07-13
 * Description: provide tar function definition
 *********************************************************************************/
#ifndef UTILS_TAR_UTIL_GZIP_H
#define UTILS_TAR_UTIL_GZIP_H

#ifdef __cplusplus
extern "C" {
#endif

// Compress
int util_gzip_z(const char *srcfile, const char *dstfile, const mode_t mode);

// Decompress
int util_gzip_d(const char *srcfile, const char *dstfile, const mode_t mode);

#ifdef __cplusplus
}
#endif

#endif
