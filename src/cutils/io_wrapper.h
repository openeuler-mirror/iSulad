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
 * Create: 2020-06-28
 * Description: provide console definition
 ******************************************************************************/
#ifndef _IO_WRAPPER_H
#define _IO_WRAPPER_H

#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef ssize_t (*io_write_func_t)(void *context, const void *data, size_t len);
typedef int (*io_close_func_t)(void *context, char **err);

struct io_write_wrapper {
    void *context;
    io_write_func_t write_func;
    io_close_func_t close_func;
};

typedef ssize_t (*io_read_func_t)(void *context, void *buf, size_t len);

struct io_read_wrapper {
    void *context;
    io_read_func_t read;
    io_close_func_t close;
};

#ifdef __cplusplus
}
#endif

#endif
