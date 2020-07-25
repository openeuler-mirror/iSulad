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
 * Author: tanyifeng
 * Create: 2018-11-08
 * Description: provide container mainloop definition
 ******************************************************************************/
#ifndef UTILS_CUTILS_MAINLOOP_H
#define UTILS_CUTILS_MAINLOOP_H

#include <stdint.h>
#include "linked_list.h"

struct epoll_descr {
    int fd;
    struct linked_list handler_list;
};

typedef int (*epoll_loop_callback_t)(int fd, uint32_t event,
                                     void *data,
                                     struct epoll_descr *descr);

extern int epoll_loop(struct epoll_descr *descr, int t);

extern int epoll_loop_add_handler(struct epoll_descr *descr, int fd,
                                  epoll_loop_callback_t callback,
                                  void *data);

extern int epoll_loop_del_handler(struct epoll_descr *descr, int fd);

extern int epoll_loop_open(struct epoll_descr *descr);

extern int epoll_loop_close(struct epoll_descr *descr);

#endif

