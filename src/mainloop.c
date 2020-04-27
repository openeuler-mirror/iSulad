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
 * Description: provide container mainloop functions
 ******************************************************************************/
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <sys/epoll.h>

#include "mainloop.h"
#include "utils.h"

struct epoll_loop_handler {
    epoll_loop_callback_t cb;
    int cbfd;
    void *cbdata;
};

#define MAX_EVENTS 100

/* epoll loop */
int epoll_loop(struct epoll_descr *descr, int t)
{
    int i;
    int ret = 0;
    struct epoll_loop_handler *epoll_handler = NULL;
    struct epoll_event evs[MAX_EVENTS];

    while (1) {
        int ep_fds = epoll_wait(descr->fd, evs, MAX_EVENTS, t);
        if (ep_fds < 0) {
            if (errno == EINTR) {
                continue;
            }
            ret = -1;
            goto out;
        }

        for (i = 0; i < ep_fds; i++) {
            epoll_handler = (struct epoll_loop_handler *)(evs[i].data.ptr);
            if (epoll_handler->cb(epoll_handler->cbfd, evs[i].events, epoll_handler->cbdata, descr) > 0) {
                goto out;
            }
        }

        if (ep_fds == 0 && t != 0) {
            goto out;
        }

        if (linked_list_empty(&descr->handler_list)) {
            goto out;
        }
    }
out:
    return ret;
}

/* epoll loop add handler */
int epoll_loop_add_handler(struct epoll_descr *descr, int fd,
                           epoll_loop_callback_t callback, void *data)
{
    struct epoll_event ev;
    struct epoll_loop_handler *epoll_handler = NULL;
    struct linked_list *node = NULL;

    epoll_handler = util_common_calloc_s(sizeof(*epoll_handler));
    if (epoll_handler == NULL) {
        goto fail_out;
    }

    epoll_handler->cbfd = fd;
    epoll_handler->cb = callback;
    epoll_handler->cbdata = data;

    ev.events = EPOLLIN;
    ev.data.ptr = epoll_handler;

    if (epoll_ctl(descr->fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
        goto fail_out;
    }

    node = util_common_calloc_s(sizeof(struct linked_list));
    if (node == NULL) {
        goto fail_out;
    }

    node->elem = epoll_handler;
    linked_list_add(&descr->handler_list, node);
    return 0;

fail_out:
    free(epoll_handler);

    return -1;
}

/* epoll loop del handler */
int epoll_loop_del_handler(struct epoll_descr *descr, int fd)
{
    struct epoll_loop_handler *epoll_handler = NULL;
    struct linked_list *index = NULL;

    linked_list_for_each(index, &descr->handler_list) {
        epoll_handler = index->elem;

        if (fd == epoll_handler->cbfd) {
            if (epoll_ctl(descr->fd, EPOLL_CTL_DEL, fd, NULL)) {
                goto fail_out;
            }

            linked_list_del(index);
            free(index->elem);
            free(index);
            return 0;
        }
    }

fail_out:
    return -1;
}

/* epoll loop open */
int epoll_loop_open(struct epoll_descr *descr)
{
    descr->fd = epoll_create1(EPOLL_CLOEXEC);
    if (descr->fd < 0) {
        return -1;
    }

    linked_list_init(&(descr->handler_list));
    return 0;
}

/* epoll loop close */
int epoll_loop_close(struct epoll_descr *descr)
{
    struct linked_list *index = NULL;
    struct linked_list *next = NULL;

    linked_list_for_each_safe(index, &(descr->handler_list), next) {
        linked_list_del(index);
        free(index->elem);
        free(index);
    }

    return close(descr->fd);
}

