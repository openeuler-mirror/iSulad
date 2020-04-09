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
 * Description: provide container linked list function definition
 ******************************************************************************/
#ifndef __LINKED_LIST_H
#define __LINKED_LIST_H

#include <stddef.h>

struct linked_list {
    void *elem;
    struct linked_list *next;
    struct linked_list *prev;
};

/* Iterate through an linked list. */
#define linked_list_for_each(__iterator, __list) \
    for ((__iterator) = (__list)->next; \
         (__iterator) != (__list); \
         (__iterator) = (__iterator)->next)

/* Iterate safely through an linked list. */
#define linked_list_for_each_safe(__iterator, __list, __next) \
    for ((__iterator) = (__list)->next, (__next) = (__iterator)->next; \
         (__iterator) != (__list); \
         (__iterator) = (__next), (__next) = (__next)->next)

/* Initialize list. */
static inline void linked_list_init(struct linked_list *list)
{
    list->elem = NULL;
    list->next = list->prev = list;
}

/* Add an element to a list. See linked_list_add() and linked_list_add_tail() for an
 * idiom. */
static inline void linked_list_add_elem(struct linked_list *list, void *elem)
{
    list->elem = elem;
}

/* Retrieve first element of list. */
static inline void *linked_list_first_elem(struct linked_list *list)
{
    return list->next->elem;
}

/* Retrieve last element of list. */
static inline void *linked_list_last_elem(struct linked_list *list)
{
    return list->prev->elem;
}

/* Retrieve first node of list. */
static inline void *linked_list_first_node(struct linked_list *list)
{
    return list->next;
}

/* Determine if list is empty. */
static inline int linked_list_empty(struct linked_list *list)
{
    return list == list->next;
}

/* Workhorse to be called from linked_list_add() and linked_list_add_tail(). */
static inline void __linked_list_add(struct linked_list *newlist,
                                     struct linked_list *prev,
                                     struct linked_list *next)
{
    next->prev = newlist;
    newlist->next = next;
    newlist->prev = prev;
    prev->next = newlist;
}

/* Idiom to add an element to the beginning of an linked list */
static inline void linked_list_add(struct linked_list *head,
                                   struct linked_list *list)
{
    __linked_list_add(list, head, head->next);
}

/* Idiom to add an element to the end of an linked list */
static inline void linked_list_add_tail(struct linked_list *head,
                                        struct linked_list *list)
{
    __linked_list_add(list, head->prev, head);
}

/* Idiom to free an linked list */
static inline void linked_list_del(const struct linked_list *list)
{
    struct linked_list *next, *prev;

    next = list->next;
    prev = list->prev;
    next->prev = prev;
    prev->next = next;
}

/* Return length of the list. */
static inline size_t linked_list_len(struct linked_list *list)
{
    size_t i = 0;
    struct linked_list *iter;
    linked_list_for_each(iter, list) {
        i++;
    }

    return i;
}

#endif

