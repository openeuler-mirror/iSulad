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
 * Description: provide rb tree definition
 ******************************************************************************/
#ifndef __RB_TREE_H_
#define __RB_TREE_H_

#include <stddef.h>
#include <stdbool.h>

#if defined(__cplusplus) || defined(c_plusplus)
extern "C" {
#endif

typedef int (*key_comparator)(const void *, const void *);
typedef void (*key_value_freer)(void *, void *);

typedef enum { RED = 0, BLACK } rbtree_colour;

typedef struct rb_node {
    void *key;
    void *value;
    rbtree_colour colour;
    struct rb_node *left;
    struct rb_node *right;
    struct rb_node *parent;
} rb_node_t;

typedef struct rb_tree {
    rb_node_t *root;
    key_comparator comparator;
    key_value_freer kvfreer;
    rb_node_t *nil;
} rb_tree_t;

typedef struct rb_iterator {
    rb_tree_t *tree;
    rb_node_t *node;
} rb_iterator_t;

int rbtree_ptr_cmp(const void *first, const void *last);
int rbtree_int_cmp(const void *first, const void *last);
int rbtree_str_cmp(const void *first, const void *last);

rb_tree_t *rbtree_new(key_comparator comparator, key_value_freer kvfreer);
void rbtree_clear(rb_tree_t *tree);
void rbtree_free(rb_tree_t *tree);
bool rbtree_insert(rb_tree_t *tree, void *key, void *value);
bool rbtree_replace(rb_tree_t *tree, void *key, void *value);
bool rbtree_remove(rb_tree_t *tree, void *key);
void rbtree_destroy(rb_tree_t *tree);
rb_node_t *rbtree_find(rb_tree_t *tree, void *key);
void *rbtree_search(rb_tree_t *tree, void *key);
void rbtree_inorder(rb_tree_t *tree);
void print_rbtree(rb_tree_t *tree);
size_t rbtree_size(const rb_tree_t *tree);

rb_iterator_t *rbtree_iterator_new(rb_tree_t *tree);
void rbtree_iterator_free(rb_iterator_t *itor);
bool rbtree_iterator_valid(const rb_iterator_t *itor);
bool rbtree_iterator_next(rb_iterator_t *itor);
bool rbtree_iterator_prev(rb_iterator_t *itor);
bool rbtree_iterator_first(rb_iterator_t *itor);
bool rbtree_iterator_last(rb_iterator_t *itor);
void *rbtree_iterator_key(rb_iterator_t *itor);
void *rbtree_iterator_value(rb_iterator_t *itor);

#if defined(__cplusplus) || defined(c_plusplus)
}
#endif

#endif /* __RB_TREE_H_ */

