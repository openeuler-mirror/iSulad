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
 * Description: provide rb tree functions
 ******************************************************************************/
#include "rb_tree.h"

#include <stdlib.h>

#include "isula_libutils/log.h"
#include "utils.h"

int rbtree_ptr_cmp(const void *first, const void *last)
{
    return ((int)(first > last) - (int)(first < last));
}

int rbtree_int_cmp(const void *first, const void *last)
{
    const int key1 = *(const int *)first;
    const int key2 = *(const int *)last;
    return ((int)(key1 > key2) - (int)(key1 < key2));
}

int rbtree_str_cmp(const void *first, const void *last)
{
    const char *key1 = first;
    const char *key2 = last;
    while (true) {
        char a = *key1++;
        char b = *key2++;
        if (!a || a != b) {
            return ((int)(a > b) - (int)(a < b));
        }
    }
}

static struct rb_node *rbtree_create_node(void *key, void *value, rb_node_t *left, rb_node_t *right, rb_node_t *parent)
{
    rb_node_t *node = NULL;
    node = util_common_calloc_s(sizeof(rb_node_t));
    if (node == NULL) {
        ERROR("failed to malloc rb tree node!");
        return NULL;
    }
    node->colour = BLACK;  // default colour
    node->key = key;
    node->value = value;
    node->left = left;
    node->right = right;
    node->parent = parent;
    return node;
}

static rb_node_t *rbtree_recursive_search(rb_tree_t *tree, rb_node_t *node, void *key)
{
    if (node == tree->nil || !(tree->comparator(key, node->key))) {
        return node;
    }
    if (tree->comparator(key, node->key) < 0) {
        return rbtree_recursive_search(tree, node->left, key);
    }
    return rbtree_recursive_search(tree, node->right, key);
}

rb_node_t *rbtree_find(rb_tree_t *tree, void *key)
{
    if (tree == NULL || key == NULL) {
        return NULL;
    }
    return rbtree_recursive_search(tree, tree->root, key);
}

void *rbtree_search(rb_tree_t *tree, void *key)
{
    if (tree == NULL || key == NULL) {
        return NULL;
    }
    rb_node_t *find = rbtree_find(tree, key);
    if (find == tree->nil) {
        return NULL;
    }
    return find->value;
}

rb_tree_t *rbtree_new(key_comparator comparator, key_value_freer kvfreer)
{
    rb_tree_t *tree = util_common_calloc_s(sizeof(rb_tree_t));
    if (tree == NULL) {
        ERROR("failed to malloc rb tree");
        return NULL;
    }
    tree->nil = rbtree_create_node(NULL, NULL, NULL, NULL, NULL);
    tree->root = tree->nil;
    tree->comparator = comparator;
    tree->kvfreer = kvfreer;
    return tree;
}

static void rbtree_destory_all(rb_tree_t *tree, rb_node_t *node)
{
    if (node == tree->nil) {
        return;
    }
    if (node->left != tree->nil) {
        rbtree_destory_all(tree, node->left);
    }
    if (node->right != tree->nil) {
        rbtree_destory_all(tree, node->right);
    }
    if (tree->kvfreer != NULL) {
        tree->kvfreer(node->key, node->value);
    }
    free(node);
}

void rbtree_clear(rb_tree_t *tree)
{
    if (tree == NULL) {
        return;
    }
    rbtree_destory_all(tree, tree->root);
}

void rbtree_free(rb_tree_t *tree)
{
    rbtree_clear(tree);
    free(tree->nil);
    tree->nil = NULL;
    free(tree);
}

/*
 * -----------------------------------------------------------
 *       |                       |
 *       y     left rot       x
 *      / \    <===========     / \
 *     x   γ                   α   y
 *    / \      ===========>       / \
 *   α   β     right rot      β   γ
 * ------------------------------------------------------------
 */
static void left_rot(rb_tree_t *tree, rb_node_t *node)
{
    rb_node_t *y = node->right;
    // turn y's left subtree into node's right subtree
    node->right = y->left;
    if (y->left != tree->nil) {
        y->left->parent = node;
    }
    // link node's parent to y
    y->parent = node->parent;
    if (node->parent == tree->nil) {
        tree->root = y;
    } else if (node == node->parent->left) {
        node->parent->left = y;
    } else {
        node->parent->right = y;
    }
    // put node on y's left
    y->left = node;
    node->parent = y;
}

static void right_rot(rb_tree_t *tree, rb_node_t *node)
{
    rb_node_t *y = node->left;
    // turn y's right subtree into node's left subtree
    node->left = y->right;
    if (y->right != tree->nil) {
        y->right->parent = node;
    }
    // link node's parent to y
    y->parent = node->parent;
    if (node->parent == tree->nil) {
        tree->root = y;
    } else if (node == node->parent->right) {
        node->parent->right = y;
    } else {
        node->parent->left = y;
    }
    // put node on y's right
    y->right = node;
    node->parent = y;
}

static void rbtree_insert_fixup(rb_tree_t *tree, rb_node_t *node)
{
    while (node->parent->colour == RED) {
        if (node->parent == node->parent->parent->left) {  // parent node is grandparent node's left child
            rb_node_t *y = NULL;
            y = node->parent->parent->right;
            if (y == NULL) {
                return;
            }

            if (y->colour == RED) {  // uncle node colour is red
                node->parent->colour = BLACK;
                y->colour = BLACK;
                node->parent->parent->colour = RED;
                node = node->parent->parent;
                continue;
            }

            // uncle node colour is black
            if (node == node->parent->right) {  // current node is right child
                node = node->parent;
                left_rot(tree, node);
            }
            // current node is left node
            node->parent->colour = BLACK;
            node->parent->parent->colour = RED;
            right_rot(tree, node->parent->parent);
        } else {  // parent node is grandparent node's right child
            rb_node_t *y = NULL;
            y = node->parent->parent->left;
            if (y == NULL) {
                return;
            }
            if (y->colour == RED) {  // uncle node colour is red
                node->parent->colour = BLACK;
                y->colour = BLACK;
                node->parent->parent->colour = RED;
                node = node->parent->parent;
                continue;
            }

            // uncle node colour is black
            if (node == node->parent->left) {  // current node is left child
                node = node->parent;
                right_rot(tree, node);
            }
            // current node is left node
            node->parent->colour = BLACK;
            node->parent->parent->colour = RED;
            left_rot(tree, node->parent->parent);
        }
    }
    tree->root->colour = BLACK;
}

static void insert_node(rb_tree_t *tree, rb_node_t *node)
{
    rb_node_t *previous = tree->nil;
    rb_node_t *index = tree->root;
    while (index != tree->nil) {
        previous = index;
        if (tree->comparator(node->key, index->key) < 0) {
            index = index->left;
        } else {
            index = index->right;
        }
    }
    node->parent = previous;
    if (previous == tree->nil) {
        tree->root = node;
    } else {
        if (tree->comparator(node->key, previous->key) < 0) {
            previous->left = node;
        } else {
            previous->right = node;
        }
    }
    node->left = tree->nil;
    node->right = tree->nil;
    node->colour = RED;
    rbtree_insert_fixup(tree, node);
}

bool rbtree_insert(rb_tree_t *tree, void *key, void *value)
{
    if (tree == NULL || key == NULL || value == NULL) {
        ERROR("tree, key or value is empty!");
        return false;
    }

    // unique key
    if (rbtree_find(tree, key) != tree->nil) {
        ERROR("the key already existed in rb tree!");
        return false;
    }
    rb_node_t *node = rbtree_create_node(key, value, tree->nil, tree->nil, tree->nil);
    if (node == NULL) {
        ERROR("failed to create rb tree node");
        return false;
    }
    insert_node(tree, node);
    return true;
}

bool rbtree_replace(rb_tree_t *tree, void *key, void *value)
{
    rb_node_t *node = NULL;

    if (tree == NULL || key == NULL || value == NULL) {
        ERROR("tree, key or value is empty!");
        return false;
    }

    // if not find, then insert
    node = rbtree_find(tree, key);
    if (node == tree->nil) {
        return rbtree_insert(tree, key, value);
    }

    if (tree->kvfreer != NULL) {
        tree->kvfreer(key, node->value);
    }
    node->value = value;

    return true;
}

static rb_node_t *rbtree_minimum(rb_tree_t *tree, rb_node_t *node)
{
    if (node == tree->nil) {
        return tree->nil;
    }
    while (node->left != tree->nil) {
        node = node->left;
    }
    return node;
}

static rb_node_t *rbtree_maximum(rb_tree_t *tree, rb_node_t *node)
{
    if (node == tree->nil) {
        return tree->nil;
    }
    while (node->right != tree->nil) {
        node = node->right;
    }
    return node;
}

void do_with_left_node_not_null(rb_tree_t *tree, rb_node_t **node)
{
    rb_node_t *sibling = (*node)->parent->right;
    if (sibling->colour == RED) {
        (*node)->parent->colour = RED;
        sibling->colour = BLACK;
        left_rot(tree, (*node)->parent);
        sibling = (*node)->parent->right;
    }

    bool flag = ((sibling->left == tree->nil || sibling->left->colour == BLACK) &&
                 (sibling->right == tree->nil || sibling->right->colour == BLACK));
    if (flag) {
        sibling->colour = RED;
        (*node) = (*node)->parent;
        return;
    }

    flag = (sibling->right == tree->nil || sibling->right->colour == BLACK);
    if (flag) {
        sibling->colour = RED;
        sibling->left->colour = BLACK;
        right_rot(tree, sibling);
        sibling = (*node)->parent->right;
    }
    sibling->colour = (*node)->parent->colour;
    (*node)->parent->colour = BLACK;
    sibling->right->colour = BLACK;
    left_rot(tree, (*node)->parent);
    (*node) = tree->root;
}

void do_with_left_node_null(rb_tree_t *tree, rb_node_t **node)
{
    rb_node_t *sibling = (*node)->parent->left;
    if (sibling->colour == RED) {
        sibling->colour = BLACK;
        (*node)->parent->colour = RED;
        right_rot(tree, (*node)->parent);
        sibling = (*node)->parent->left;
    }

    bool flag = ((sibling->right == tree->nil || sibling->right->colour == BLACK) &&
                 (sibling->left == tree->nil || sibling->left->colour == BLACK));

    if (flag) {
        sibling->colour = RED;
        (*node) = (*node)->parent;
        return;
    }

    flag = (sibling->left == tree->nil || sibling->left->colour == BLACK);
    if (flag) {
        sibling->colour = RED;
        sibling->right->colour = BLACK;
        left_rot(tree, sibling);
        sibling = (*node)->parent->left;
    }
    sibling->colour = (*node)->parent->colour;
    (*node)->parent->colour = BLACK;
    sibling->left->colour = BLACK;
    right_rot(tree, (*node)->parent);
    (*node) = tree->root;
}

static void rbtree_erase_fixup(rb_tree_t *tree, rb_node_t *node)
{
    while ((node == tree->nil || node->colour == BLACK) && node != tree->root) {
        if (node == node->parent->left) {
            do_with_left_node_not_null(tree, &node);
        } else {
            do_with_left_node_null(tree, &node);
        }
    }
    if (node != NULL) {
        node->colour = BLACK;
    }
}

static void rbtree_transplant(rb_tree_t *tree, rb_node_t *u, rb_node_t *v)
{
    if (u->parent == tree->nil) {
        tree->root = v;
    } else if (u == u->parent->left) {
        u->parent->left = v;
    } else {
        u->parent->right = v;
    }
    v->parent = u->parent;
}

static void rbtree_erase(rb_tree_t *tree, rb_node_t *node)
{
    rb_node_t *x = NULL;
    rb_node_t *y = node;
    rbtree_colour y_original_colour = y->colour;
    if (node->left == tree->nil) {
        x = node->right;
        rbtree_transplant(tree, node, node->right);
    } else if (node->right == tree->nil) {
        x = node->left;
        rbtree_transplant(tree, node, node->left);
    } else {
        y = rbtree_minimum(tree, node->right);
        y_original_colour = y->colour;
        x = y->right;
        if (y->parent == node) {
            x->parent = y;
        } else {
            rbtree_transplant(tree, y, y->right);
            y->right = node->right;
            y->right->parent = y;
        }
        rbtree_transplant(tree, node, y);
        y->left = node->left;
        y->left->parent = y;
        y->colour = node->colour;
    }

    if (y_original_colour == BLACK) {
        rbtree_erase_fixup(tree, x);
    }

    if (tree->kvfreer != NULL) {
        tree->kvfreer(node->key, node->value);
    }
    free(node);
}

bool rbtree_remove(rb_tree_t *tree, void *key)
{
    if (tree == NULL || key == NULL) {
        return false;
    }
    rb_node_t *node = rbtree_find(tree, key);
    if (node == tree->nil) {
        ERROR("no such key in rb tree");
        return false;
    }

    rbtree_erase(tree, node);
    return true;
}

static size_t number_of_nodes(const rb_tree_t *tree, const rb_node_t *node)
{
    size_t count = 0;
    if (node == tree->nil) {
        return 0;
    }
    count = 1 + number_of_nodes(tree, node->left) + number_of_nodes(tree, node->right);
    return count;
}
size_t rbtree_size(const rb_tree_t *tree)
{
    if (tree == NULL) {
        return 0;
    }
    return number_of_nodes(tree, tree->root);
}

rb_iterator_t *rbtree_iterator_new(rb_tree_t *tree)
{
    if (tree == NULL) {
        return NULL;
    }
    rb_iterator_t *itor = NULL;
    itor = util_common_calloc_s(sizeof(rb_iterator_t));
    if (itor == NULL) {
        ERROR("failed to alloc memory");
        return NULL;
    }
    itor->tree = tree;
    (void)rbtree_iterator_first(itor);
    return itor;
}

void rbtree_iterator_free(rb_iterator_t *itor)
{
    if (itor != NULL) {
        free(itor);
    }
}

bool rbtree_iterator_valid(const rb_iterator_t *itor)
{
    if (itor == NULL) {
        return false;
    }
    return itor->node != itor->tree->nil;
}

static rb_node_t *rbtree_successor(rb_tree_t *tree, rb_node_t *node)
{
    if (tree == NULL || node == NULL) {
        return NULL;
    }
    if (node->right != tree->nil) {
        return rbtree_minimum(tree, node->right);
    }
    rb_node_t *successor = node->parent;
    while (successor != tree->nil && node == successor->right) {
        node = successor;
        successor = successor->parent;
    }
    return successor;
}

bool rbtree_iterator_next(rb_iterator_t *itor)
{
    if (itor == NULL) {
        return false;
    }

    return (itor->node != itor->tree->nil) &&
           (itor->node = rbtree_successor(itor->tree, itor->node)) != itor->tree->nil;
}

static rb_node_t *rbtree_predecessor(rb_tree_t *tree, rb_node_t *node)
{
    if (node->left != tree->nil) {
        return rbtree_maximum(tree, node->left);
    }
    rb_node_t *predecessor = node->parent;
    while (predecessor != tree->nil && node == predecessor->left) {
        node = predecessor;
        predecessor = predecessor->parent;
    }
    return predecessor;
}

bool rbtree_iterator_prev(rb_iterator_t *itor)
{
    if (itor == NULL) {
        return false;
    }
    return (itor->node != itor->tree->nil) &&
           (itor->node = rbtree_predecessor(itor->tree, itor->node)) != itor->tree->nil;
}

bool rbtree_iterator_first(rb_iterator_t *itor)
{
    if (itor == NULL) {
        return false;
    }
    return (itor->node = rbtree_minimum(itor->tree, itor->tree->root)) != itor->tree->nil;
}

bool rbtree_iterator_last(rb_iterator_t *itor)
{
    if (itor == NULL) {
        return false;
    }
    return (itor->node = rbtree_maximum(itor->tree, itor->tree->root)) != itor->tree->nil;
}

void *rbtree_iterator_key(rb_iterator_t *itor)
{
    if (itor == NULL) {
        return NULL;
    }
    return itor->node ? itor->node->key : NULL;
}

void *rbtree_iterator_value(rb_iterator_t *itor)
{
    if (itor == NULL) {
        return NULL;
    }
    return itor->node ? itor->node->value : NULL;
}

