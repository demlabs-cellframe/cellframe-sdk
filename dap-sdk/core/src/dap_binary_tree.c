/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source commdatay https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dap_binary_tree.h"



static void s_list_construct(dap_list_t *a_list, dap_binary_tree_t *a_elm)
{
    if (a_elm != NULL) {
        s_list_construct(a_list, a_elm->left);
        dap_list_append(a_list, a_elm->data);
        s_list_construct(a_list, a_elm->right);
    }
}

dap_list_t *dap_binary_tree_inorder_list(dap_binary_tree_t *a_tree_root) {
    if (!a_tree_root) {
        return NULL;
    }
    dap_list_t *l_tmp = dap_list_alloc();
    s_list_construct(l_tmp, a_tree_root);
    dap_list_t *l_list = l_tmp->next;
    l_list->prev = NULL;
    dap_list_free1(l_tmp);
    return l_list;
}

static dap_binary_tree_t *s_tree_search(dap_binary_tree_t *a_elm, dap_binary_tree_key_t a_key)
{
    if (a_elm == NULL || KEY_EQ(a_key, a_elm->key))
        return a_elm;
    if (KEY_LS(a_key, a_elm->key)) {
        return s_tree_search(a_elm->left, a_key);
    } else {
        return s_tree_search(a_elm->right, a_key);
    }
}

void *dap_binary_tree_search(dap_binary_tree_t *a_tree_root, dap_binary_tree_key_t a_key)
{
    dap_binary_tree_t *l_res = s_tree_search(a_tree_root, a_key);
    if (l_res) {
        return l_res->data;
    }
    return NULL;
}

static dap_binary_tree_t *s_tree_minimum(dap_binary_tree_t *a_elm)
{
  if (a_elm->left == NULL)
     return a_elm;
  return s_tree_minimum(a_elm->left);
}

void *dap_binary_tree_minimum(dap_binary_tree_t *a_tree_root)
{
    dap_binary_tree_t *l_res = s_tree_minimum(a_tree_root);
    if (l_res) {
        return l_res->data;
    }
    return NULL;
}

static dap_binary_tree_t *s_tree_maximum(dap_binary_tree_t *a_elm)
{
  if (a_elm->right == NULL)
     return a_elm;
  return s_tree_maximum(a_elm->right);
}

void *dap_binary_tree_maximum(dap_binary_tree_t *a_tree_root)
{
    dap_binary_tree_t *l_res = s_tree_maximum(a_tree_root);
    if (l_res) {
        return l_res->data;
    }
    return NULL;
}

static dap_binary_tree_t *s_tree_insert(dap_binary_tree_t *a_elm, dap_binary_tree_key_t a_key, void *a_data)
{
    if (a_elm == NULL) {
        dap_binary_tree_t* l_elm = DAP_NEW_Z(dap_binary_tree_t);
        l_elm->left = l_elm->right = NULL;
        l_elm->key = a_key;
        l_elm->data = a_data;
        return l_elm;
    }
    if (KEY_LS(a_key, a_elm->key)) {
        a_elm->left = s_tree_insert(a_elm->left, a_key, a_data);
    } else if (KEY_GT(a_key, a_elm->key)) {
        a_elm->right = s_tree_insert(a_elm->right, a_key, a_data);
    } else { //if KEY_EQ(a_key, a_elm->key)
        a_elm->data = a_data;
    }
    return a_elm;
}

dap_binary_tree_t *dap_binary_tree_insert(dap_binary_tree_t *a_tree_root, dap_binary_tree_key_t a_key, void *a_data)
{
    return s_tree_insert(a_tree_root, a_key, a_data);
}

static dap_binary_tree_t *s_tree_delete(dap_binary_tree_t *a_elm, dap_binary_tree_key_t a_key)
{
    if (a_elm == NULL) {
        return a_elm;
    }
    if (KEY_LS(a_key, a_elm->key)) {
        a_elm->left = s_tree_delete(a_elm->left, a_key);
    } else if (KEY_GT(a_key, a_elm->key)) {
        a_elm->right = s_tree_delete(a_elm->right, a_key);
    } else if (a_elm->left && a_elm->right) {
        dap_binary_tree_t *l_tmp = s_tree_minimum(a_elm->right);
        a_elm->key = l_tmp->key;
        a_elm->data = l_tmp->data;
        a_elm->right = s_tree_delete(a_elm->right, a_elm->key);
    } else if (a_elm->left) {
        dap_binary_tree_t * l_elm_old_left = a_elm->left;
        DAP_DELETE(a_elm->data);
        DAP_DELETE(a_elm);
        a_elm = l_elm_old_left;
    } else if (a_elm->right) {
        dap_binary_tree_t * l_elm_old_right = a_elm->right;
        DAP_DELETE(a_elm->data);
        DAP_DELETE(a_elm);
        a_elm = l_elm_old_right;
    } else {
        DAP_DELETE(a_elm->data);
        DAP_DELETE(a_elm);
        a_elm = NULL;
    }
    return a_elm;
}

/**
 * @brief dap_binary_tree_delete - remove element with key from a tree
 * @param a_tree_root - root of a tree
 * @param a_key - a key value
 * @return !!a new tree root
 */
dap_binary_tree_t *dap_binary_tree_delete(dap_binary_tree_t *a_tree_root, dap_binary_tree_key_t a_key)
{
    return s_tree_delete(a_tree_root, a_key);
}


void s_tree_count(dap_binary_tree_t *a_elm, size_t *a_count)
{
    if (a_elm != NULL) {
        s_tree_count(a_elm->left, a_count);
        (*a_count)++;
        s_tree_count(a_elm->right, a_count);
    }
}

size_t dap_binary_tree_count(dap_binary_tree_t *a_tree_root)
{
    size_t l_ret = 0;
    s_tree_count(a_tree_root, &l_ret);
    return l_ret;
}

dap_binary_tree_t *s_tree_clear(dap_binary_tree_t *a_elm)
{
    if (!a_elm) {
        return NULL;
    }
    if (a_elm->left) {
        a_elm->left = s_tree_clear(a_elm->left);
    }
    if (a_elm->right) {
        a_elm->right = s_tree_clear(a_elm->right);
    }
    DAP_DELETE(a_elm->data);
    DAP_DELETE(a_elm);
    return NULL;
}

void dap_binary_tree_clear(dap_binary_tree_t *a_tree_root)
{
    s_tree_clear(a_tree_root);
}
