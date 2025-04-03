/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
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

#pragma once


#include <string.h>
#include "dap_common.h"
#include "dap_list.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef const char *dap_binary_tree_key_t;
#define KEY_LS(a, b) (strcmp(a, b) < 0)
#define KEY_GT(a, b) (strcmp(a, b) > 0)
#define KEY_EQ(a, b) (strcmp(a, b) == 0)

typedef struct dap_binary_tree {
    dap_binary_tree_key_t key;
    void *data;
    struct dap_binary_tree *left;
    struct dap_binary_tree *right;
} dap_binary_tree_t;

dap_list_t *dap_binary_tree_inorder_list(dap_binary_tree_t *a_tree_root);
void *dap_binary_tree_search(dap_binary_tree_t *a_tree_root, dap_binary_tree_key_t a_key);
void *dap_binary_tree_minimum(dap_binary_tree_t *a_tree_root);
void *dap_binary_tree_maximum(dap_binary_tree_t *a_tree_root);
dap_binary_tree_t *dap_binary_tree_insert(dap_binary_tree_t *a_tree_root, dap_binary_tree_key_t a_key, void *a_data);
dap_binary_tree_t *dap_binary_tree_delete(dap_binary_tree_t *a_tree_root, dap_binary_tree_key_t a_key);
size_t dap_binary_tree_count(dap_binary_tree_t *a_tree_root);
void dap_binary_tree_clear(dap_binary_tree_t *a_tree_root);


#ifdef __cplusplus
}
#endif
