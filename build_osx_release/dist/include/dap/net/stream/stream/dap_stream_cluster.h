/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2023
* All rights reserved.

This file is part of DAP SDK the open source project

DAP SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

DAP SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include <dap_common.h>
#include <stdint.h>
#include <pthread.h>
#include "uthash.h"
#include "dap_list.h"
#include "dap_guuid.h"
#include "json.h"

#define DAP_STREAM_CLUSTER_GLOBAL   "global"    // This mnemonim is for globally broadcasting grops
#define DAP_STREAM_CLUSTER_LOCAL    "local"     // This mnemonim is for not broadcasting groups

typedef struct dap_cluster dap_cluster_t;

typedef struct dap_cluster_member {
    dap_stream_node_addr_t addr;    // Member addr, HT key
    int role;                       // Member role & access rights (user-defined enum)
    bool persistent;                // Persistent members won't be removed with its links
    void *info;                     // Member info pointer
    dap_cluster_t *cluster;         // Cluster pointer
    UT_hash_handle hh;
} dap_cluster_member_t;

typedef void (*dap_cluster_change_callback_t)(dap_cluster_member_t *a_member, void *a_arg);

// Role in cluster
typedef enum dap_cluster_type {
    DAP_CLUSTER_TYPE_INVALID = 0,
    DAP_CLUSTER_TYPE_EMBEDDED,      // Type network link managment with balancer intregration
    DAP_CLUSTER_TYPE_AUTONOMIC,     // Type of static link management, passive by default, switching to active one for absent links
    DAP_CLUSTER_TYPE_ISOLATED,      // Type of active internal independent link managment
    DAP_CLUSTER_TYPE_SYSTEM,        // Especial link management for local and global clusters
    DAP_CLUSTER_TYPE_VIRTUAL        // No links managment for this type of clusters
} dap_cluster_type_t;

typedef enum dap_cluster_status {
    DAP_CLUSTER_STATUS_DISABLED = 0,
    DAP_CLUSTER_STATUS_ENABLED
} dap_cluster_status_t;

typedef struct dap_cluster {
    char *mnemonim;                 // Field for alternative cluster finding, unique
    dap_guuid_t guuid;              // Unique global cluster id
    dap_cluster_type_t type;        // Link management type
    dap_cluster_status_t status;    // Active or inactive for now
    pthread_rwlock_t members_lock;
    dap_cluster_member_t *members;  // Cluster members (by stream addr) and callbacks
    dap_cluster_change_callback_t members_add_callback;
    dap_cluster_change_callback_t members_delete_callback;
    void *callbacks_arg;
    void *_inheritor;
    UT_hash_handle hh, hh_str;      // Handles for uuid and mnemonim storages
} dap_cluster_t;

// Cluster common funcs
dap_cluster_t *dap_cluster_new(const char *a_mnemonim, dap_guuid_t a_guuid, dap_cluster_type_t a_type);
void dap_cluster_delete(dap_cluster_t *a_cluster);
dap_cluster_t *dap_cluster_find(dap_guuid_t a_uuid);
dap_cluster_t *dap_cluster_by_mnemonim(const char *a_mnemonim);

// Member funcs
dap_cluster_member_t *dap_cluster_member_add(dap_cluster_t *a_cluster, dap_stream_node_addr_t *a_addr, int a_role, void *a_info);
dap_cluster_member_t *dap_cluster_member_find_unsafe(dap_cluster_t *a_cluster, dap_stream_node_addr_t *a_member_addr);
int dap_cluster_member_find_role(dap_cluster_t *a_cluster, dap_stream_node_addr_t *a_member_addr);
size_t dap_cluster_members_count(dap_cluster_t *a_cluster);
DAP_STATIC_INLINE bool dap_cluster_is_empty(dap_cluster_t *a_cluster) { return !dap_cluster_members_count(a_cluster); }
int dap_cluster_member_delete(dap_cluster_t *a_cluster, dap_stream_node_addr_t *a_member_addr);
void dap_cluster_delete_all_members(dap_cluster_t *a_cluster);
void dap_cluster_broadcast(dap_cluster_t *a_cluster, const char a_ch_id, uint8_t a_type, const void *a_data, size_t a_data_size,
                           dap_stream_node_addr_t *a_exclude_aray, size_t a_exclude_array_size);
json_object *dap_cluster_get_links_info_json(dap_cluster_t *a_cluster);
char *dap_cluster_get_links_info(dap_cluster_t *a_cluster);
void dap_cluster_link_delete_from_all(dap_list_t *a_cluster_list, dap_stream_node_addr_t *a_addr);
dap_stream_node_addr_t dap_cluster_get_random_link(dap_cluster_t *a_cluster);
dap_stream_node_addr_t *dap_cluster_get_all_members_addrs(dap_cluster_t *a_cluster, size_t *a_count, int a_role);
void dap_cluster_members_register(dap_cluster_t *a_cluster);
