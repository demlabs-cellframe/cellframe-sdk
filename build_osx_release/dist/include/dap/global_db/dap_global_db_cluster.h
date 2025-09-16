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

#include "dap_time.h"
#include "dap_stream.h"
#include "dap_stream_cluster.h"
#include "dap_global_db.h"
#include "dap_link_manager.h"

#define DAP_GLOBAL_DB_CLUSTER_GLOBAL    DAP_STREAM_CLUSTER_GLOBAL ".*"      // This groups mask is for globally broadcasting grops
#define DAP_GLOBAL_DB_CLUSTER_LOCAL     DAP_STREAM_CLUSTER_LOCAL  ".*"      // This groups mask is for not broadcasting groups
#define DAP_GLOBAL_DB_UNCLUSTERED_TTL   3600                                // Time-to-life for "global.*" mask, 1 hour by default

typedef enum dap_global_db_role {
    DAP_GDB_MEMBER_ROLE_NOBODY = 0,     // No access
    DAP_GDB_MEMBER_ROLE_GUEST,          // Read-only access
    DAP_GDB_MEMBER_ROLE_USER,           // Read-write access, no delete or rewrite
    DAP_GDB_MEMBER_ROLE_ROOT,           // Full access
    DAP_GDB_MEMBER_ROLE_DEFAULT,        // Use preset default role
    DAP_GDB_MEMBER_ROLE_INVALID = -1    // Virtual role
} dap_global_db_role_t;

DAP_STATIC_INLINE const char *dap_global_db_cluster_role_str(dap_global_db_role_t a_role)
{
    switch (a_role) {
    case DAP_GDB_MEMBER_ROLE_NOBODY:    return "NOBODY";
    case DAP_GDB_MEMBER_ROLE_GUEST:     return "GUEST";
    case DAP_GDB_MEMBER_ROLE_USER:      return "USER";
    case DAP_GDB_MEMBER_ROLE_ROOT:      return "ROOT";
    default:                            return "UNKNOWN";
    }
}

typedef void (*dap_store_obj_callback_notify_t)(dap_store_obj_t *a_obj, void *a_arg);

typedef struct dap_global_db_notifier {
    dap_store_obj_callback_notify_t callback_notify;
    void *callback_arg;             // Cluster changes notify callback and its argument
    struct dap_global_db_notifier *prev, *next;
} dap_global_db_notifier_t;

enum dap_global_db_sync_state {
    DAP_GLOBAL_DB_SYNC_STATE_START,
    DAP_GLOBAL_DB_SYNC_STATE_IDLE
};

typedef struct dap_global_db_sync_context {
    enum dap_global_db_sync_state state;
    dap_time_t stage_last_activity;
    dap_stream_node_addr_t current_link;
} dap_global_db_sync_context_t;

typedef struct dap_global_db_cluster {
    char *groups_mask;                          // GDB cluster coverage area
    dap_cluster_t *links_cluster;               // Cluster container for network links
    dap_cluster_t *role_cluster;                // Cluster container for members with especial roles
    dap_global_db_role_t default_role;          // Role assined for new membersadded with default one
    uint64_t ttl;                               // Time-to-life for objects in the cluster, in seconds
    bool owner_root_access;                     // Deny if false, grant overwise
    dap_global_db_notifier_t *notifiers;        // Cluster notifiers
    dap_global_db_instance_t *dbi;              // Pointer to database instance that contains the cluster
    struct dap_global_db_cluster *prev, *next;  // Pointers to next and previous cluster instances in the global clusters list
    dap_global_db_sync_context_t sync_context;  // Cluster synchronization context for current client
    dap_link_manager_t *link_manager;  // Pointer to link manager
} dap_global_db_cluster_t;

int dap_global_db_cluster_init();
void dap_global_db_cluster_deinit();
dap_global_db_cluster_t *dap_global_db_cluster_by_group(dap_global_db_instance_t *a_dbi, const char *a_group_name);
void dap_global_db_cluster_broadcast(dap_global_db_cluster_t *a_cluster, dap_store_obj_t *a_store_obj);
dap_global_db_cluster_t *dap_global_db_cluster_add(dap_global_db_instance_t *a_dbi, const char *a_mnemonim, dap_guuid_t a_guuid,
                                                   const char *a_group_mask, uint64_t a_ttl, bool a_owner_root_access,
                                                   dap_global_db_role_t a_default_role, dap_cluster_type_t a_links_cluster_role);
DAP_STATIC_INLINE int dap_global_db_cluster_member_delete(dap_global_db_cluster_t *a_cluster, dap_stream_node_addr_t *a_member_addr)
{
    return a_cluster ? dap_cluster_member_delete(a_cluster->role_cluster, a_member_addr) : -2;
}
dap_cluster_member_t *dap_global_db_cluster_member_add(dap_global_db_cluster_t *a_cluster, dap_stream_node_addr_t *a_node_addr, dap_global_db_role_t a_role);
void dap_global_db_cluster_delete(dap_global_db_cluster_t *a_cluster);
void dap_global_db_cluster_notify(dap_global_db_cluster_t *a_cluster, dap_store_obj_t *a_store_obj);
int dap_global_db_cluster_add_notify_callback(dap_global_db_cluster_t *a_cluster, dap_store_obj_callback_notify_t a_callback, void *a_callback_arg);
