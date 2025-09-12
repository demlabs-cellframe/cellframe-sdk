/*
 * Authors:
 * Security Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2025
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_stream_node_addr.h"
#include "dap_time.h"

#ifdef __cplusplus
extern "C" {
#endif

// Access control types
typedef enum {
    DAP_NODE_ACCESS_ALLOW = 0,
    DAP_NODE_ACCESS_DENY = 1,
    DAP_NODE_ACCESS_TEMPORARY_BAN = 2
} dap_node_access_result_t;

// Node access control entry
typedef struct dap_node_access_entry {
    dap_stream_node_addr_t node_addr;
    dap_node_access_result_t access_type;
    dap_time_t created;
    dap_time_t expires;  // 0 for permanent
    char reason[128];
    uint32_t violation_count;
    UT_hash_handle hh;
} dap_node_access_entry_t;

// Access control configuration
typedef struct dap_node_access_config {
    bool whitelist_mode;  // If true, only whitelisted nodes allowed
    bool blacklist_enabled;
    uint32_t max_violations_before_ban;
    dap_time_t temporary_ban_duration;  // seconds
    dap_time_t permanent_ban_threshold; // violations within this time = permanent ban
} dap_node_access_config_t;

// Initialize node access control system
int dap_chain_node_access_control_init(dap_node_access_config_t *a_config);

// Deinitialize node access control system
void dap_chain_node_access_control_deinit(void);

// Check if node is allowed to connect
dap_node_access_result_t dap_chain_node_access_check(dap_stream_node_addr_t *a_node_addr);

// Add node to whitelist
int dap_chain_node_access_whitelist_add(dap_stream_node_addr_t *a_node_addr, const char *a_reason);

// Add node to blacklist
int dap_chain_node_access_blacklist_add(dap_stream_node_addr_t *a_node_addr, const char *a_reason, dap_time_t a_duration);

// Remove node from whitelist
int dap_chain_node_access_whitelist_remove(dap_stream_node_addr_t *a_node_addr);

// Remove node from blacklist
int dap_chain_node_access_blacklist_remove(dap_stream_node_addr_t *a_node_addr);

// Report violation for node (may lead to automatic ban)
void dap_chain_node_access_report_violation(dap_stream_node_addr_t *a_node_addr, const char *a_reason);

// Load access control lists from config files
int dap_chain_node_access_load_config(const char *a_whitelist_file, const char *a_blacklist_file);

// Save access control lists to config files
int dap_chain_node_access_save_config(const char *a_whitelist_file, const char *a_blacklist_file);

// Get access control statistics
typedef struct dap_node_access_stats {
    uint32_t whitelisted_nodes;
    uint32_t blacklisted_nodes;
    uint32_t temporary_banned_nodes;
    uint32_t total_violations_today;
    uint32_t connections_blocked_today;
} dap_node_access_stats_t;

dap_node_access_stats_t dap_chain_node_access_get_stats(void);

// Utility macros
#define DAP_NODE_ACCESS_CHECK_AND_BLOCK(node_addr) \
    do { \
        if (dap_chain_node_access_check(node_addr) != DAP_NODE_ACCESS_ALLOW) { \
            log_it(L_WARNING, "Node " NODE_ADDR_FP_STR " access denied", NODE_ADDR_FP_ARGS_S(*node_addr)); \
            return false; \
        } \
    } while(0)

#define DAP_NODE_ACCESS_REPORT_AND_CHECK(node_addr, reason) \
    do { \
        dap_chain_node_access_report_violation(node_addr, reason); \
        if (dap_chain_node_access_check(node_addr) != DAP_NODE_ACCESS_ALLOW) { \
            return false; \
        } \
    } while(0)

#ifdef __cplusplus
}
#endif
