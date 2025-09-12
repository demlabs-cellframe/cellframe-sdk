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

#include "dap_chain_node_access_control.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "uthash.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define LOG_TAG "node_access_control"

// Global access control state
static dap_node_access_config_t s_config = {0};
static dap_node_access_entry_t *s_access_entries = NULL;
static pthread_rwlock_t s_access_lock = PTHREAD_RWLOCK_INITIALIZER;
static dap_node_access_stats_t s_stats = {0};
static pthread_mutex_t s_stats_lock = PTHREAD_MUTEX_INITIALIZER;

// Initialize node access control system
int dap_chain_node_access_control_init(dap_node_access_config_t *a_config) {
    if (!a_config) {
        log_it(L_ERROR, "Node access control config is NULL");
        return -1;
    }
    
    s_config = *a_config;
    
    log_it(L_NOTICE, "Node access control initialized (whitelist_mode: %s, blacklist_enabled: %s)",
           s_config.whitelist_mode ? "ON" : "OFF",
           s_config.blacklist_enabled ? "ON" : "OFF");
    return 0;
}

// Deinitialize node access control system
void dap_chain_node_access_control_deinit(void) {
    pthread_rwlock_wrlock(&s_access_lock);
    dap_node_access_entry_t *l_entry, *l_tmp;
    HASH_ITER(hh, s_access_entries, l_entry, l_tmp) {
        HASH_DEL(s_access_entries, l_entry);
        DAP_DELETE(l_entry);
    }
    pthread_rwlock_unlock(&s_access_lock);
    
    log_it(L_NOTICE, "Node access control deinitialized");
}

// Check if node is allowed to connect
dap_node_access_result_t dap_chain_node_access_check(dap_stream_node_addr_t *a_node_addr) {
    if (!a_node_addr) {
        return DAP_NODE_ACCESS_DENY;
    }
    
    dap_time_t l_now = dap_time_now();
    
    pthread_rwlock_rdlock(&s_access_lock);
    
    dap_node_access_entry_t *l_entry = NULL;
    HASH_FIND(hh, s_access_entries, a_node_addr, sizeof(*a_node_addr), l_entry);
    
    if (l_entry) {
        // Check if temporary ban expired
        if (l_entry->access_type == DAP_NODE_ACCESS_TEMPORARY_BAN && 
            l_entry->expires > 0 && l_now > l_entry->expires) {
            // Ban expired, remove entry
            pthread_rwlock_unlock(&s_access_lock);
            pthread_rwlock_wrlock(&s_access_lock);
            HASH_DEL(s_access_entries, l_entry);
            DAP_DELETE(l_entry);
            pthread_rwlock_unlock(&s_access_lock);
            
            // If whitelist mode, deny by default
            return s_config.whitelist_mode ? DAP_NODE_ACCESS_DENY : DAP_NODE_ACCESS_ALLOW;
        }
        
        dap_node_access_result_t l_result = l_entry->access_type;
        pthread_rwlock_unlock(&s_access_lock);
        return l_result;
    }
    
    pthread_rwlock_unlock(&s_access_lock);
    
    // No entry found
    if (s_config.whitelist_mode) {
        // Whitelist mode: deny by default
        return DAP_NODE_ACCESS_DENY;
    } else {
        // Normal mode: allow by default (unless blacklisted)
        return DAP_NODE_ACCESS_ALLOW;
    }
}

// Add node to whitelist
int dap_chain_node_access_whitelist_add(dap_stream_node_addr_t *a_node_addr, const char *a_reason) {
    if (!a_node_addr) {
        return -1;
    }
    
    pthread_rwlock_wrlock(&s_access_lock);
    
    dap_node_access_entry_t *l_entry = NULL;
    HASH_FIND(hh, s_access_entries, a_node_addr, sizeof(*a_node_addr), l_entry);
    
    if (l_entry) {
        // Update existing entry
        l_entry->access_type = DAP_NODE_ACCESS_ALLOW;
        l_entry->expires = 0; // Permanent
        if (a_reason) {
            dap_strncpy(l_entry->reason, a_reason, sizeof(l_entry->reason) - 1);
        }
    } else {
        // Create new entry
        l_entry = DAP_NEW_Z(dap_node_access_entry_t);
        l_entry->node_addr = *a_node_addr;
        l_entry->access_type = DAP_NODE_ACCESS_ALLOW;
        l_entry->created = dap_time_now();
        l_entry->expires = 0; // Permanent
        if (a_reason) {
            dap_strncpy(l_entry->reason, a_reason, sizeof(l_entry->reason) - 1);
        }
        HASH_ADD(hh, s_access_entries, node_addr, sizeof(*a_node_addr), l_entry);
        
        pthread_mutex_lock(&s_stats_lock);
        s_stats.whitelisted_nodes++;
        pthread_mutex_unlock(&s_stats_lock);
    }
    
    pthread_rwlock_unlock(&s_access_lock);
    
    log_it(L_INFO, "Node " NODE_ADDR_FP_STR " added to whitelist: %s",
           NODE_ADDR_FP_ARGS_S(*a_node_addr), a_reason ? a_reason : "no reason");
    return 0;
}

// Add node to blacklist
int dap_chain_node_access_blacklist_add(dap_stream_node_addr_t *a_node_addr, const char *a_reason, dap_time_t a_duration) {
    if (!a_node_addr) {
        return -1;
    }
    
    pthread_rwlock_wrlock(&s_access_lock);
    
    dap_node_access_entry_t *l_entry = NULL;
    HASH_FIND(hh, s_access_entries, a_node_addr, sizeof(*a_node_addr), l_entry);
    
    dap_time_t l_now = dap_time_now();
    
    if (l_entry) {
        // Update existing entry
        l_entry->access_type = a_duration > 0 ? DAP_NODE_ACCESS_TEMPORARY_BAN : DAP_NODE_ACCESS_DENY;
        l_entry->expires = a_duration > 0 ? l_now + a_duration : 0;
        l_entry->violation_count++;
        if (a_reason) {
            dap_strncpy(l_entry->reason, a_reason, sizeof(l_entry->reason) - 1);
        }
    } else {
        // Create new entry
        l_entry = DAP_NEW_Z(dap_node_access_entry_t);
        l_entry->node_addr = *a_node_addr;
        l_entry->access_type = a_duration > 0 ? DAP_NODE_ACCESS_TEMPORARY_BAN : DAP_NODE_ACCESS_DENY;
        l_entry->created = l_now;
        l_entry->expires = a_duration > 0 ? l_now + a_duration : 0;
        l_entry->violation_count = 1;
        if (a_reason) {
            dap_strncpy(l_entry->reason, a_reason, sizeof(l_entry->reason) - 1);
        }
        HASH_ADD(hh, s_access_entries, node_addr, sizeof(*a_node_addr), l_entry);
        
        pthread_mutex_lock(&s_stats_lock);
        if (a_duration > 0) {
            s_stats.temporary_banned_nodes++;
        } else {
            s_stats.blacklisted_nodes++;
        }
        pthread_mutex_unlock(&s_stats_lock);
    }
    
    pthread_rwlock_unlock(&s_access_lock);
    
    log_it(L_WARNING, "Node " NODE_ADDR_FP_STR " added to blacklist (%s ban): %s",
           NODE_ADDR_FP_ARGS_S(*a_node_addr),
           a_duration > 0 ? "temporary" : "permanent",
           a_reason ? a_reason : "no reason");
    return 0;
}

// Report violation for node (may lead to automatic ban)
void dap_chain_node_access_report_violation(dap_stream_node_addr_t *a_node_addr, const char *a_reason) {
    if (!a_node_addr || !s_config.blacklist_enabled) {
        return;
    }
    
    pthread_mutex_lock(&s_stats_lock);
    s_stats.total_violations_today++;
    pthread_mutex_unlock(&s_stats_lock);
    
    pthread_rwlock_wrlock(&s_access_lock);
    
    dap_node_access_entry_t *l_entry = NULL;
    HASH_FIND(hh, s_access_entries, a_node_addr, sizeof(*a_node_addr), l_entry);
    
    dap_time_t l_now = dap_time_now();
    
    if (l_entry) {
        l_entry->violation_count++;
        l_entry->last_seen = l_now;
        if (a_reason) {
            dap_strncpy(l_entry->reason, a_reason, sizeof(l_entry->reason) - 1);
        }
    } else {
        // Create new entry for tracking violations
        l_entry = DAP_NEW_Z(dap_node_access_entry_t);
        l_entry->node_addr = *a_node_addr;
        l_entry->access_type = DAP_NODE_ACCESS_ALLOW; // Still allowed, just tracking
        l_entry->created = l_now;
        l_entry->violation_count = 1;
        l_entry->first_seen = l_now;
        l_entry->last_seen = l_now;
        if (a_reason) {
            dap_strncpy(l_entry->reason, a_reason, sizeof(l_entry->reason) - 1);
        }
        HASH_ADD(hh, s_access_entries, node_addr, sizeof(*a_node_addr), l_entry);
    }
    
    // Check if automatic ban should be applied
    if (l_entry->violation_count >= s_config.max_violations_before_ban) {
        // Check if violations happened within permanent ban threshold
        if (l_now - l_entry->first_seen <= s_config.permanent_ban_threshold) {
            // Permanent ban
            l_entry->access_type = DAP_NODE_ACCESS_DENY;
            l_entry->expires = 0;
            log_it(L_WARNING, "Node " NODE_ADDR_FP_STR " permanently banned after %u violations",
                   NODE_ADDR_FP_ARGS_S(*a_node_addr), l_entry->violation_count);
        } else {
            // Temporary ban
            l_entry->access_type = DAP_NODE_ACCESS_TEMPORARY_BAN;
            l_entry->expires = l_now + s_config.temporary_ban_duration;
            log_it(L_WARNING, "Node " NODE_ADDR_FP_STR " temporarily banned for %lu seconds after %u violations",
                   NODE_ADDR_FP_ARGS_S(*a_node_addr), s_config.temporary_ban_duration, l_entry->violation_count);
        }
    }
    
    pthread_rwlock_unlock(&s_access_lock);
}

// Get access control statistics
dap_node_access_stats_t dap_chain_node_access_get_stats(void) {
    pthread_mutex_lock(&s_stats_lock);
    dap_node_access_stats_t l_stats = s_stats;
    pthread_mutex_unlock(&s_stats_lock);
    return l_stats;
}
