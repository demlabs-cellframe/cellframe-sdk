/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Pavel Uhanov <pavel.uhanov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2024
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
#include <stdint.h>
#include "dap_list.h"
#include "dap_timerfd.h"
#include "dap_common.h"
#include "dap_client.h"
#include "dap_stream_cluster.h"

#define DAP_NET_ID_INVALID UINT64_C(~0)

typedef struct dap_link_manager dap_link_manager_t;
typedef struct dap_link dap_link_t;

typedef void (*dap_link_manager_callback_t)(dap_link_t *, void*);
typedef void (*dap_link_manager_callback_connected_t)(dap_link_t *, uint64_t);
typedef bool (*dap_link_manager_callback_disconnected_t)(dap_link_t *, uint64_t, int);
typedef void (*dap_link_manager_callback_error_t)(dap_link_t *, uint64_t, int);
typedef int (*dap_link_manager_callback_fill_net_info_t)(dap_link_t *);
typedef int (*dap_link_manager_callback_link_request_t)(uint64_t);
typedef int (*dap_link_manager_callback_link_count_changed_t)();

typedef struct dap_link_manager_callbacks {
    dap_link_manager_callback_connected_t connected;
    dap_link_manager_callback_disconnected_t disconnected;
    dap_link_manager_callback_error_t error;
    dap_link_manager_callback_fill_net_info_t fill_net_info;
    dap_link_manager_callback_link_request_t link_request;
    dap_link_manager_callback_link_count_changed_t link_count_changed;

} dap_link_manager_callbacks_t;

// connection states
typedef enum dap_link_state {
    LINK_STATE_DISCONNECTED = 0,
    LINK_STATE_CONNECTING,
    LINK_STATE_ESTABLISHED
} dap_link_state_t;

typedef struct dap_link {
    dap_stream_node_addr_t addr;
    bool is_uplink;
    dap_list_t *active_clusters;
    struct {
        dap_link_state_t state;
        uint32_t attempts_count;
        dap_client_t *client;
        dap_list_t *associated_nets;
        dap_time_t start_after;
        dap_events_socket_uuid_t es_uuid;
        bool ready;
    } uplink;
    dap_list_t *static_clusters;
    dap_link_manager_t *link_manager;
    bool stream_is_destroyed;
    UT_hash_handle hh;
} dap_link_t;

typedef struct dap_link_manager {
    bool active;                // work status
    uint32_t max_attempts_num;  // max attempts to connect to each link
    uint32_t reconnect_delay;   // pause before next connection attempt
    dap_list_t *nets;           // managed nets list
    dap_link_t *links;          // links HASH_TAB
    pthread_rwlock_t links_lock;
    pthread_rwlock_t nets_lock;
    dap_link_manager_callbacks_t callbacks;  // callbacks
} dap_link_manager_t;

int dap_link_manager_init(const dap_link_manager_callbacks_t *a_callbacks);
void dap_link_manager_deinit();
dap_link_manager_t *dap_link_manager_new(const dap_link_manager_callbacks_t *a_callbacks);
dap_link_manager_t *dap_link_manager_get_default();
int dap_link_manager_add_net(uint64_t a_net_id, dap_cluster_t *a_link_cluster, uint32_t a_min_links_number);
int dap_link_manager_add_net_associate(uint64_t a_net_id, dap_cluster_t *a_link_cluster);
void dap_link_manager_remove_net(uint64_t a_net_id);
void dap_link_manager_add_links_cluster(dap_cluster_member_t *a_member, void *a_arg);
void dap_link_manager_remove_links_cluster(dap_cluster_member_t *a_member, void *a_arg);
void dap_link_manager_add_static_links_cluster(dap_cluster_member_t *a_member, void *a_arg);
void dap_link_manager_remove_static_links_cluster(dap_cluster_member_t *a_member, void *a_arg);
int dap_link_manager_link_create(dap_stream_node_addr_t *a_node_addr, uint64_t a_associated_net_id);
int dap_link_manager_link_update(dap_stream_node_addr_t *a_link, const char *a_host, uint16_t a_port);
bool dap_link_manager_link_find(dap_stream_node_addr_t *a_node_addr, uint64_t a_net_id);
int dap_link_manager_stream_add(dap_stream_node_addr_t *a_node_addr, bool a_uplink);
void dap_link_manager_stream_delete(dap_stream_node_addr_t *a_node_addr);
void dap_link_manager_accounting_link_in_net(uint64_t a_net_id, dap_stream_node_addr_t *a_node_addr, bool a_no_error);
void dap_link_manager_set_net_condition(uint64_t a_net_id, bool a_new_condition);
bool dap_link_manager_get_net_condition(uint64_t a_net_id);
size_t dap_link_manager_links_count(uint64_t a_net_id);
size_t dap_link_manager_required_links_count(uint64_t a_net_id);
size_t dap_link_manager_needed_links_count(uint64_t a_net_id);
void dap_link_manager_set_condition(bool a_new_condition);
bool dap_link_manager_get_condition();
char *dap_link_manager_get_links_info();
dap_stream_node_addr_t *dap_link_manager_get_net_links_addrs(uint64_t a_net_id, size_t *a_uplinks_count, size_t *a_downlinks_count, bool a_established_only);
dap_stream_node_addr_t *dap_link_manager_get_ignored_addrs(size_t *a_ignored_count, uint64_t a_net_id);
void dap_link_manager_stream_replace(dap_stream_node_addr_t *a_addr, bool a_new_is_uplink);
