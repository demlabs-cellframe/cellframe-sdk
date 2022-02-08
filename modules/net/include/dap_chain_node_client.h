/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

#pragma once

#include <pthread.h>
#include <stdbool.h>

#include "uthash.h"
#include "dap_client.h"
#include "dap_chain_node.h"
#include "dap_stream_ch_pkt.h"

// connection states
typedef enum dap_chain_node_client_state {
    NODE_CLIENT_STATE_ERROR = -1,
    NODE_CLIENT_STATE_DISCONNECTED = 0,
    NODE_CLIENT_STATE_GET_NODE_ADDR = 1,
    NODE_CLIENT_STATE_NODE_ADDR_LEASED = 2,
    NODE_CLIENT_STATE_PING = 3,
    NODE_CLIENT_STATE_PONG = 4,
    NODE_CLIENT_STATE_CONNECTING = 5,
    NODE_CLIENT_STATE_ESTABLISHED = 100,
    NODE_CLIENT_STATE_SYNC_GDB_UPDATES = 101,
    NODE_CLIENT_STATE_SYNC_GDB = 102,
    NODE_CLIENT_STATE_SYNC_GDB_RVRS = 103,
    NODE_CLIENT_STATE_SYNC_CHAINS_UPDATES = 110,
    NODE_CLIENT_STATE_SYNC_CHAINS = 111,
    NODE_CLIENT_STATE_SYNC_CHAINS_RVRS = 112,
    NODE_CLIENT_STATE_SYNCED = 120,
    NODE_CLIENT_STATE_CHECKED = 130,
} dap_chain_node_client_state_t;

typedef enum dap_chain_node_sync_status {
    NODE_SYNC_STATUS_STARTED = 0,
    NODE_SYNC_STATUS_WAITING = 1,
    NODE_SYNC_STATUS_IN_PROGRESS = 2,
    NODE_SYNC_STATUS_FAILED = -1,
    NODE_SYNC_STATUS_MISSING = -2
} dap_chain_node_sync_status_t;

typedef struct dap_chain_node_client dap_chain_node_client_t;

typedef void (*dap_chain_node_client_callback_t)(dap_chain_node_client_t *, void*);
typedef void (*dap_chain_node_client_callback_stage_t)(dap_chain_node_client_t *, dap_client_stage_t, void * );
typedef void (*dap_chain_node_client_callback_error_t)(dap_chain_node_client_t *, int, void *);

typedef struct dap_chain_node_client_callbacks{
    dap_chain_node_client_callback_t connected;
    dap_chain_node_client_callback_t disconnected;
    dap_chain_node_client_callback_t delete;
    dap_chain_node_client_callback_stage_t stage;
    dap_chain_node_client_callback_error_t error;

    dap_stream_ch_callback_packet_t chain_pkt_in;
    dap_stream_ch_callback_packet_t chain_pkt_out;
    dap_stream_ch_callback_packet_t net_pkt_in;
    dap_stream_ch_callback_packet_t net_pkt_out;
    dap_stream_ch_callback_packet_t srv_pkt_in;
    dap_stream_ch_callback_packet_t srv_pkt_out;
} dap_chain_node_client_callbacks_t;

// state for a client connection
typedef struct dap_chain_node_client {
    dap_chain_node_client_state_t state;

    dap_events_socket_uuid_t uuid;
    bool resync_gdb;
    bool resync_chains;

    dap_chain_cell_id_t cell_id;

    dap_client_t *client;
    dap_stream_worker_t * stream_worker;

    // Update section
    dap_chain_t * cur_chain; // Current chain to update
    dap_chain_cell_t * cur_cell; // Current cell to update

    // Channel chain
    dap_stream_ch_t * ch_chain;
    dap_stream_ch_uuid_t ch_chain_uuid;
    // Channel chain net
    dap_stream_ch_t * ch_chain_net;
    dap_stream_ch_uuid_t ch_chain_net_uuid;
    // Channel chain net srv
    dap_stream_ch_t * ch_chain_net_srv;
    dap_stream_ch_uuid_t ch_chain_net_srv_uuid;

    dap_chain_node_info_t * info;
    dap_events_t *events;

    dap_chain_net_t * net;
    char last_error[128];

    // Timer
    dap_events_socket_t * timer_update_states;
    dap_events_socket_uuid_t esocket_uuid;


    #ifndef _WIN32
    pthread_cond_t wait_cond;
    #else
    HANDLE wait_cond;
    #endif
    pthread_mutex_t wait_mutex;

    // For hash indexing
    UT_hash_handle hh;
    dap_chain_node_addr_t cur_node_addr;
    dap_chain_node_addr_t remote_node_addr;
    struct in_addr remote_ipv4;
    struct in6_addr remote_ipv6;

    bool keep_connection;
    bool is_connected;
    dap_timerfd_t *sync_timer;
    // callbacks
    dap_chain_node_client_callbacks_t callbacks;
    void * callbacks_arg;
} dap_chain_node_client_t;

#define DAP_CHAIN_NODE_CLIENT(a) (a ? (dap_chain_node_client_t *) (a)->_inheritor : NULL)

int dap_chain_node_client_init(void);

void dap_chain_node_client_deinit(void);


dap_chain_node_client_t* dap_chain_node_client_create_n_connect(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info,
                                                                const char *a_active_channels,dap_chain_node_client_callbacks_t *a_callbacks,
                                                                void * a_callback_arg );


dap_chain_node_client_t* dap_chain_node_client_connect_channels(dap_chain_net_t * a_net, dap_chain_node_info_t *a_node_info,  const char *a_active_channels);
/**
 * Create handshake to server
 *
 * return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_node_client_connect(dap_chain_net_t * a_net, dap_chain_node_info_t *node_info);


/**
 * Reset client state to connected state if it is connected
 */
void dap_chain_node_client_reset(dap_chain_node_client_t *a_client);
/**
 * Close connection to server, delete chain_node_client_t *client
 */
void dap_chain_node_client_close(dap_chain_node_client_t *client);

/**
 * Send stream request to server
 */
int dap_chain_node_client_send_ch_pkt(dap_chain_node_client_t *a_client, uint8_t a_ch_id, uint8_t a_type,
        const void *a_buf, size_t a_buf_size);

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample NODE_CLIENT_STATE_CONNECT or NODE_CLIENT_STATE_SENDED
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int dap_chain_node_client_wait(dap_chain_node_client_t *a_client, int a_waited_state, int a_timeout_ms);

int dap_chain_node_client_set_callbacks(dap_client_t *a_client, uint8_t a_ch_id);

int dap_chain_node_client_send_nodelist_req(dap_chain_node_client_t *a_client);

dap_chain_node_sync_status_t dap_chain_node_client_start_sync(dap_events_socket_uuid_t *l_uuid);

static inline const char * dap_chain_node_client_state_to_str( dap_chain_node_client_state_t a_state)
{
    switch (a_state) {
        case NODE_CLIENT_STATE_ERROR: return "ERROR";
        case NODE_CLIENT_STATE_DISCONNECTED: return "DISCONNECTED";
        case NODE_CLIENT_STATE_GET_NODE_ADDR: return "GET_NODE_ADDR";
        case NODE_CLIENT_STATE_NODE_ADDR_LEASED: return "NODE_ADDR_LEASED";
        case NODE_CLIENT_STATE_PING: return "PING";
        case NODE_CLIENT_STATE_PONG: return "PONG";
        case NODE_CLIENT_STATE_CONNECTING: return "CONNECT";
        case NODE_CLIENT_STATE_ESTABLISHED: return "CONNECTED";
        case NODE_CLIENT_STATE_SYNC_GDB: return "SYNC_GDB";
        case NODE_CLIENT_STATE_SYNC_CHAINS: return "SYNC_CHAINS";
        case NODE_CLIENT_STATE_SYNCED: return "SYNCED";
        case NODE_CLIENT_STATE_CHECKED: return "CHECKED";
        default: return "(Undefined node client state)";
    }

}
