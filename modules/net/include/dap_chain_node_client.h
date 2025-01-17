/*
 * Authors:
 * Dmitriy A. Gearasimov <naeper@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net

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

#include <pthread.h>
#include <stdbool.h>

#include "uthash.h"
#include "dap_client.h"
#include "dap_chain_node.h"
#include "dap_stream_ch_pkt.h"

#ifdef __cplusplus
extern "C" {
#endif

// connection states
typedef enum dap_chain_node_client_state {
    NODE_CLIENT_STATE_ERROR = -1,
    NODE_CLIENT_STATE_DISCONNECTED = 0,
    NODE_CLIENT_STATE_PING = 3,
    NODE_CLIENT_STATE_PONG = 4,
    NODE_CLIENT_STATE_CONNECTING = 5,
    NODE_CLIENT_STATE_ESTABLISHED = 100,
    NODE_CLIENT_STATE_CHECKED = 130,
    NODE_CLIENT_STATE_VALID_READY = 140,
} dap_chain_node_client_state_t;

typedef struct dap_chain_node_client dap_chain_node_client_t;

typedef void (*dap_chain_node_client_callback_t)(dap_chain_node_client_t *, void*);
typedef void (*dap_chain_node_client_callback_stage_t)(dap_chain_node_client_t *, dap_client_stage_t, void * );
typedef void (*dap_chain_node_client_callback_error_t)(dap_chain_node_client_t *, int, void *);

typedef struct dap_chain_node_client_callbacks {
    dap_chain_node_client_callback_t connected;
    dap_chain_node_client_callback_t disconnected;
    dap_chain_node_client_callback_t delete;
    dap_chain_node_client_callback_stage_t stage;
    dap_chain_node_client_callback_error_t error;
} dap_chain_node_client_callbacks_t;

typedef struct dap_chain_node_client_notify_callbacks {
    dap_stream_ch_callback_packet_t net_pkt_in;
    dap_stream_ch_callback_packet_t net_pkt_out;
    dap_stream_ch_callback_packet_t srv_pkt_in;
    dap_stream_ch_callback_packet_t srv_pkt_out;
} dap_chain_node_client_notify_callbacks_t;

// state for a client connection
typedef struct dap_chain_node_client {
    dap_chain_node_client_state_t state;

    dap_chain_cell_id_t cell_id;

    dap_client_t *client;
    dap_stream_worker_t * stream_worker;

    // Update section
    dap_chain_t * cur_chain; // Current chain to update
    dap_chain_cell_t * cur_cell; // Current cell to update

    // Channel chain net
    dap_stream_ch_t * ch_chain_net;
    dap_stream_ch_uuid_t ch_chain_net_uuid;
    // Channel chain net srv
    dap_stream_ch_t * ch_chain_net_srv;
    dap_stream_ch_uuid_t ch_chain_net_srv_uuid;

    dap_chain_node_info_t * info;

    dap_chain_net_t * net;
    char last_error[128];

    dap_events_socket_uuid_t esocket_uuid;

    pthread_cond_t wait_cond;
    pthread_mutex_t wait_mutex;

    dap_chain_node_addr_t remote_node_addr;

    bool is_connected;
    dap_timerfd_t *sync_timer;
    dap_timerfd_t *reconnect_timer;
    // callbacks
    dap_chain_node_client_callbacks_t callbacks;
    dap_chain_node_client_notify_callbacks_t notify_callbacks;
    void *callbacks_arg;
} dap_chain_node_client_t;

#define DAP_CHAIN_NODE_CLIENT(a) (a ? (dap_chain_node_client_t *) (a)->_inheritor : NULL)

int dap_chain_node_client_init();

void dap_chain_node_client_deinit(void);

dap_chain_node_client_t *dap_chain_node_client_create(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info,
                                                      const dap_chain_node_client_callbacks_t *a_callbacks, void *a_callback_arg);

bool dap_chain_node_client_connect(dap_chain_node_client_t *a_node_client, const char *a_active_channels);

/**
 * Create handshake to server
 *
 * return a connection handle, or NULL, if an error
 */
dap_chain_node_client_t* dap_chain_node_client_create_n_connect(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info,
                                                                const char *a_active_channels, const dap_chain_node_client_callbacks_t *a_callbacks,
                                                                void *a_callback_arg);

DAP_STATIC_INLINE dap_chain_node_client_t *dap_chain_node_client_connect_channels(dap_chain_net_t *a_net,
                                                                                  dap_chain_node_info_t *a_node_info,
                                                                                  const char *a_active_channels)
{ return dap_chain_node_client_create_n_connect(a_net, a_node_info, a_active_channels, NULL, NULL); }

DAP_STATIC_INLINE dap_chain_node_client_t* dap_chain_node_client_connect_default_channels(dap_chain_net_t *a_net, dap_chain_node_info_t *a_node_info)
{ return dap_chain_node_client_connect_channels(a_net,a_node_info, "CN"); }


DAP_STATIC_INLINE ssize_t dap_chain_node_client_write_unsafe(dap_chain_node_client_t *a_client, const char a_ch_id, uint8_t a_type, void *a_data, size_t a_data_size)
{ if (!a_client) return 0; return dap_client_write_unsafe(a_client->client, a_ch_id, a_type, a_data, a_data_size); }

DAP_STATIC_INLINE int dap_chain_node_client_write_mt(dap_chain_node_client_t *a_client, const char a_ch_id, uint8_t a_type, void *a_data, size_t a_data_size)
{ if (!a_client) return -1; return dap_client_write_mt(a_client->client, a_ch_id, a_type, a_data, a_data_size); }

DAP_STATIC_INLINE void dap_chain_node_client_queue_clear(dap_chain_node_client_t *a_client)
{ if (!a_client) return; dap_client_queue_clear(a_client->client); };

/**
 * Close connection to server, delete chain_node_client_t with specified UUID
 */
void dap_chain_node_client_close_unsafe(dap_chain_node_client_t *a_node_client);
void dap_chain_node_client_close_mt(dap_chain_node_client_t *a_node_client);

/**
 * wait for the complete of request
 *
 * timeout_ms timeout in milliseconds
 * waited_state state which we will wait, sample NODE_CLIENT_STATE_CONNECT or NODE_CLIENT_STATE_SENDED
 * return -1 false, 0 timeout, 1 end of connection or sending data
 */
int dap_chain_node_client_wait(dap_chain_node_client_t *a_client, int a_waited_state, int a_timeout_ms);

static inline const char * dap_chain_node_client_state_to_str( dap_chain_node_client_state_t a_state)
{
    switch (a_state) {
        case NODE_CLIENT_STATE_ERROR: return "ERROR";
        case NODE_CLIENT_STATE_DISCONNECTED: return "DISCONNECTED";
        case NODE_CLIENT_STATE_PING: return "PING";
        case NODE_CLIENT_STATE_PONG: return "PONG";
        case NODE_CLIENT_STATE_CONNECTING: return "CONNECT";
        case NODE_CLIENT_STATE_ESTABLISHED: return "CONNECTED";
        case NODE_CLIENT_STATE_CHECKED: return "CHECKED";
        default: return "(Undefined node client state)";
    }

}

#ifdef __cplusplus
}
#endif