/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
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
#pragma once

#include "dap_config.h"
#include "dap_chain_net_srv.h"
#include "dap_events.h"

#define DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX "srv.vpn"

#define DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_CLIENT    0x01
#define DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA      0x02

#define DAP_STREAM_CH_ID_NET_SRV_VPN        'S'

#define DAP_CHAIN_NET_SRV_VPN_ID            0x0000000000000001

#define VPN_PACKET_OP_CODE_CONNECTED        0x000000a9
#define VPN_PACKET_OP_CODE_CONNECT          0x000000aa
#define VPN_PACKET_OP_CODE_DISCONNECT       0x000000ab
#define VPN_PACKET_OP_CODE_SEND             0x000000ac
#define VPN_PACKET_OP_CODE_RECV             0x000000ad
#define VPN_PACKET_OP_CODE_PROBLEM          0x000000ae

#define VPN_PROBLEM_CODE_NO_FREE_ADDR                0x00000001
#define VPN_PROBLEM_CODE_TUNNEL_DOWN                 0x00000002
#define VPN_PROBLEM_CODE_PACKET_LOST                 0x00000003
#define VPN_PROBLEM_CODE_ALREADY_ASSIGNED_ADDR       0x00000004

#define VPN_PACKET_OP_CODE_VPN_METADATA     0x000000b0
#define VPN_PACKET_OP_CODE_VPN_RESERVED     0x000000b1
#define VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST 0x000000b2
#define VPN_PACKET_OP_CODE_VPN_ADDR_REPLY   0x000000b3

#define VPN_PACKET_OP_CODE_VPN_SEND         0x000000bc
#define VPN_PACKET_OP_CODE_VPN_RECV         0x000000bd

#define VPN_PACKET_OP_CODE_PING             0xc0
#define VPN_PACKET_OP_CODE_PONG             0xc1

typedef struct ch_vpn_pkt {
    struct {
        int sock_id; // Client's socket id
        uint32_t op_code; // Operation code
        uint32_t usage_id; // Usage id (for multinetworking)
        union {
            struct { // L4 connect operation
                uint32_t addr_size;
                uint16_t port;
                uint16_t padding;
            } op_connect;
            struct { // For data transmission, usualy for I/O functions
                uint32_t data_size;
                uint32_t padding;
            } op_data;
            struct { // We have a problem and we know that!
                uint32_t code; // I hope we'll have no more than 4B+ problems, not I??
                uint32_t padding_padding_padding_damned_padding_nobody_nowhere_uses_this_fild_but_if_wil_change_me_pls_with_an_auto_rename;
            } op_problem;
            struct {
                uint32_t padding1;
                uint32_t padding2;
            } raw; // Raw access to OP bytes
        };
    } DAP_ALIGN_PACKED header;
    byte_t data[]; // Binary data nested by packet
}DAP_ALIGN_PACKED ch_vpn_pkt_t;

typedef struct dap_chain_net_srv_vpn_tun_socket dap_chain_net_srv_vpn_tun_socket_t;
typedef struct dap_chain_net_srv_ch_vpn dap_chain_net_srv_ch_vpn_t;


// Copy is present on each tun socket
typedef struct usage_client {
    dap_chain_net_srv_ch_vpn_t * ch_vpn;
    dap_chain_datum_tx_receipt_t * receipt;
    size_t receipt_size;
    uint32_t usage_id;
    dap_chain_net_srv_t * srv;
    dap_chain_net_srv_vpn_tun_socket_t * tun_socket;
    UT_hash_handle hh;
} usage_client_t;

typedef struct dap_chain_net_srv_ch_vpn_info dap_chain_net_srv_ch_vpn_info_t;

typedef struct dap_chain_net_srv_vpn_tun_socket {
    uint8_t worker_id;
    dap_worker_t * worker;
    dap_events_socket_t * es;
    dap_chain_net_srv_ch_vpn_info_t * clients; // Remote clients identified by destination address
    dap_events_socket_t ** queue_tun_msg_input;
    dap_list_t *fifo;
    //UT_hash_handle hh;
}dap_chain_net_srv_vpn_tun_socket_t;

#define CH_SF_TUN_SOCKET(a) ((dap_chain_net_srv_vpn_tun_socket_t*) a->_inheritor )


/**
 * @struct dap_stream_ch_vpn
 * @brief Object that creates for every remote channel client
 *
 *
 **/
typedef struct dap_chain_net_srv_ch_vpn
{
    uint32_t usage_id;
    dap_chain_net_srv_t* net_srv;
    //dap_chain_net_srv_uid_t srv_uid; // Unique ID for service.
    bool is_allowed;
    dap_chain_net_srv_vpn_tun_socket_t * tun_socket;

    struct in_addr addr_ipv4;
    dap_stream_ch_t * ch;
    UT_hash_handle hh;
} dap_chain_net_srv_ch_vpn_t;

typedef struct dap_chain_net_srv_ch_vpn_info
{
    struct in_addr addr_ipv4;
    bool is_on_this_worker;
    bool is_reassigned_once;//Copy of esocket was_reassigned field. Used
                            // to prevent jumping on systems without FlowControl
    uint32_t usage_id;
    dap_chain_net_srv_ch_vpn_t * ch_vpn;
    uint64_t ch_vpn_uuid;
    dap_events_socket_t * queue_msg; // Message queue
    dap_worker_t * worker;
    dap_events_socket_t * esocket;
    dap_events_socket_uuid_t esocket_uuid;
    UT_hash_handle hh;
}dap_chain_net_srv_ch_vpn_info_t;

typedef struct dap_chain_net_srv_vpn_item_ipv4{
    struct in_addr addr;
    struct dap_chain_net_srv_vpn_item_ipv4 * next;
} dap_chain_net_srv_vpn_item_ipv4_t;

typedef struct dap_chain_net_srv_vpn
{
    dap_chain_net_srv_vpn_item_ipv4_t * ipv4_unleased;
    dap_chain_net_srv_ch_vpn_t * ch_vpn_ipv4;
    dap_chain_net_srv_t * parent;
} dap_chain_net_srv_vpn_t;

#define CH_VPN(a) ((dap_chain_net_srv_ch_vpn_t *) ((a)->internal) )

int dap_chain_net_srv_client_vpn_init(dap_config_t * g_config);

int dap_chain_net_srv_vpn_init(dap_config_t * g_config);
void dap_chain_net_srv_vpn_deinit(void);


