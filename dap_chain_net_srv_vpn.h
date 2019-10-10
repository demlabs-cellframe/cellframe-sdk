/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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
#include "dap_chain_net_srv.h"

#define VPN_PACKET_OP_CODE_CONNECTED        0x000000a9
#define VPN_PACKET_OP_CODE_CONNECT          0x000000aa
#define VPN_PACKET_OP_CODE_DISCONNECT       0x000000ab
#define VPN_PACKET_OP_CODE_SEND             0x000000ac
#define VPN_PACKET_OP_CODE_RECV             0x000000ad
#define VPN_PACKET_OP_CODE_PROBLEM          0x000000ae

#define VPN_PROBLEM_CODE_NO_FREE_ADDR       0x00000001
#define VPN_PROBLEM_CODE_TUNNEL_DOWN        0x00000002
#define VPN_PROBLEM_CODE_PACKET_LOST        0x00000003

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
    }__attribute__((packed)) header;
    uint8_t data[]; // Binary data nested by packet
}__attribute__((packed)) ch_vpn_pkt_t;

/**
 * @struct ch_vpn_socket_proxy
 * @brief Internal data storage for single socket proxy functions. Usualy helpfull for\
  *        port forwarding or for protecting single application's connection
 *
 **/
typedef struct ch_vpn_socket_proxy {
    int id;
    int sock;
    struct in_addr client_addr; // Used in raw L3 connections
    pthread_mutex_t mutex;
    dap_stream_ch_t * ch;

    bool signal_to_delete;
    ch_vpn_pkt_t * pkt_out[100];
    size_t pkt_out_size;

    uint64_t bytes_sent;
    uint64_t bytes_recieved;

    time_t time_created;
    time_t time_lastused;

    UT_hash_handle hh;
    UT_hash_handle hh2;
    UT_hash_handle hh_sock;
} ch_vpn_socket_proxy_t;


/**
 * @struct dap_stream_ch_vpn
 * @brief Object that creates for every remote channel client
 *
 *
 **/
typedef struct dap_chain_net_srv_vpn
{
    dap_chain_net_srv_t net_srv;
    //dap_chain_net_srv_uid_t srv_uid; // Unique ID for service.
    pthread_mutex_t mutex;
    ch_vpn_socket_proxy_t * socks;
    int raw_l3_sock;

    dap_ledger_t *ledger;
} dap_chain_net_srv_vpn_t;

#define CH_VPN(a) ((dap_chain_net_srv_vpn_t *) ((a)->internal) )

int dap_chain_net_srv_vpn_init(dap_config_t * g_config);
void dap_chain_net_srv_vpn_deinit();
