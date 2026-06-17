/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Minimal header for VPN client compatibility after service extraction
 */
#pragma once

#include "dap_config.h"
#include "dap_chain_net_srv.h"
#include "dap_events.h"

#define DAP_CHAIN_NET_SRV_VPN_CDB_GDB_PREFIX "srv.vpn"

#define DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA      0x02
#define DAP_STREAM_CH_NET_SRV_ID_VPN        'S'

#define DAP_CHAIN_NET_SRV_VPN_ID 0x0000000000000002

#define VPN_PACKET_OP_CODE_VPN_SEND         0x000000bc
#define VPN_PACKET_OP_CODE_VPN_RECV         0x000000bd

#define TUN_MTU 0xFFFF

typedef struct dap_stream_ch_vpn_pkt {
    struct {
        int sock_id;
        uint32_t op_code;
        uint32_t usage_id;
        union {
            struct {
                uint32_t addr_size;
                uint16_t port DAP_ALIGNED(4);
            } DAP_PACKED op_connect;
            struct {
                uint32_t data_size DAP_ALIGNED(8);
            } DAP_PACKED op_data;
            struct {
                uint32_t code DAP_ALIGNED(8);
            } DAP_PACKED op_problem;
            struct {
                uint64_t op_data_raw DAP_ALIGNED(8);
            } DAP_PACKED raw;
        };
    } DAP_ALIGN_PACKED header;
    byte_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_vpn_pkt_t;

typedef struct dap_chain_net_srv_vpn_tun_socket dap_chain_net_srv_vpn_tun_socket_t;
typedef struct dap_chain_net_srv_ch_vpn dap_chain_net_srv_ch_vpn_t;
typedef struct dap_chain_net_srv_ch_vpn_info dap_chain_net_srv_ch_vpn_info_t;

typedef struct dap_chain_net_srv_vpn_tun_socket {
    uint8_t worker_id;
    dap_worker_t * worker;
    dap_events_socket_t * es;
    dap_chain_net_srv_ch_vpn_info_t * clients;
    dap_events_socket_t ** queue_tun_msg_input;
    size_t buf_size_aux;
} dap_chain_net_srv_vpn_tun_socket_t;

typedef struct dap_chain_net_srv_ch_vpn_info
{
    struct in_addr addr_ipv4;
    bool is_on_this_worker;
    bool is_reassigned_once;
    uint32_t usage_id;
    dap_chain_net_srv_ch_vpn_t * ch_vpn;
    uint64_t ch_vpn_uuid;
    dap_events_socket_t * queue_msg;
    dap_worker_t * worker;
    dap_events_socket_t * esocket;
    dap_events_socket_uuid_t esocket_uuid;
    UT_hash_handle hh;
} dap_chain_net_srv_ch_vpn_info_t;

typedef struct dap_chain_net_srv_ch_vpn
{
    uint32_t usage_id;
    dap_chain_net_srv_t* net_srv;
    bool is_allowed;
    dap_chain_net_srv_vpn_tun_socket_t * tun_socket;
    struct in_addr addr_ipv4;
    dap_stream_ch_t * ch;
    UT_hash_handle hh;
} dap_chain_net_srv_ch_vpn_t;

#define CH_VPN(a) ((dap_chain_net_srv_ch_vpn_t *) ((a)->internal) )
