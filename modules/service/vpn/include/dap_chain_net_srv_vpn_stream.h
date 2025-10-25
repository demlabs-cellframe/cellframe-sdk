/**
 * @file dap_chain_net_srv_vpn_stream.h
 * @brief VPN Service Stream Channel Handlers Module
 * @details Stream channel lifecycle (new/delete/packet_in/packet_out) and worker assignment callbacks
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#pragma once

#include "dap_stream_ch.h"
#include "dap_events_socket.h"
#include "dap_worker.h"
#include "dap_chain_net_srv.h"

// Forward declaration for VPN channel structures
struct dap_chain_net_srv_ch_vpn;
struct dap_stream_ch_vpn_pkt;

// Stream channel lifecycle callbacks

/**
 * @brief Worker assignment callback
 * @details Called when stream esocket is assigned to a worker (for FlowControl/CPU reassignment)
 * @param a_es Events socket
 * @param a_worker Worker it's assigned to
 */
void vpn_srv_ch_esocket_assigned(dap_events_socket_t *a_es, dap_worker_t *a_worker);

/**
 * @brief Worker unassignment callback
 * @details Called when stream esocket is unassigned from a worker
 * @param a_es Events socket
 * @param a_worker Worker it was assigned to
 */
void vpn_srv_ch_esocket_unassigned(dap_events_socket_t *a_es, dap_worker_t *a_worker);

/**
 * @brief Channel constructor
 * @details Allocates ch_vpn structure, sets up worker reassignment, initializes session
 * @param a_ch Stream channel
 * @param a_arg User argument (unused)
 */
void vpn_srv_ch_new(dap_stream_ch_t *a_ch, void *a_arg);

/**
 * @brief Channel destructor
 * @details Cleanup IP lease, send unassign messages to workers, cleanup timer, free ch_vpn
 * @param a_ch Stream channel
 * @param a_arg User argument (unused)
 */
void vpn_srv_ch_delete(dap_stream_ch_t *a_ch, void *a_arg);

/**
 * @brief Packet input handler
 * @details Processes all VPN opcodes (PING/PONG/ADDR_REQUEST/ADDR_REPLY/RECV/SEND)
 * @param a_ch Stream channel
 * @param a_arg Packet data (dap_stream_ch_pkt_t*)
 * @return true if packet was processed, false otherwise
 */
bool vpn_srv_ch_packet_in(dap_stream_ch_t *a_ch, void *a_arg);

/**
 * @brief Packet output handler
 * @details Validates usage state before allowing packet output
 * @param a_ch Stream channel
 * @param a_arg User argument (unused)
 * @return true if output is allowed, false otherwise
 */
bool vpn_srv_ch_packet_out(dap_stream_ch_t *a_ch, void *a_arg);

// Helper functions

/**
 * @brief Process VPN address request from client
 * @details Leases new IP address, sends VPN_PACKET_OP_CODE_VPN_ADDR_REPLY
 * @param a_ch Stream channel
 * @param a_usage Service usage structure
 * @return 0 on success, negative on error
 */
int vpn_srv_ch_packet_in_vpn_address_request(dap_stream_ch_t *a_ch, dap_chain_net_srv_usage_t *a_usage);

/**
 * @brief Handle TUN address leased (client-side callback)
 * @details Called when client receives VPN_PACKET_OP_CODE_VPN_ADDR_REPLY
 * @param a_ch_vpn VPN channel structure
 * @param a_vpn_pkt VPN packet with address data
 * @param a_pkt_size Packet size
 * @return 0 on success, negative on error
 */
int vpn_srv_ch_tun_addr_leased(
    struct dap_chain_net_srv_ch_vpn *a_ch_vpn,
    struct dap_stream_ch_vpn_pkt *a_vpn_pkt,
    size_t a_pkt_size);

/**
 * @brief Send PONG packet in response to PING
 * @param a_ch Stream channel
 */
void vpn_srv_send_pong_pkt(dap_stream_ch_t *a_ch);


