/**
 * @file dap_chain_net_srv_vpn_stream.c
 * @brief VPN Service Stream Channel Handlers Implementation
 * @details Stream channel lifecycle, packet handlers, worker assignment
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#include "dap_chain_net_srv_vpn_stream.h"
#include "dap_chain_net_srv_vpn_internal.h"
#include "dap_chain_net_vpn_client_tun.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_stream_ch_pkt.h"
#include "dap_stream_ch_chain_net_srv.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_http_client.h"
#include "uthash.h"
#include <arpa/inet.h>
#include <assert.h>

#define LOG_TAG "dap_chain_net_srv_vpn_stream"

// External symbols from internal.h
extern dap_chain_net_srv_ch_vpn_t *s_ch_vpn_addrs;
extern pthread_rwlock_t s_clients_rwlock;
extern vpn_local_network_t *s_raw_server;
extern pthread_rwlock_t s_raw_server_rwlock;
extern bool s_debug_more;

// External TUN messaging functions (from TUN module)
extern void s_tun_send_msg_esocket_reassigned_all_inter(
    uint32_t a_worker_own_id,
    dap_chain_net_srv_ch_vpn_t *a_ch_vpn,
    dap_events_socket_t *a_esocket,
    dap_events_socket_uuid_t a_esocket_uuid,
    struct in_addr a_addr);

extern void s_tun_send_msg_ip_unassigned_all(
    uint32_t a_worker_own_id,
    dap_chain_net_srv_ch_vpn_t *a_ch_vpn,
    struct in_addr a_addr);

extern void s_tun_send_msg_ip_assigned_all(
    uint32_t a_worker_own_id,
    dap_chain_net_srv_ch_vpn_t *a_ch_vpn,
    struct in_addr a_addr);

// External limits update function (from limits module)
extern void s_update_limits(
    dap_stream_ch_t *a_ch,
    dap_chain_net_srv_stream_session_t *a_srv_session,
    dap_chain_net_srv_usage_t *a_usage,
    size_t a_bytes);

// Forward declarations for internal helpers
static void s_ch_packet_in_vpn_address_request(dap_stream_ch_t *a_ch, dap_chain_net_srv_usage_t *a_usage);
static void send_pong_pkt(dap_stream_ch_t *a_ch);

// External client function (from client module or separate impl)
extern int ch_sf_tun_addr_leased(
    dap_chain_net_srv_ch_vpn_t *a_ch_vpn,
    dap_stream_ch_vpn_pkt_t *a_vpn_pkt,
    size_t a_pkt_size);

/**
 * @brief Worker assignment callback
 */
void vpn_srv_ch_esocket_assigned(dap_events_socket_t *a_es, dap_worker_t *a_worker)
{
    dap_http_client_t *l_http_client = DAP_HTTP_CLIENT(a_es);
    assert(l_http_client);
    dap_stream_t *l_stream = DAP_STREAM(l_http_client);
    if (!l_stream)
        return;
    dap_stream_ch_t *l_ch = l_stream->channel[DAP_CHAIN_NET_SRV_VPN_ID];
    if (!l_ch)
        return;
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(l_ch);
    assert(l_ch_vpn);
    s_tun_send_msg_esocket_reassigned_all_inter(
        a_worker->id,
        l_ch_vpn,
        l_ch_vpn->ch->stream->esocket,
        l_ch_vpn->ch->stream->esocket_uuid,
        l_ch_vpn->addr_ipv4);
}

/**
 * @brief Worker unassignment callback
 */
void vpn_srv_ch_esocket_unassigned(dap_events_socket_t *a_es, dap_worker_t *a_worker)
{
    UNUSED(a_worker);
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(((dap_stream_ch_t *)a_es->_inheritor));
    
    s_tun_send_msg_esocket_reassigned_all_inter(
        a_es->worker->id,
        l_ch_vpn,
        l_ch_vpn->ch->stream->esocket,
        l_ch_vpn->ch->stream->esocket_uuid,
        l_ch_vpn->addr_ipv4);
}

/**
 * @brief Channel constructor - allocates ch_vpn structure, sets up worker reassignment
 */
void vpn_srv_ch_new(dap_stream_ch_t *a_ch, void *a_arg)
{
    UNUSED(a_arg);
    
    // Enable worker reassignment for FlowControl
    a_ch->stream->esocket->flags |= DAP_SOCK_REASSIGN_ONCE;
    a_ch->stream->esocket->callbacks.worker_assign_callback = vpn_srv_ch_esocket_assigned;

    a_ch->internal = DAP_NEW_Z(dap_chain_net_srv_ch_vpn_t);
    if (!a_ch->internal) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return;
    }
    
    dap_chain_net_srv_ch_vpn_t *l_srv_vpn = CH_VPN(a_ch);

    // Create stream session if not exists
    if (a_ch->stream->session->_inheritor == NULL && a_ch->stream->session != NULL)
        dap_chain_net_srv_stream_session_create(a_ch->stream->session);
    
    // Get VPN service
    dap_chain_net_srv_uid_t l_uid = {.uint64 = DAP_CHAIN_NET_SRV_VPN_ID};
    l_srv_vpn->net_srv = dap_chain_net_srv_get(l_uid);
    l_srv_vpn->ch = a_ch;

    dap_chain_net_srv_stream_session_t *l_srv_session = 
        (dap_chain_net_srv_stream_session_t *)a_ch->stream->session->_inheritor;

    l_srv_vpn->usage_id = l_srv_session->usage_active ? l_srv_session->usage_active->id : 0;
    dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
}

/**
 * @brief Channel destructor - cleanup IP lease, send unassign messages, cleanup timer
 */
void vpn_srv_ch_delete(dap_stream_ch_t *a_ch, void *a_arg)
{
    UNUSED(a_arg);
    
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);
    dap_chain_net_srv_vpn_t *l_srv_vpn = (dap_chain_net_srv_vpn_t *)l_ch_vpn->net_srv->_internal;

    dap_chain_net_srv_usage_t *l_usage = NULL;

    dap_chain_net_srv_stream_session_t *l_srv_session = 
        DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);
    if (l_srv_session)
        l_usage = l_srv_session->usage_active;

    // Delete save_limits timer if exists
    if (l_usage && l_usage->save_limits_timer) {
        dap_timerfd_delete_mt(l_usage->save_limits_timer->worker, l_usage->save_limits_timer->esocket_uuid);
        l_usage->save_limits_timer = NULL;
    }
    
    bool l_is_unleased = false;
    
    // Handle IP address leasing cleanup
    if (l_ch_vpn->addr_ipv4.s_addr) {
        // Signal all workers that IP is unassigned
        s_tun_send_msg_ip_unassigned_all(a_ch->stream_worker->worker->id, l_ch_vpn, l_ch_vpn->addr_ipv4);

        pthread_rwlock_wrlock(&s_raw_server_rwlock);
        if (s_raw_server) {
            if (s_raw_server->ipv4_lease_last.s_addr == l_ch_vpn->addr_ipv4.s_addr) {
                // Revert lease counter
                s_raw_server->ipv4_lease_last.s_addr = ntohl(ntohl(s_raw_server->ipv4_lease_last.s_addr) - 1);
            } else {
                l_is_unleased = true;
            }
        }
        pthread_rwlock_unlock(&s_raw_server_rwlock);
    }
    
    // Remove from clients hash table
    pthread_rwlock_wrlock(&s_clients_rwlock);
    if (s_ch_vpn_addrs) {
        HASH_DEL(s_ch_vpn_addrs, l_ch_vpn);
    }

    // Add to unleased list if needed
    if (l_is_unleased) {
        log_it(L_DEBUG, "Unlease address %s and store in threshold", inet_ntoa(l_ch_vpn->addr_ipv4));
        dap_chain_net_srv_vpn_item_ipv4_t *l_item_unleased = DAP_NEW_Z(dap_chain_net_srv_vpn_item_ipv4_t);
        if (!l_item_unleased) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            pthread_rwlock_unlock(&s_clients_rwlock);
            return;
        }
        l_item_unleased->addr.s_addr = l_ch_vpn->addr_ipv4.s_addr;
        l_item_unleased->next = l_srv_vpn->ipv4_unleased;
        l_srv_vpn->ipv4_unleased = l_item_unleased;
    }

    pthread_rwlock_unlock(&s_clients_rwlock);

    // Clear ch_vpn structure
    l_ch_vpn->ch = NULL;
    l_ch_vpn->net_srv = NULL;
    l_ch_vpn->is_allowed = false;
    DAP_DEL_Z(a_ch->internal);
}

/**
 * @brief Send PONG packet in response to PING
 */
static void send_pong_pkt(dap_stream_ch_t *a_ch)
{
    dap_stream_ch_vpn_pkt_t pkt_out = {};
    pkt_out.header.op_code = VPN_PACKET_OP_CODE_PONG;

    dap_stream_ch_pkt_write_unsafe(a_ch, 'd', &pkt_out, sizeof(dap_stream_ch_vpn_pkt_t));
    dap_stream_ch_set_ready_to_write_unsafe(a_ch, true);
}

/**
 * @brief Process VPN address request from client
 * @details Leases new IP address, sends VPN_PACKET_OP_CODE_VPN_ADDR_REPLY
 */
static void s_ch_packet_in_vpn_address_request(dap_stream_ch_t *a_ch, dap_chain_net_srv_usage_t *a_usage)
{
    dap_chain_net_srv_ch_vpn_t *l_ch_vpn = CH_VPN(a_ch);
    dap_chain_net_srv_vpn_t *l_srv_vpn = (dap_chain_net_srv_vpn_t *)a_usage->service->_internal;
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        DAP_CHAIN_NET_SRV_STREAM_SESSION(l_ch_vpn->ch->stream->session);

    // Try to reuse unleased address first
    pthread_rwlock_wrlock(&s_raw_server_rwlock);
    dap_chain_net_srv_vpn_item_ipv4_t *l_item_ipv4 = l_srv_vpn->ipv4_unleased;
    
    if (l_item_ipv4) {
        // Reuse unleased address
        l_ch_vpn->addr_ipv4.s_addr = l_item_ipv4->addr.s_addr;
        a_ch->stream->session->tun_client_addr.s_addr = l_item_ipv4->addr.s_addr;
        
        pthread_rwlock_unlock(&s_raw_server_rwlock);
        pthread_rwlock_wrlock(&s_clients_rwlock);
        HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof(l_ch_vpn->addr_ipv4), l_ch_vpn);
        pthread_rwlock_unlock(&s_clients_rwlock);

        // Send VPN_ADDR_REPLY
        dap_stream_ch_vpn_pkt_t *l_pkt_out = DAP_NEW_STACK_SIZE(
            dap_stream_ch_vpn_pkt_t,
            sizeof(l_pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_network_addr));
        
        l_pkt_out->header.sock_id = 0;  // Unified TUN API: sock_id is deprecated
        l_pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
        l_pkt_out->header.usage_id = a_usage->id;
        l_pkt_out->header.op_data.data_size = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw);

        memcpy(l_pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
        memcpy(l_pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_gw,
               sizeof(s_raw_server->ipv4_gw));

        size_t l_data_to_write = l_pkt_out->header.op_data.data_size + sizeof(l_pkt_out->header);
        size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(
            a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, l_pkt_out, l_data_to_write);
        
        l_srv_session->stats.bytes_sent += l_data_wrote;
        if (l_data_wrote < l_data_to_write) {
            log_it(L_WARNING, "Buffer overflow: can't send packet with VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: sent only %zd from %zd",
                   l_data_wrote, l_data_to_write);
            l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
            l_srv_session->stats.packets_sent_lost++;
        } else {
            char l_str_ipv4addr[INET_ADDRSTRLEN], l_str_ipv4gw[INET_ADDRSTRLEN],
                 l_str_ipv4mask[INET_ADDRSTRLEN], l_str_ipv4netaddr[INET_ADDRSTRLEN],
                 l_str_ipv4last[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &l_ch_vpn->addr_ipv4, l_str_ipv4addr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_gw, l_str_ipv4gw, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_network_mask, l_str_ipv4mask, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_network_addr, l_str_ipv4netaddr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &s_raw_server->ipv4_lease_last, l_str_ipv4last, INET_ADDRSTRLEN);

            log_it(L_INFO, "VPN client IP address %s leased"
                    "\r\n\tnet gateway %s"
                    "\r\n\tnet mask %s"
                    "\r\n\tgw %s"
                    "\r\n\tlast_addr %s",
                    l_str_ipv4addr, l_str_ipv4gw, l_str_ipv4mask, l_str_ipv4netaddr, l_str_ipv4last);

            l_srv_vpn->ipv4_unleased = l_item_ipv4->next;
            DAP_DEL_Z(l_item_ipv4);
            l_srv_session->stats.packets_sent++;
            s_tun_send_msg_ip_assigned_all(a_ch->stream_worker->worker->id, l_ch_vpn, l_ch_vpn->addr_ipv4);
        }
    } else {
        // Lease new address
        struct in_addr n_addr = {0}, n_addr_max;
        n_addr.s_addr = ntohl(s_raw_server->ipv4_lease_last.s_addr);
        n_addr.s_addr++;
        n_addr_max.s_addr = (ntohl(s_raw_server->ipv4_gw.s_addr) | ~ntohl(s_raw_server->ipv4_network_mask.s_addr));

        n_addr.s_addr = htonl(n_addr.s_addr);
        n_addr_max.s_addr = htonl(n_addr_max.s_addr);

        char l_str_naddr[INET_ADDRSTRLEN], l_str_naddr_max[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &n_addr, l_str_naddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &n_addr_max, l_str_naddr_max, INET_ADDRSTRLEN);

        log_it(L_DEBUG, "\tnew_address         = %s\r\n\tnew_address_max = %s", l_str_naddr, l_str_naddr_max);

        n_addr.s_addr = ntohl(n_addr.s_addr);
        n_addr_max.s_addr = ntohl(n_addr_max.s_addr);
        
        if (n_addr.s_addr <= n_addr_max.s_addr) {
            // Address is available
            n_addr.s_addr = htonl(n_addr.s_addr);
            n_addr_max.s_addr = htonl(n_addr_max.s_addr);

            s_raw_server->ipv4_lease_last.s_addr = n_addr.s_addr;
            a_ch->stream->session->tun_client_addr.s_addr = n_addr.s_addr;
            l_ch_vpn->addr_ipv4.s_addr = n_addr.s_addr;

            pthread_rwlock_unlock(&s_raw_server_rwlock);
            pthread_rwlock_wrlock(&s_clients_rwlock);
            HASH_ADD(hh, s_ch_vpn_addrs, addr_ipv4, sizeof(l_ch_vpn->addr_ipv4), l_ch_vpn);
            pthread_rwlock_unlock(&s_clients_rwlock);

            // Send VPN_ADDR_REPLY
            dap_stream_ch_vpn_pkt_t *pkt_out = DAP_NEW_STACK_SIZE(
                dap_stream_ch_vpn_pkt_t,
                sizeof(pkt_out->header) + sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw));
            
            pkt_out->header.sock_id = 0;  // Unified TUN API: sock_id is deprecated
            pkt_out->header.op_code = VPN_PACKET_OP_CODE_VPN_ADDR_REPLY;
            pkt_out->header.op_data.data_size = sizeof(l_ch_vpn->addr_ipv4) + sizeof(s_raw_server->ipv4_gw);
            pkt_out->header.usage_id = a_usage->id;

            memcpy(pkt_out->data, &l_ch_vpn->addr_ipv4, sizeof(l_ch_vpn->addr_ipv4));
            memcpy(pkt_out->data + sizeof(l_ch_vpn->addr_ipv4), &s_raw_server->ipv4_gw,
                   sizeof(s_raw_server->ipv4_gw));

            size_t l_data_to_write = pkt_out->header.op_data.data_size + sizeof(pkt_out->header);
            size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(
                a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out, l_data_to_write);
            
            l_srv_session->stats.bytes_sent += l_data_wrote;
            if (l_data_wrote < l_data_to_write) {
                log_it(L_WARNING, "Buffer overflow: can't send packet with VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: sent only %zd from %zd",
                       l_data_wrote, l_data_to_write);
                l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
                l_srv_session->stats.packets_sent_lost++;
            } else {
                l_srv_session->stats.packets_sent++;
                s_tun_send_msg_ip_assigned_all(a_ch->stream_worker->worker->id, l_ch_vpn, l_ch_vpn->addr_ipv4);
            }
        } else {
            // No free addresses left
            pthread_rwlock_unlock(&s_raw_server_rwlock);
            
            log_it(L_ERROR, "No free IP address left, can't lease one...");
            dap_stream_ch_vpn_pkt_t *pkt_out = DAP_NEW_STACK_SIZE(dap_stream_ch_vpn_pkt_t, sizeof(pkt_out->header));
            pkt_out->header.sock_id = 0;  // Unified TUN API: sock_id is deprecated
            pkt_out->header.op_code = VPN_PACKET_OP_CODE_PROBLEM;
            pkt_out->header.usage_id = a_usage->id;
            pkt_out->header.op_problem.code = VPN_PROBLEM_CODE_NO_FREE_ADDR;
            
            size_t l_data_to_write = sizeof(pkt_out->header);
            size_t l_data_wrote = dap_stream_ch_pkt_write_unsafe(
                a_ch, DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA, pkt_out, l_data_to_write);
            
            l_srv_session->stats.bytes_sent += l_data_wrote;
            if (l_data_wrote < l_data_to_write) {
                log_it(L_WARNING, "Buffer overflow: can't send packet with VPN_PACKET_OP_CODE_PROBLEM: sent only %zd from %zd",
                       l_data_wrote, l_data_to_write);
                l_srv_session->stats.bytes_sent_lost += l_data_to_write - l_data_wrote;
                l_srv_session->stats.packets_sent_lost++;
            } else {
                l_srv_session->stats.packets_sent++;
            }
        }
    }
}

/**
 * @brief Packet input handler - processes all VPN opcodes
 */
bool vpn_srv_ch_packet_in(dap_stream_ch_t *a_ch, void *a_arg)
{
    dap_stream_ch_pkt_t *l_pkt = (dap_stream_ch_pkt_t *)a_arg;
    dap_stream_ch_vpn_pkt_t *l_vpn_pkt = (dap_stream_ch_vpn_pkt_t *)l_pkt->data;
    
    if (l_pkt->hdr.data_size < sizeof(l_vpn_pkt->header)) {
        log_it(L_WARNING, "Data size of stream channel packet %u is lesser than size of VPN packet header %zu",
               l_pkt->hdr.data_size, sizeof(l_vpn_pkt->header));
        return false;
    }
    
    size_t l_vpn_pkt_data_size = l_pkt->hdr.data_size - sizeof(l_vpn_pkt->header);
    dap_chain_net_srv_stream_session_t *l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION(a_ch->stream->session);
    dap_chain_net_srv_usage_t *l_usage = l_srv_session->usage_active;

    if (!l_usage) {
        log_it(L_NOTICE, "No active usage in list, possible disconnected. Send nothing on this channel");
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    }

    if (!l_usage->is_active && l_usage->service_substate > DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN) {
        log_it(L_INFO, "Usage inactivation: switch off packet input & output channels");
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe(l_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED, NULL, 0);
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    } else if (l_usage->service_substate <= DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN) {
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    }

    // Check node role
    if (dap_chain_net_get_role(l_usage->net).enums > NODE_ROLE_MASTER) {
        log_it(L_ERROR, 
            "You can't provide service with ID %"DAP_UINT64_FORMAT_X" in net %s. Node role should be not lower than master\n",
            l_usage->service->uid.uint64, l_usage->net->pub.name);
        l_usage->is_active = false;
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe(l_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED, NULL, 0);
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    }

    debug_if(s_debug_more, L_INFO, "Got srv_vpn packet with op_code=0x%02x", l_vpn_pkt->header.op_code);
    
    if (l_vpn_pkt->header.op_code >= 0xb0) { // Raw packets
        switch (l_vpn_pkt->header.op_code) {
            case VPN_PACKET_OP_CODE_PING:
                a_ch->stream->esocket->last_ping_request = time(NULL);
                l_srv_session->stats.bytes_recv += l_vpn_pkt_data_size;
                l_srv_session->stats.packets_recv++;
                send_pong_pkt(a_ch);
                break;
            
            case VPN_PACKET_OP_CODE_PONG:
                a_ch->stream->esocket->last_ping_request = time(NULL);
                l_srv_session->stats.bytes_recv += l_vpn_pkt_data_size;
                l_srv_session->stats.packets_recv++;
                break;
            
            // Client-side: address reply
            case VPN_PACKET_OP_CODE_VPN_ADDR_REPLY: {
                if (ch_sf_tun_addr_leased(CH_VPN(a_ch), l_vpn_pkt, l_pkt->hdr.data_size) < 0) {
                    log_it(L_ERROR, "Can't create tun");
                    break;
                }
                s_tun_send_msg_ip_assigned_all(a_ch->stream_worker->worker->id, CH_VPN(a_ch), CH_VPN(a_ch)->addr_ipv4);
                l_srv_session->stats.bytes_recv += l_pkt->hdr.data_size;
                l_srv_session->stats.packets_recv++;
            } break;
            
            // Server-side: address request
            case VPN_PACKET_OP_CODE_VPN_ADDR_REQUEST: {
                log_it(L_INFO, "Received address request");
                if (s_raw_server) {
                    s_ch_packet_in_vpn_address_request(a_ch, l_usage);
                } else {
                    dap_stream_ch_chain_net_srv_pkt_error_t l_err = {0};
                    l_err.code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_SERVICE_IN_CLIENT_MODE;
                    dap_stream_ch_pkt_write_unsafe(l_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR,
                                                    &l_err, sizeof(l_err));
                }
                l_srv_session->stats.bytes_recv += l_pkt->hdr.data_size;
                l_srv_session->stats.packets_recv++;
            } break;
            
            // Client-side: receive data from server
            case VPN_PACKET_OP_CODE_VPN_RECV: {
                if (l_vpn_pkt_data_size != l_vpn_pkt->header.op_data.data_size) {
                    log_it(L_WARNING, "Size of VPN packet data %zu is not equal to estimated size %u",
                           l_vpn_pkt_data_size, l_vpn_pkt->header.op_data.data_size);
                    return false;
                }
                a_ch->stream->esocket->last_ping_request = time(NULL);
                
                dap_events_socket_t *l_es = dap_chain_net_vpn_client_tun_get_esock();
                dap_chain_net_srv_vpn_tun_socket_t *l_tun = l_es ? l_es->_inheritor : NULL;
                
                assert(l_tun);
                if (!l_tun)
                    return log_it(L_ERROR, "Tun not found!"), false;
                
                size_t l_ret = dap_events_socket_write_unsafe(l_tun->es, l_vpn_pkt->data, l_vpn_pkt->header.op_data.data_size);
                l_srv_session->stats.bytes_sent += l_ret;
                
                if (l_ret == l_vpn_pkt->header.op_data.data_size) {
                    l_srv_session->stats.packets_sent++;
                } else if (l_ret > 0) {
                    log_it(L_WARNING, "Lost %zd bytes, buffer overflow", l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.bytes_sent_lost += (l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.packets_sent_lost++;
                }
            } break;
            
            // Server-side: send data to client
            case VPN_PACKET_OP_CODE_VPN_SEND: {
                if (l_vpn_pkt_data_size != l_vpn_pkt->header.op_data.data_size) {
                    log_it(L_WARNING, "Size of VPN packet data %zu is not equal to estimated size %u",
                           l_vpn_pkt_data_size, l_vpn_pkt->header.op_data.data_size);
                    return false;
                }
                
                dap_chain_net_srv_vpn_tun_socket_t *l_tun = g_vpn_tun_sockets[a_ch->stream_worker->worker->id];
                assert(l_tun);
                
                size_t l_ret = dap_events_socket_write_unsafe(l_tun->es, l_vpn_pkt,
                    sizeof(l_vpn_pkt->header) + l_vpn_pkt->header.op_data.data_size) - sizeof(l_vpn_pkt->header);
                
                l_srv_session->stats.bytes_sent += l_ret;
                l_usage->client->bytes_sent += l_ret;
                s_update_limits(a_ch, l_srv_session, l_usage, l_ret);
                
                if (l_ret == l_vpn_pkt->header.op_data.data_size) {
                    l_srv_session->stats.packets_sent++;
                } else if (l_ret > 0) {
                    log_it(L_WARNING, "Lost %zd bytes, buffer overflow", l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.bytes_sent_lost += (l_vpn_pkt->header.op_data.data_size - l_ret);
                    l_srv_session->stats.packets_sent_lost++;
                }
            } break;
            
            default:
                log_it(L_WARNING, "Can't process SF type 0x%02x", l_vpn_pkt->header.op_code);
                return false;
        }
    }
    return true;
}

/**
 * @brief Packet output handler - validates usage state before allowing output
 */
bool vpn_srv_ch_packet_out(dap_stream_ch_t *a_ch, void *a_arg)
{
    UNUSED(a_arg);
    
    dap_chain_net_srv_stream_session_t *l_srv_session = DAP_CHAIN_NET_SRV_STREAM_SESSION(a_ch->stream->session);
    dap_chain_net_srv_usage_t *l_usage = l_srv_session->usage_active;
    
    if (!l_usage) {
        log_it(L_NOTICE, "No active usage in list, possible disconnected. Send nothing on this channel");
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    }

    if (!l_usage->is_active && l_usage->service_substate > DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN) {
        log_it(L_INFO, "Usage inactivation: switch off packet input & output channels");
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe(l_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED, NULL, 0);
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    } else if (l_usage->service_substate <= DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN) {
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    }
    
    if ((l_usage->service_state != DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_FREE) && 
        (!l_usage->receipt && l_usage->service_state != DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE)) {
        log_it(L_WARNING, "No active receipt, switching off");
        l_usage->is_active = false;
        if (l_usage->client)
            dap_stream_ch_pkt_write_unsafe(l_usage->client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_NOTIFY_STOPPED, NULL, 0);
        dap_stream_ch_set_ready_to_write_unsafe(a_ch, false);
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
        return false;
    }
    
    return false;
}

// Public wrappers for compatibility

int vpn_srv_ch_packet_in_vpn_address_request(dap_stream_ch_t *a_ch, dap_chain_net_srv_usage_t *a_usage)
{
    s_ch_packet_in_vpn_address_request(a_ch, a_usage);
    return 0;
}

void vpn_srv_send_pong_pkt(dap_stream_ch_t *a_ch)
{
    send_pong_pkt(a_ch);
}

int vpn_srv_ch_tun_addr_leased(
    struct dap_chain_net_srv_ch_vpn *a_ch_vpn,
    struct dap_stream_ch_vpn_pkt *a_vpn_pkt,
    size_t a_pkt_size)
{
    return ch_sf_tun_addr_leased(a_ch_vpn, a_vpn_pkt, a_pkt_size);
}

