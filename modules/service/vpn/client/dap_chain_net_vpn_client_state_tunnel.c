/**
 * @file dap_chain_net_vpn_client_state_tunnel.c
 * @brief TUN Device and Stream Channel packet forwarding callbacks
 * @details Handles bidirectional packet forwarding:
 *          - TUN → Stream: Outgoing packets (client to VPN server)
 *          - Stream → TUN: Incoming packets (VPN server to client)
 * @date 2025-10-25
 * @copyright (c) 2025 Cellframe Network
 */

#include "include/dap_chain_net_vpn_client_state_internal.h"
#include "dap_common.h"

#define LOG_TAG "dap_chain_net_vpn_client_state_tunnel"

/**
 * @brief TUN device data received callback
 * @details Called when packet arrives from TUN device (from local network stack).
 *          Forwards packet to VPN server via stream channel.
 * @param a_tun TUN device handle
 * @param a_data Packet data
 * @param a_data_size Packet size in bytes
 * @param a_user_data State machine context
 */
void s_tun_data_received_callback(dap_net_tun_t *a_tun, const void *a_data, 
                                   size_t a_data_size, void *a_user_data) {
    UNUSED(a_tun);
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_user_data;
    
    if (!l_sm || !l_sm->vpn_channel || !a_data || a_data_size == 0) {
        log_it(L_WARNING, "Invalid parameters in TUN data callback");
        return;
    }
    
    if (l_sm->current_state != VPN_STATE_CONNECTED) {
        log_it(L_DEBUG, "Dropping packet: not in CONNECTED state (current: %d)", l_sm->current_state);
        return;
    }
    
    // Forward packet to VPN server via stream channel
    size_t l_written = dap_stream_ch_pkt_write_unsafe(l_sm->vpn_channel, 
                                                        DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA,
                                                        a_data, a_data_size);
    
    if (l_written != a_data_size) {
        log_it(L_ERROR, "Failed to write packet to stream channel: %zu/%zu bytes", 
               l_written, a_data_size);
        return;
    }
    
    // Update statistics
    pthread_mutex_lock(&l_sm->mutex);
    l_sm->bytes_sent += a_data_size;
    pthread_mutex_unlock(&l_sm->mutex);
    
    debug_if(g_debug_more, L_DEBUG, "Forwarded %zu bytes from TUN to server", a_data_size);
}

/**
 * @brief TUN device error callback
 * @details Called when TUN device encounters an error.
 *          Triggers CONNECTION_LOST event if currently connected.
 * @param a_tun TUN device handle
 * @param a_error_code Error code
 * @param a_error_msg Error message (may be NULL)
 * @param a_user_data State machine context
 */
void s_tun_error_callback(dap_net_tun_t *a_tun, int a_error_code, 
                          const char *a_error_msg, void *a_user_data) {
    UNUSED(a_tun);
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_user_data;
    
    log_it(L_ERROR, "TUN device error (code %d): %s", 
           a_error_code, a_error_msg ? a_error_msg : "unknown");
    
    if (l_sm && l_sm->current_state == VPN_STATE_CONNECTED) {
        // Trigger connection lost event
        dap_chain_net_vpn_client_sm_transition(l_sm, VPN_EVENT_CONNECTION_LOST);
    }
}

/**
 * @brief Stream channel packet received callback
 * @details Called when packet is received from VPN server (incoming traffic).
 *          Forwards packet to TUN device for local network stack processing.
 * @param a_ch Stream channel handle
 * @param a_arg State machine context
 */
void s_stream_ch_packet_in_callback(dap_stream_ch_t *a_ch, void *a_arg) {
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_arg;
    
    if (!l_sm || !l_sm->tun_handle || !a_ch) {
        log_it(L_WARNING, "Invalid parameters in stream packet callback");
        return;
    }
    
    if (l_sm->current_state != VPN_STATE_CONNECTED) {
        log_it(L_DEBUG, "Dropping packet: not in CONNECTED state (current: %d)", 
               l_sm->current_state);
        return;
    }
    
    // Get packet from stream channel
    dap_stream_ch_pkt_t *l_pkt = dap_stream_ch_pkt_read_unsafe(a_ch);
    if (!l_pkt) {
        return;  // No packet available
    }
    
    // Check packet type
    if (l_pkt->hdr.type != DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA) {
        log_it(L_WARNING, "Unexpected packet type: 0x%02x", l_pkt->hdr.type);
        DAP_DELETE(l_pkt);
        return;
    }
    
    // Write packet to TUN device
    size_t l_data_size = l_pkt->hdr.size;
    if (l_data_size > 0) {
        int l_result = dap_net_tun_write(l_sm->tun_handle, l_pkt->data, l_data_size);
        
        if (l_result < 0) {
            log_it(L_ERROR, "Failed to write %zu bytes to TUN device (error: %d)", 
                   l_data_size, l_result);
        } else {
            // Update statistics
            pthread_mutex_lock(&l_sm->mutex);
            l_sm->bytes_received += l_data_size;
            pthread_mutex_unlock(&l_sm->mutex);
            
            debug_if(g_debug_more, L_DEBUG, "Forwarded %zu bytes from server to TUN", l_data_size);
        }
    }
    
    DAP_DELETE(l_pkt);
}

