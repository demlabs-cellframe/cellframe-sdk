/**
 * @file dap_chain_net_vpn_client_state_tunnel.c
 * @brief TUN Device and Stream Channel packet forwarding callbacks
 * @details Handles bidirectional packet forwarding:
 *          - TUN → Stream: Outgoing packets (client to VPN server)
 *          - Stream → TUN: Incoming packets (VPN server to client)
 * 
 *          ARCHITECTURE: Thread-safe, worker-affinity aware
 *          - Uses dap_net_tun_t channel_info (worker + UUID) for routing
 *          - No state machine dependency for packet forwarding
 *          - Proper synchronization via TUN internal structures
 * 
 * @date 2025-10-25
 * @copyright (c) 2025 Cellframe Network
 */

#include "dap_chain_net_vpn_client_state_internal.h"
#include "dap_common.h"
#include "dap_stream_ch_pkt.h"

#define LOG_TAG "dap_chain_net_vpn_client_state_tunnel"

// Debug flag (external)
extern bool s_debug_more;

/**
 * @brief TUN device data received callback (NEW API)
 * @details Called when packet arrives from TUN device (from local network stack).
 *          Forwards packet to VPN server via stream channel using channel_info from TUN.
 * 
 *          NEW: Receives channel_info (worker + UUID) directly from dap_net_tun_t!
 *               No need to access state machine for routing info.
 * 
 * @param a_tun TUN device handle
 * @param a_data Packet data
 * @param a_data_size Packet size in bytes
 * @param a_channel_info Channel routing info (worker + UUID) - provided by TUN!
 * @param a_user_data State machine context (for stats only)
 */
void dap_chain_net_vpn_client_tun_data_received_callback(
    dap_net_tun_t *a_tun,
    const void *a_data,
    size_t a_data_size,
    const dap_net_tun_channel_info_t *a_channel_info,
    void *a_user_data)
{
    UNUSED(a_tun);
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_user_data;
    
    if (!l_sm || !a_data || a_data_size == 0) {
        log_it(L_WARNING, "Invalid parameters in TUN data callback");
        return;
    }
    
    if (l_sm->current_state != VPN_STATE_CONNECTED) {
        log_it(L_DEBUG, "Dropping packet: not in CONNECTED state (current: %d)", l_sm->current_state);
        return;
    }
    
    // Check channel info (provided by TUN!)
    if (!a_channel_info || !a_channel_info->worker || dap_uuid_is_blank(&a_channel_info->channel_uuid)) {
        log_it(L_WARNING, "No VPN channel info available from TUN (not set yet?)");
        return;
    }
    
    // Forward packet to VPN server via stream channel (MT-safe API)
    // Use channel info directly from TUN - no state machine access needed!
    size_t l_written = dap_stream_ch_pkt_write_mt(
        a_channel_info->worker,
        a_channel_info->channel_uuid,
        DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA,
        a_data,
        a_data_size
    );
    
    if (l_written != a_data_size) {
        log_it(L_ERROR, "Failed to write packet to stream channel: %zu/%zu bytes", 
               l_written, a_data_size);
        return;
    }
    
    // Update statistics
    pthread_mutex_lock(&l_sm->mutex);
    l_sm->bytes_sent += a_data_size;
    pthread_mutex_unlock(&l_sm->mutex);
    
    debug_if(s_debug_more, L_DEBUG, "Forwarded %zu bytes from TUN to server (worker=%p, uuid="UUID_FORMAT_STR")",
             a_data_size, a_channel_info->worker, UUID_FORMAT_ARGS(&a_channel_info->channel_uuid));
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
void dap_chain_net_vpn_client_tun_error_callback(dap_net_tun_t *a_tun, int a_error_code, 
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
 * 
 *          Signature: dap_stream_ch_chain_net_srv_callback_packet_t
 *          void (*)(dap_stream_ch_chain_net_srv_t *, uint8_t, dap_stream_ch_pkt_t *, void *)
 * 
 * @param a_ch_srv Stream channel service handle
 * @param a_pkt_type Packet type
 * @param a_pkt Packet data
 * @param a_arg State machine context
 */
void dap_chain_net_vpn_client_stream_packet_in_callback(
    dap_stream_ch_chain_net_srv_t *a_ch_srv,
    uint8_t a_pkt_type,
    dap_stream_ch_pkt_t *a_pkt,
    void *a_arg)
{
    UNUSED(a_ch_srv);
    dap_chain_net_vpn_client_sm_t *l_sm = (dap_chain_net_vpn_client_sm_t *)a_arg;
    
    if (!l_sm || !l_sm->tun_handle || !a_pkt) {
        log_it(L_WARNING, "Invalid parameters in stream packet callback");
        return;
    }
    
    if (l_sm->current_state != VPN_STATE_CONNECTED) {
        log_it(L_DEBUG, "Dropping packet: not in CONNECTED state (current: %d)", 
               l_sm->current_state);
        return;
    }
    
    // Check packet type
    if (a_pkt_type != DAP_STREAM_CH_PKT_TYPE_NET_SRV_VPN_DATA) {
        log_it(L_WARNING, "Unexpected packet type: 0x%02x", a_pkt_type);
        return;
    }
    
    // Write packet to TUN device
    size_t l_data_size = a_pkt->hdr.data_size;
    if (l_data_size > 0) {
        ssize_t l_result = dap_net_tun_write(l_sm->tun_handle, a_pkt->data, l_data_size);
        
        if (l_result < 0) {
            log_it(L_ERROR, "Failed to write %zu bytes to TUN device (error: %zd)", 
                   l_data_size, l_result);
        } else {
            // Update statistics
            pthread_mutex_lock(&l_sm->mutex);
            l_sm->bytes_received += l_data_size;
            pthread_mutex_unlock(&l_sm->mutex);
            
            debug_if(s_debug_more, L_DEBUG, "Forwarded %zu bytes from server to TUN", l_data_size);
        }
    }
}
