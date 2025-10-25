/**
 * @file dap_chain_net_srv_vpn_tun.c
 * @brief VPN Service TUN Device Management Implementation
 * @details TUN initialization, event callbacks, packet routing
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#include "dap_chain_net_srv_vpn_tun.h"
#include "dap_chain_net_srv_vpn_internal.h"
#include "../tun/include/dap_net_tun.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_events_socket.h"
#include "dap_context.h"
#include "dap_stream_ch_pkt.h"
#include "uthash.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <assert.h>
#include <pthread.h>

#define LOG_TAG "dap_chain_net_srv_vpn_tun"

// Macro for TUN socket access
#define CH_SF_TUN_SOCKET(a) ((dap_chain_net_srv_vpn_tun_socket_t *)((a)->_inheritor))

/**
 * @brief Initialize TUN device infrastructure
 */
int vpn_srv_tun_init(void)
{
    g_vpn_raw_server = DAP_NEW_Z(vpn_local_network_t);
    if (!g_vpn_raw_server) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    
    pthread_rwlock_init(&g_vpn_raw_server_rwlock, NULL);
    pthread_mutex_init(&g_vpn_tun_sockets_mutex_started, NULL);
    pthread_cond_init(&g_vpn_tun_sockets_cond_started, NULL);

    return 0;
}

/**
 * @brief Create TUN device using unified TUN API
 */
int vpn_srv_tun_create(dap_config_t *a_config)
{
    // Parse network configuration
    const char *c_addr = dap_config_get_item_str(a_config, "srv_vpn", "network_address");
    const char *c_mask = dap_config_get_item_str(a_config, "srv_vpn", "network_mask");
    
    if (!c_addr || !c_mask) {
        log_it(L_CRITICAL, "Error while reading network parameters from config (network_address and network_mask)");
        return -1;
    }

    inet_aton(c_addr, &g_vpn_raw_server->ipv4_network_addr);
    inet_aton(c_mask, &g_vpn_raw_server->ipv4_network_mask);
    g_vpn_raw_server->ipv4_gw.s_addr = (g_vpn_raw_server->ipv4_network_addr.s_addr | 0x01000000);
    g_vpn_raw_server->ipv4_lease_last.s_addr = g_vpn_raw_server->ipv4_gw.s_addr;
    g_vpn_raw_server->auto_cpu_reassignment = dap_config_get_item_bool_default(a_config, "srv_vpn", "auto_cpu_reassignment", false);

    // Prepare unified TUN configuration
    dap_net_tun_config_t l_tun_config = {
        .mode = DAP_NET_TUN_MODE_SERVER,
        .network_addr = g_vpn_raw_server->ipv4_network_addr,
        .network_mask = g_vpn_raw_server->ipv4_network_mask,
        .gateway_addr = g_vpn_raw_server->ipv4_gw,
        .device_name_prefix = "tun",
        .mtu = 1500,
        .worker_count = 0,  // Auto-detect CPU count
        .workers = NULL,     // Will use dap_events_worker_get()
        .on_data_received = vpn_srv_tun_data_received_callback,
        .on_error = vpn_srv_tun_error_callback,
        .callback_arg = NULL,
        .auto_cpu_reassignment = g_vpn_raw_server->auto_cpu_reassignment
    };

    // Initialize unified TUN device
    g_vpn_tun_handle = dap_net_tun_init(&l_tun_config);
    if (!g_vpn_tun_handle) {
        log_it(L_ERROR, "Failed to initialize unified TUN device");
        return -1;
    }

    // Get device info
    const char *l_tun_name = dap_net_tun_get_device_name(g_vpn_tun_handle, 0);
    if (l_tun_name) {
        g_vpn_raw_server->tun_device_name = strdup(l_tun_name);
    }

    g_vpn_tun_sockets_count = dap_net_tun_get_device_count(g_vpn_tun_handle);

    log_it(L_NOTICE, "Auto CPU reassignment is set to '%s'", g_vpn_raw_server->auto_cpu_reassignment ? "true" : "false");
    log_it(L_INFO, "TUN device initialized with %u devices", g_vpn_tun_sockets_count);

    return 0;
}

/**
 * @brief Create event stream for TUN file descriptor
 */
dap_events_socket_t *vpn_srv_tun_event_stream_create(dap_worker_t *a_worker, int a_tun_fd)
{
    assert(a_worker);
    
    dap_events_socket_callbacks_t l_s_callbacks = {
        .new_callback            = vpn_srv_es_tun_new,
        .read_callback           = vpn_srv_es_tun_read,
        .write_callback          = vpn_srv_es_tun_write,
        .error_callback          = vpn_srv_es_tun_error,
        .delete_callback         = vpn_srv_es_tun_delete,
        .write_finished_callback = vpn_srv_es_tun_write_finished
    };

    dap_events_socket_t *l_es = dap_events_socket_wrap_no_add(a_tun_fd, &l_s_callbacks);
    l_es->type = DESCRIPTOR_TYPE_FILE;
    l_es->no_close = true;
    dap_events_socket_assign_on_worker_mt(l_es, a_worker);

    return l_es;
}

/**
 * @brief TUN data received callback (unified TUN API)
 */
void vpn_srv_tun_data_received_callback(
    dap_net_tun_t *a_tun,
    const void *a_data,
    size_t a_data_size,
    const dap_net_tun_channel_info_t *a_channel_info,
    void *a_arg)
{
    UNUSED(a_tun);
    UNUSED(a_channel_info);  // Not used in SERVER mode (no channel routing needed)
    UNUSED(a_arg);
    
    if (!a_data || a_data_size == 0) {
        return;
    }
    
    debug_if(g_vpn_debug_more, L_DEBUG, "Received %zu bytes from TUN device", a_data_size);
    
    // Parse IP header to get destination address
    if (a_data_size < 20) {  // Minimum IP header size
        log_it(L_WARNING, "Packet too small for IP header: %zu bytes", a_data_size);
        return;
    }
    
    const uint8_t *l_ip_packet = (const uint8_t *)a_data;
    struct in_addr l_dst_addr;
    memcpy(&l_dst_addr, l_ip_packet + 16, 4);  // Destination IP at offset 16
    
    // Find client by destination IP
    pthread_rwlock_rdlock(&g_vpn_clients_rwlock);
    dap_chain_net_srv_ch_vpn_t *l_client = NULL;
    HASH_FIND(hh, g_vpn_ch_vpn_addrs, &l_dst_addr, sizeof(struct in_addr), l_client);
    
    if (!l_client) {
        pthread_rwlock_unlock(&g_vpn_clients_rwlock);
        debug_if(g_vpn_debug_more, L_WARNING, "No client found for destination %s",
                 inet_ntoa(l_dst_addr));
        return;
    }
    
    // Send packet to client via stream channel
    if (l_client->ch && l_client->ch->stream) {
        dap_stream_ch_pkt_write_unsafe(l_client->ch, DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_DATA,
                                        a_data, a_data_size);
        debug_if(g_vpn_debug_more, L_DEBUG, "Routed %zu bytes to client %s",
                 a_data_size, inet_ntoa(l_dst_addr));
    }
    
    pthread_rwlock_unlock(&g_vpn_clients_rwlock);
}

/**
 * @brief TUN error callback (unified TUN API - NEW SIGNATURE)
 */
void vpn_srv_tun_error_callback(
    dap_net_tun_t *a_tun,
    int a_error,
    const char *a_error_msg,
    void *a_arg)
{
    UNUSED(a_tun);
    UNUSED(a_arg);
    
    log_it(L_ERROR, "TUN device error (code %d): %s", a_error, a_error_msg ? a_error_msg : "unknown");
}

/**
 * @brief TUN event socket constructor
 */
void vpn_srv_es_tun_new(dap_events_socket_t *a_es, void *a_arg)
{
    UNUSED(a_arg);
    
    dap_chain_net_srv_vpn_tun_socket_t *l_tun_socket = DAP_NEW_Z(dap_chain_net_srv_vpn_tun_socket_t);
    if (!l_tun_socket) {
        log_it(L_ERROR, "Can't allocate memory for tun socket");
        return;
    }
    
    dap_worker_t *l_worker = l_tun_socket->worker = a_es->worker;
    uint32_t l_worker_id = l_tun_socket->worker_id = l_worker->id;
    l_tun_socket->es = a_es;

    g_vpn_tun_sockets_queue_msg[l_worker_id] = dap_context_create_queue(l_worker->context, s_tun_recv_msg_callback);
    g_vpn_tun_sockets[l_worker_id] = l_tun_socket;

    l_tun_socket->queue_tun_msg_input = DAP_NEW_Z_SIZE(dap_events_socket_t *,
                                                        sizeof(dap_events_socket_t *) * dap_events_thread_get_count());
    a_es->_inheritor = l_tun_socket;

    // Signal that it's ready
    pthread_mutex_lock(&g_vpn_tun_sockets_mutex_started);
    g_vpn_tun_sockets_started++;
    pthread_cond_broadcast(&g_vpn_tun_sockets_cond_started);
    pthread_mutex_unlock(&g_vpn_tun_sockets_mutex_started);

    log_it(L_NOTICE, "New TUN event socket initialized for worker %u", l_tun_socket->worker_id);
}

/**
 * @brief TUN event socket destructor
 */
void vpn_srv_es_tun_delete(dap_events_socket_t *a_es, void *a_arg)
{
    UNUSED(a_arg);
    
    if (a_es->worker) {
        g_vpn_tun_sockets[a_es->worker->id] = NULL;
        dap_events_socket_remove_and_delete_unsafe(g_vpn_tun_sockets_queue_msg[a_es->worker->id], false);
        log_it(L_NOTICE, "Destroyed TUN event socket");
    }
}

/**
 * @brief TUN read callback - routes packets based on dest IP
 */
void vpn_srv_es_tun_read(dap_events_socket_t *a_es, void *a_arg)
{
    UNUSED(a_arg);
    
    dap_chain_net_srv_vpn_tun_socket_t *l_tun_socket = CH_SF_TUN_SOCKET(a_es);
    assert(l_tun_socket);
    
    size_t l_buf_in_size = a_es->buf_in_size;
    struct iphdr *iph = (struct iphdr *)a_es->buf_in;
    
    if (g_vpn_debug_more) {
        char l_str_daddr[INET_ADDRSTRLEN] = {[0] = '\0'};
        char l_str_saddr[INET_ADDRSTRLEN] = {[0] = '\0'};
        struct in_addr l_daddr;
        struct in_addr l_saddr;
        size_t l_ip_tot_len;
        
#ifdef DAP_OS_LINUX
        l_daddr.s_addr = iph->daddr;
        l_saddr.s_addr = iph->saddr;
        l_ip_tot_len = ntohs(iph->tot_len);
#else
        l_daddr.s_addr = iph->ip_dst.s_addr;
        l_saddr.s_addr = iph->ip_src.s_addr;
        l_ip_tot_len = ntohs(iph->ip_len);
#endif
        inet_ntop(AF_INET, &l_daddr, l_str_daddr, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &l_saddr, l_str_saddr, INET_ADDRSTRLEN);
        log_it(L_DEBUG, "TUN#%u received ip packet %s->%s tot_len: %zu",
               l_tun_socket->worker_id, l_str_saddr, l_str_daddr, l_ip_tot_len);
    }

    if (l_buf_in_size) {
        struct in_addr l_in_daddr;
#ifdef DAP_OS_LINUX
        l_in_daddr.s_addr = iph->daddr;
#else
        l_in_daddr.s_addr = iph->ip_dst.s_addr;
#endif
        dap_chain_net_srv_ch_vpn_info_t *l_vpn_info = NULL;
        
        // Try to find in worker's clients, without locks
        if (l_tun_socket->clients) {
            HASH_FIND_INT(l_tun_socket->clients, &l_in_daddr.s_addr, l_vpn_info);
        }
        
        if (l_vpn_info) {
            if (!l_vpn_info->is_on_this_worker && !l_vpn_info->is_reassigned_once && g_vpn_raw_server->auto_cpu_reassignment) {
                log_it(L_NOTICE, "Reassigning from worker %u to %u", l_vpn_info->worker->id, a_es->worker->id);
                l_vpn_info->is_reassigned_once = true;
                dap_events_socket_reassign_between_workers_mt(l_vpn_info->worker, l_vpn_info->esocket, a_es->worker);
            }
            s_tun_client_send_data(l_vpn_info, a_es->buf_in, l_buf_in_size);
        } else if (g_vpn_debug_more) {
            char l_str_daddr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &l_in_daddr, l_str_daddr, sizeof(l_in_daddr));
            log_it(L_WARNING, "Can't find route for destination %s", l_str_daddr);
        }
        a_es->buf_in_size = 0;
    }
}

/**
 * @brief TUN write callback - writes VPN packets to TUN
 */
bool vpn_srv_es_tun_write(dap_events_socket_t *a_es, void *a_arg)
{
    UNUSED(a_arg);
    
    dap_chain_net_srv_vpn_tun_socket_t *l_tun = CH_SF_TUN_SOCKET(a_es);
    assert(l_tun);
    assert(l_tun->es == a_es);
    
    size_t l_shift = 0;
    debug_if(g_vpn_debug_more, L_DEBUG, "Write %lu bytes to tun", l_tun->es->buf_out_size);
    
    for (ssize_t l_pkt_size = 0, l_bytes_written = 0; l_tun->es->buf_out_size;) {
        dap_stream_ch_vpn_pkt_t *l_vpn_pkt = (dap_stream_ch_vpn_pkt_t *)(l_tun->es->buf_out + l_shift);
        l_pkt_size = l_vpn_pkt->header.op_data.data_size;
        
        debug_if(g_vpn_debug_more, L_DEBUG, "Packet: op_code 0x%02x, data size %ld",
                 l_vpn_pkt->header.op_code, l_pkt_size);
        
        l_bytes_written = write(l_tun->es->fd, l_vpn_pkt->data, l_pkt_size);
        
        if (l_bytes_written == l_pkt_size) {
            l_pkt_size += sizeof(l_vpn_pkt->header);
            l_tun->es->buf_out_size -= l_pkt_size;
            l_shift += l_pkt_size;
        } else {
            int l_errno = errno;
            debug_if(l_bytes_written > 0, L_WARNING,
                     "Error on writing to tun: wrote %zd / %zd bytes", l_bytes_written, l_pkt_size);
            
            switch (l_errno) {
                case EAGAIN:
                    // Unwritten packets remain untouched in buffer
                    break;
                case EINVAL:
                    // Something wrong with this packet, skip it
                    debug_if(g_vpn_debug_more, L_ERROR, "Skip this packet...");
                    l_pkt_size += sizeof(l_vpn_pkt->header);
                    l_tun->es->buf_out_size -= l_pkt_size;
                    l_shift += l_pkt_size;
                    break;
                default:
                    log_it(L_ERROR, "Write to tun error %d: \"%s\"", errno, dap_strerror(errno));
                    break;
            }
            break;
        }
    }
    
    if (l_tun->es->buf_out_size) {
        debug_if(g_vpn_debug_more, L_DEBUG, "Left %lu bytes unwritten", l_tun->es->buf_out_size);
        if (l_shift)
            memmove(l_tun->es->buf_out, &l_tun->es->buf_out[l_shift], l_tun->es->buf_out_size);
    }
    
    l_tun->buf_size_aux = l_tun->es->buf_out_size;  // Backup buffer size
    l_tun->es->buf_out_size = 0;  // Prevent regular writing operations
    
    return false;
}

/**
 * @brief TUN write finished callback - restores buffer size
 */
void vpn_srv_es_tun_write_finished(dap_events_socket_t *a_es, void *a_arg)
{
    UNUSED(a_arg);
    
    dap_chain_net_srv_vpn_tun_socket_t *l_tun = CH_SF_TUN_SOCKET(a_es);
    assert(l_tun);
    assert(l_tun->es == a_es);
    
    l_tun->es->buf_out_size = l_tun->buf_size_aux;  // Restore buffer size
    dap_events_socket_set_writable_unsafe(a_es, l_tun->buf_size_aux > 0);
    debug_if(g_vpn_debug_more && (l_tun->buf_size_aux > 0), L_INFO,
             "%zd bytes still in buf_out, poll again", l_tun->buf_size_aux);
    l_tun->buf_size_aux = 0;
}

/**
 * @brief TUN error callback
 */
void vpn_srv_es_tun_error(dap_events_socket_t *a_es, int a_error)
{
    if (!a_es->_inheritor)
        return;
    
    log_it(L_CRITICAL, "Error %d in socket %"DAP_FORMAT_SOCKET" (socket type %d)",
           a_error, a_es->socket, a_es->type);
}

