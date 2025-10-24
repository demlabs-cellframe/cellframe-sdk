/*
 * Authors:
 * Dmitriy A. Gerasimov <gerasimov.dmitriy@demlabs.net>
 * Cellframe Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2025
 * All rights reserved.
 *
 * This file is part of DAP SDK the open source project
 *
 *    DAP SDK is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *
 *    DAP SDK is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You should have received a copy of the GNU General Public License
 *    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef DAP_OS_WINDOWS

#include <windows.h>
#include <winioctl.h>
#include <iphlpapi.h>
#include <winsock2.h>
#include <ws2ipdef.h>

// WinTun API (requires wintun.dll)
#include <wintun.h>

#include "dap_net_tun.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_worker.h"
#include "dap_events_socket.h"

#define LOG_TAG "dap_net_tun_windows"

#define WINTUN_POOL_NAME L"CellframeVPN"
#define WINTUN_ADAPTER_NAME L"CellframeTUN"

/**
 * @brief Windows-specific TUN device data (WinTun)
 */
typedef struct dap_net_tun_windows {
    WINTUN_ADAPTER_HANDLE *adapters;    // WinTun adapter handles
    WINTUN_SESSION_HANDLE *sessions;    // WinTun session handles
    HANDLE *read_events;                // Read event handles
    dap_events_socket_t **wintun_es;   // Event sockets
} dap_net_tun_windows_t;

/**
 * @brief TUN device internal structure
 */
struct dap_net_tun {
    dap_net_tun_mode_t mode;
    
    struct in_addr network_addr;
    struct in_addr network_mask;
    struct in_addr gateway_addr;
    uint16_t mtu;
    
    uint32_t device_count;
    char **device_names;
    int *device_fds;
    dap_events_socket_t **event_sockets;
    
    dap_worker_t **workers;
    bool workers_allocated_internally;
    
    dap_net_tun_data_callback_t on_data_received;
    dap_net_tun_error_callback_t on_error;
    void *callback_arg;
    
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t packets_sent;
    uint64_t packets_received;
    
    void *platform_data;
};

// WinTun function pointers (loaded from wintun.dll)
static WINTUN_CREATE_ADAPTER_FUNC WintunCreateAdapter = NULL;
static WINTUN_DELETE_ADAPTER_FUNC WintunDeleteAdapter = NULL;
static WINTUN_START_SESSION_FUNC WintunStartSession = NULL;
static WINTUN_END_SESSION_FUNC WintunEndSession = NULL;
static WINTUN_GET_READ_WAIT_EVENT_FUNC WintunGetReadWaitEvent = NULL;
static WINTUN_RECEIVE_PACKET_FUNC WintunReceivePacket = NULL;
static WINTUN_RELEASE_RECEIVE_PACKET_FUNC WintunReleaseReceivePacket = NULL;
static WINTUN_ALLOCATE_SEND_PACKET_FUNC WintunAllocateSendPacket = NULL;
static WINTUN_SEND_PACKET_FUNC WintunSendPacket = NULL;

static HMODULE s_wintun_dll = NULL;
static bool s_wintun_loaded = false;

/**
 * @brief Load WinTun DLL and function pointers
 */
static int s_load_wintun_dll(void)
{
    if (s_wintun_loaded) {
        return 0;
    }
    
    s_wintun_dll = LoadLibraryW(L"wintun.dll");
    if (!s_wintun_dll) {
        log_it(L_ERROR, "Failed to load wintun.dll (error %lu). Ensure WinTun is installed.", GetLastError());
        return -1;
    }
    
    // Load function pointers
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC)GetProcAddress(s_wintun_dll, "WintunCreateAdapter");
    WintunDeleteAdapter = (WINTUN_DELETE_ADAPTER_FUNC)GetProcAddress(s_wintun_dll, "WintunDeleteAdapter");
    WintunStartSession = (WINTUN_START_SESSION_FUNC)GetProcAddress(s_wintun_dll, "WintunStartSession");
    WintunEndSession = (WINTUN_END_SESSION_FUNC)GetProcAddress(s_wintun_dll, "WintunEndSession");
    WintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC)GetProcAddress(s_wintun_dll, "WintunGetReadWaitEvent");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC)GetProcAddress(s_wintun_dll, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC)GetProcAddress(s_wintun_dll, "WintunReleaseReceivePacket");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC)GetProcAddress(s_wintun_dll, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC)GetProcAddress(s_wintun_dll, "WintunSendPacket");
    
    if (!WintunCreateAdapter || !WintunDeleteAdapter || !WintunStartSession || !WintunEndSession ||
        !WintunGetReadWaitEvent || !WintunReceivePacket || !WintunReleaseReceivePacket ||
        !WintunAllocateSendPacket || !WintunSendPacket) {
        log_it(L_ERROR, "Failed to load WinTun function pointers");
        FreeLibrary(s_wintun_dll);
        s_wintun_dll = NULL;
        return -2;
    }
    
    s_wintun_loaded = true;
    log_it(L_NOTICE, "WinTun DLL loaded successfully");
    
    return 0;
}

/**
 * @brief Configure Windows network interface
 */
static int s_configure_wintun_network(dap_net_tun_t *a_tun, WINTUN_ADAPTER_HANDLE a_adapter)
{
    char l_cmd[512];
    char l_str_gw[INET_ADDRSTRLEN];
    char l_str_mask[INET_ADDRSTRLEN];
    
    inet_ntop(AF_INET, &a_tun->gateway_addr, l_str_gw, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &a_tun->network_mask, l_str_mask, INET_ADDRSTRLEN);
    
    // Get adapter LUID for netsh commands
    NET_LUID l_luid;
    WintunGetAdapterLUID(a_adapter, &l_luid);
    
    // Get interface index
    NET_IFINDEX l_if_index;
    if (ConvertInterfaceLuidToIndex(&l_luid, &l_if_index) != NO_ERROR) {
        log_it(L_ERROR, "Failed to get interface index");
        return -1;
    }
    
    // Configure IP address via netsh
    snprintf(l_cmd, sizeof(l_cmd),
             "netsh interface ip set address name=\"%s\" static %s %s",
             a_tun->device_names[0], l_str_gw, l_str_mask);
    
    if (system(l_cmd) != 0) {
        log_it(L_WARNING, "Failed to configure IP address via netsh");
    }
    
    // Set MTU
    snprintf(l_cmd, sizeof(l_cmd),
             "netsh interface ipv4 set subinterface \"%s\" mtu=%u",
             a_tun->device_names[0], a_tun->mtu);
    
    if (system(l_cmd) != 0) {
        log_it(L_WARNING, "Failed to set MTU");
    }
    
    log_it(L_NOTICE, "Configured %s: gw=%s, mask=%s, mtu=%u",
           a_tun->device_names[0], l_str_gw, l_str_mask, a_tun->mtu);
    
    return 0;
}

/**
 * @brief WinTun read thread procedure
 */
static DWORD WINAPI s_wintun_read_thread(LPVOID a_arg)
{
    dap_net_tun_t *l_tun = (dap_net_tun_t *)a_arg;
    dap_net_tun_windows_t *l_win = (dap_net_tun_windows_t *)l_tun->platform_data;
    
    // Note: For multiple adapters, need separate threads
    uint32_t l_device_index = 0;  // Simplified for now
    
    HANDLE l_wait_event = WintunGetReadWaitEvent(l_win->sessions[l_device_index]);
    
    while (true) {
        // Wait for packet
        WaitForSingleObject(l_wait_event, INFINITE);
        
        // Receive packet
        DWORD l_packet_size;
        BYTE *l_packet = WintunReceivePacket(l_win->sessions[l_device_index], &l_packet_size);
        
        if (l_packet) {
            // Update statistics
            l_tun->bytes_received += l_packet_size;
            l_tun->packets_received++;
            
            // Call user callback
            if (l_tun->on_data_received) {
                l_tun->on_data_received(l_tun, l_packet, l_packet_size, l_tun->callback_arg);
            }
            
            // Release packet
            WintunReleaseReceivePacket(l_win->sessions[l_device_index], l_packet);
        }
    }
    
    return 0;
}

/**
 * @brief Initialize TUN device(s)
 */
dap_net_tun_t* dap_net_tun_init(const dap_net_tun_config_t *a_config)
{
    if (!a_config) {
        log_it(L_ERROR, "Config is NULL");
        return NULL;
    }
    
    // Load WinTun DLL
    if (s_load_wintun_dll() < 0) {
        return NULL;
    }
    
    dap_net_tun_t *l_tun = DAP_NEW_Z(dap_net_tun_t);
    if (!l_tun) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    
    // Copy configuration
    l_tun->mode = a_config->mode;
    l_tun->network_addr = a_config->network_addr;
    l_tun->network_mask = a_config->network_mask;
    l_tun->gateway_addr = a_config->gateway_addr;
    l_tun->mtu = a_config->mtu ? a_config->mtu : 1420;  // Lower MTU for WinTun
    l_tun->on_data_received = a_config->on_data_received;
    l_tun->on_error = a_config->on_error;
    l_tun->callback_arg = a_config->callback_arg;
    
    // Create Windows-specific data
    dap_net_tun_windows_t *l_win = DAP_NEW_Z(dap_net_tun_windows_t);
    if (!l_win) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        DAP_DELETE(l_tun);
        return NULL;
    }
    
    l_tun->platform_data = l_win;
    
    // Determine device count
    // Note: WinTun doesn't support true multi-queue like Linux
    // For SERVER mode, create multiple adapters (suboptimal but works)
    if (l_tun->mode == DAP_NET_TUN_MODE_CLIENT) {
        l_tun->device_count = 1;
    } else {
        l_tun->device_count = 1;  // WinTun: single adapter recommended
        log_it(L_INFO, "SERVER mode on Windows: using single WinTun adapter (no native multi-queue)");
    }
    
    // Allocate arrays
    l_tun->device_names = DAP_NEW_Z_SIZE(char*, l_tun->device_count * sizeof(char*));
    l_tun->device_fds = DAP_NEW_Z_SIZE(int, l_tun->device_count * sizeof(int));
    l_tun->event_sockets = DAP_NEW_Z_SIZE(dap_events_socket_t*, l_tun->device_count * sizeof(dap_events_socket_t*));
    l_win->adapters = DAP_NEW_Z_SIZE(WINTUN_ADAPTER_HANDLE, l_tun->device_count * sizeof(WINTUN_ADAPTER_HANDLE));
    l_win->sessions = DAP_NEW_Z_SIZE(WINTUN_SESSION_HANDLE, l_tun->device_count * sizeof(WINTUN_SESSION_HANDLE));
    l_win->read_events = DAP_NEW_Z_SIZE(HANDLE, l_tun->device_count * sizeof(HANDLE));
    
    if (!l_tun->device_names || !l_win->adapters || !l_win->sessions || !l_win->read_events) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    // Create WinTun adapter(s)
    for (uint32_t i = 0; i < l_tun->device_count; i++) {
        GUID l_guid;
        CoCreateGuid(&l_guid);
        
        WINTUN_ADAPTER_HANDLE l_adapter = WintunCreateAdapter(
            WINTUN_ADAPTER_NAME,
            WINTUN_POOL_NAME,
            &l_guid
        );
        
        if (!l_adapter) {
            log_it(L_ERROR, "WintunCreateAdapter failed (error %lu)", GetLastError());
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        l_win->adapters[i] = l_adapter;
        l_tun->device_names[i] = dap_strdup("CellframeTUN");  // WinTun adapter name
        
        // Start session
        l_win->sessions[i] = WintunStartSession(l_adapter, 0x400000);  // 4MB ring buffer
        if (!l_win->sessions[i]) {
            log_it(L_ERROR, "WintunStartSession failed (error %lu)", GetLastError());
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        // Get read wait event
        l_win->read_events[i] = WintunGetReadWaitEvent(l_win->sessions[i]);
        
        log_it(L_INFO, "Created WinTun adapter #%u: %s", i, l_tun->device_names[i]);
        
        // Create read thread for this adapter
        HANDLE l_thread = CreateThread(NULL, 0, s_wintun_read_thread, l_tun, 0, NULL);
        if (!l_thread) {
            log_it(L_ERROR, "Failed to create read thread (error %lu)", GetLastError());
            dap_net_tun_deinit(l_tun);
            return NULL;
        }
        
        CloseHandle(l_thread);  // Detach thread
    }
    
    // Configure network
    if (s_configure_wintun_network(l_tun, l_win->adapters[0]) < 0) {
        log_it(L_ERROR, "Failed to configure WinTun network");
        dap_net_tun_deinit(l_tun);
        return NULL;
    }
    
    log_it(L_NOTICE, "WinTun initialized: mode=%s, adapters=%u",
           l_tun->mode == DAP_NET_TUN_MODE_CLIENT ? "CLIENT" : "SERVER",
           l_tun->device_count);
    
    return l_tun;
}

/**
 * @brief Deinitialize TUN device(s)
 */
void dap_net_tun_deinit(dap_net_tun_t *a_tun)
{
    if (!a_tun)
        return;
    
    dap_net_tun_windows_t *l_win = (dap_net_tun_windows_t *)a_tun->platform_data;
    
    if (l_win) {
        // End sessions
        if (l_win->sessions) {
            for (uint32_t i = 0; i < a_tun->device_count; i++) {
                if (l_win->sessions[i]) {
                    WintunEndSession(l_win->sessions[i]);
                }
            }
            DAP_DELETE(l_win->sessions);
        }
        
        // Delete adapters
        if (l_win->adapters) {
            for (uint32_t i = 0; i < a_tun->device_count; i++) {
                if (l_win->adapters[i]) {
                    WintunDeleteAdapter(l_win->adapters[i]);
                }
            }
            DAP_DELETE(l_win->adapters);
        }
        
        DAP_DELETE(l_win->read_events);
        DAP_DELETE(l_win->wintun_es);
        DAP_DELETE(l_win);
    }
    
    // Free device names
    if (a_tun->device_names) {
        for (uint32_t i = 0; i < a_tun->device_count; i++) {
            DAP_DELETE(a_tun->device_names[i]);
        }
        DAP_DELETE(a_tun->device_names);
    }
    
    DAP_DELETE(a_tun->device_fds);
    DAP_DELETE(a_tun->event_sockets);
    DAP_DELETE(a_tun);
    
    log_it(L_INFO, "WinTun device deinitialized");
}

/**
 * @brief Write data to WinTun device
 */
ssize_t dap_net_tun_write(dap_net_tun_t *a_tun, const void *a_data, size_t a_data_size)
{
    if (!a_tun || !a_data || a_data_size == 0) {
        return -1;
    }
    
    dap_net_tun_windows_t *l_win = (dap_net_tun_windows_t *)a_tun->platform_data;
    if (!l_win) {
        return -2;
    }
    
    // Select device (only 1 for WinTun)
    uint32_t l_device_index = 0;
    
    // Allocate send packet
    BYTE *l_packet = WintunAllocateSendPacket(l_win->sessions[l_device_index], (DWORD)a_data_size);
    if (!l_packet) {
        log_it(L_WARNING, "WintunAllocateSendPacket failed (error %lu)", GetLastError());
        return -3;
    }
    
    // Copy data
    memcpy(l_packet, a_data, a_data_size);
    
    // Send packet
    WintunSendPacket(l_win->sessions[l_device_index], l_packet);
    
    // Update statistics
    a_tun->bytes_sent += a_data_size;
    a_tun->packets_sent++;
    
    return (ssize_t)a_data_size;
}

/**
 * @brief Get device name
 */
const char* dap_net_tun_get_device_name(dap_net_tun_t *a_tun, uint32_t a_device_index)
{
    if (!a_tun || a_device_index >= a_tun->device_count) {
        return NULL;
    }
    
    return a_tun->device_names[a_device_index];
}

/**
 * @brief Get device count
 */
uint32_t dap_net_tun_get_device_count(dap_net_tun_t *a_tun)
{
    return a_tun ? a_tun->device_count : 0;
}

/**
 * @brief Get statistics
 */
int dap_net_tun_get_stats(
    dap_net_tun_t *a_tun,
    uint64_t *a_bytes_sent,
    uint64_t *a_bytes_received,
    uint64_t *a_packets_sent,
    uint64_t *a_packets_received)
{
    if (!a_tun) {
        return -1;
    }
    
    if (a_bytes_sent) *a_bytes_sent = a_tun->bytes_sent;
    if (a_bytes_received) *a_bytes_received = a_tun->bytes_received;
    if (a_packets_sent) *a_packets_sent = a_tun->packets_sent;
    if (a_packets_received) *a_packets_received = a_tun->packets_received;
    
    return 0;
}

/**
 * @brief Get file descriptor (not applicable for WinTun - returns -1)
 */
int dap_net_tun_get_fd(dap_net_tun_t *a_tun, uint32_t a_device_index)
{
    UNUSED(a_tun);
    UNUSED(a_device_index);
    // WinTun doesn't use traditional file descriptors
    return -1;
}

/**
 * @brief Get mode
 */
dap_net_tun_mode_t dap_net_tun_get_mode(dap_net_tun_t *a_tun)
{
    return a_tun ? a_tun->mode : DAP_NET_TUN_MODE_CLIENT;
}

#endif // DAP_OS_WINDOWS

