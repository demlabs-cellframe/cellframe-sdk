/**
 * @file dap_chain_net_vpn_client_backup.h
 * @brief VPN Client Network Configuration Backup and Restore
 *
 * Provides persistent backup/restore functionality for network configuration
 * to handle daemon crashes gracefully without leaking network settings.
 *
 * @date 2025-10-23
 * @copyright (c) 2025 Cellframe Network
 */

#pragma once

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Default backup file path
 */
#define DAP_CHAIN_NET_VPN_CLIENT_BACKUP_FILE "/opt/cellframe-vpn-client/var/lib/network.backup"

/**
 * @brief Network configuration backup structure
 *
 * Contains all necessary information to restore original network configuration
 * after VPN disconnect or daemon crash.
 */
typedef struct dap_chain_net_vpn_client_backup {
    // Metadata
    int64_t timestamp;              // Unix timestamp of backup creation
    char *platform;                 // "linux", "macos", "windows"
    char *connection_state;         // "connecting", "connected", "disconnecting"
    bool backup_valid;              // Is this backup valid for restore?
    
    // VPN connection info
    char *vpn_server_ip;            // VPN server IP address
    char *vpn_interface;            // VPN tunnel interface name (e.g., "tun0")
    char *vpn_gateway;              // VPN gateway IP (optional)
    
    // Original network configuration
    char *original_gateway;         // Original default gateway IP
    char *original_interface;       // Original default interface name
    char *original_metric;          // Original route metric (Linux, optional)
    
    // DNS configuration
    size_t original_dns_count;      // Number of original DNS servers
    char **original_dns_servers;    // Array of original DNS server IPs
    size_t original_search_domains_count;
    char **original_search_domains; // Array of original search domains
    
    // Platform-specific data
    char *original_resolv_conf;     // Full /etc/resolv.conf content (Linux)
    char *network_service;          // Network service name (macOS)
    uint32_t interface_index;       // Interface index (Windows)
    
    // Opaque platform-specific backup data
    void *platform_specific_backup; // Platform backup structure
} dap_chain_net_vpn_client_backup_t;

/**
 * @brief Create a new backup structure
 * @return Allocated backup structure or NULL on error
 */
dap_chain_net_vpn_client_backup_t* dap_chain_net_vpn_client_backup_new(void);

/**
 * @brief Free backup structure and all its fields
 * @param a_backup Backup structure to free
 */
void dap_chain_net_vpn_client_backup_free(dap_chain_net_vpn_client_backup_t *a_backup);

/**
 * @brief Save backup structure to JSON file
 * @param a_backup Backup structure to save
 * @param a_path File path (if NULL, uses default path)
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_backup_save(const dap_chain_net_vpn_client_backup_t *a_backup, 
                                          const char *a_path);

/**
 * @brief Load backup structure from JSON file
 * @param a_path File path (if NULL, uses default path)
 * @param a_out_backup Output pointer for loaded backup
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_backup_load(const char *a_path,
                                          dap_chain_net_vpn_client_backup_t **a_out_backup);

/**
 * @brief Validate backup structure
 * @param a_backup Backup structure to validate
 * @return true if backup is valid and can be restored, false otherwise
 */
bool dap_chain_net_vpn_client_backup_validate(const dap_chain_net_vpn_client_backup_t *a_backup);

/**
 * @brief Remove backup file
 * @param a_path File path (if NULL, uses default path)
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_backup_remove(const char *a_path);

/**
 * @brief Check if backup file exists
 * @param a_path File path (if NULL, uses default path)
 * @return true if file exists, false otherwise
 */
bool dap_chain_net_vpn_client_backup_exists(const char *a_path);

/**
 * @brief Auto-restore network configuration if backup exists (crash recovery)
 *
 * This function should be called on daemon startup. If a valid backup file exists,
 * it means the daemon crashed previously without proper cleanup. This function will:
 * 1. Load the backup
 * 2. Validate it
 * 3. Restore original network configuration
 * 4. Remove the backup file
 *
 * @return 0 if no restore needed or restore successful, negative on error
 */
int dap_chain_net_vpn_client_backup_auto_restore(void);

/**
 * @brief Create backup directory if it doesn't exist
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_backup_ensure_dir(void);

/**
 * @brief Get backup file path
 * @param a_custom_path Custom path or NULL for default
 * @return Backup file path (caller should not free)
 */
const char* dap_chain_net_vpn_client_backup_get_path(const char *a_custom_path);

#ifdef __cplusplus
} // extern "C"
#endif

