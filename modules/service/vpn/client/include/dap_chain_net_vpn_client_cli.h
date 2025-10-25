/**
 * @file dap_chain_net_vpn_client_cli.h
 * @brief VPN Client CLI commands for Cellframe Node
 * @details Provides standalone CLI commands for VPN client functionality within cellframe-node-cli
 * 
 * Supports:
 * - cellframe-node-cli vpn_client connect [options]
 * - cellframe-node-cli vpn_client disconnect
 * - cellframe-node-cli vpn_client status
 * - cellframe-node-cli vpn_client config
 * - Full wallet integration
 * - Automatic node selection
 * - Multi-hop routing
 * 
 * @date 2025-10-23
 * @author Cellframe Development Team
 */

#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_chain_net.h"
#include "dap_chain_wallet.h"
#include "dap_cli_server.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief VPN connection parameters for CLI
 */
typedef struct dap_chain_net_vpn_client_cli_connect_params {
    // Network and server
    dap_chain_net_t *net;                               // Cellframe network
    const char *server_addr;                            // Server address (or NULL for auto-select)
    uint16_t server_port;                               // Server port (0 for default)
    
    // Payment
    dap_chain_wallet_t *wallet;                         // Wallet for payment
    const char *payment_token;                          // Token ticker for payment
    uint256_t payment_amount;                           // Payment amount
    const char *payment_tx_hash;                        // Payment transaction hash (if pre-paid)
    
    // Routing
    bool notable;                                       // Do not modify routing table
    bool nodns;                                         // Do not modify DNS settings
    bool multi_hop;                                     // Enable multi-hop routing
    const char *multi_hop_route;                        // Comma-separated node addresses
    
    // Transport and obfuscation
    const char *transport_type;                         // Transport type (udp, ws, etc)
    const char *obfuscation_mode;                       // Obfuscation mode (mimicry, padding, etc)
    
    // Auto-selection criteria
    const char *auto_select_criteria;                   // "speed", "security", "cost", "brevity"
    uint32_t auto_select_timeout_ms;                    // Timeout for node selection
} dap_chain_net_vpn_client_cli_connect_params_t;

/**
 * @brief VPN client CLI configuration
 */
typedef struct dap_chain_net_vpn_client_cli_config {
    bool enable_auto_reconnect;                         // Auto-reconnect on connection loss
    uint32_t reconnect_interval_sec;                    // Reconnect interval in seconds
    bool enable_stats_logging;                          // Log statistics periodically
    uint32_t stats_log_interval_sec;                    // Stats logging interval
    const char *default_transport;                      // Default transport type
    const char *default_obfuscation;                    // Default obfuscation mode
} dap_chain_net_vpn_client_cli_config_t;

// --- Initialization ---

/**
 * @brief Initialize VPN client CLI module
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_init();

/**
 * @brief Deinitialize VPN client CLI module
 */
void dap_chain_net_vpn_client_cli_deinit();

// --- CLI Commands ---

/**
 * @brief Register VPN client CLI commands
 * @details Registers all VPN client commands with dap_cli_server
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_register_commands();

/**
 * @brief CLI command: vpn_client connect
 * @param argc Argument count
 * @param argv Argument values
 * @param arg_func Argument parsing function
 * @param str_reply Output string for reply
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_cmd_connect(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief CLI command: vpn_client disconnect
 * @param argc Argument count
 * @param argv Argument values
 * @param arg_func Argument parsing function
 * @param str_reply Output string for reply
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_cmd_disconnect(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief CLI command: vpn_client status
 * @param argc Argument count
 * @param argv Argument values
 * @param arg_func Argument parsing function
 * @param str_reply Output string for reply
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_cmd_status(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief CLI command: vpn_client config
 * @param argc Argument count
 * @param argv Argument values
 * @param arg_func Argument parsing function
 * @param str_reply Output string for reply
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_cmd_config(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief CLI command: vpn_client wallet
 * @param argc Argument count
 * @param argv Argument values
 * @param str_reply Output string for reply
 * @param a_version Protocol version
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_cmd_wallet(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief CLI command: vpn_client network
 * @param argc Argument count
 * @param argv Argument values
 * @param str_reply Output string for reply
 * @param a_version Protocol version
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_cmd_network(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief Main CLI command router for vpn_client
 * @param argc Argument count
 * @param argv Argument values  
 * @param str_reply Output string for reply
 * @param a_version Protocol version
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_cmd(int argc, char **argv, void **str_reply, int a_version);

// --- Helper Functions ---

/**
 * @brief Parse connection parameters from CLI arguments
 * @param argc Argument count
 * @param argv Argument values
 * @param a_params Output connection parameters
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_parse_connect_params(int argc, char **argv,
                                                        dap_chain_net_vpn_client_cli_connect_params_t *a_params);

/**
 * @brief Get wallet by name or address
 * @param wallet_name Wallet name or address
 * @return Wallet pointer or NULL if not found
 */
dap_chain_wallet_t* dap_chain_net_vpn_client_cli_get_wallet(const char *wallet_name);

/**
 * @brief Select optimal VPN node automatically
 * @param net Network
 * @param criteria Selection criteria ("speed", "security", "cost", "brevity")
 * @param timeout_ms Timeout for selection
 * @param out_addr Output server address
 * @param out_port Output server port
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_auto_select_node(dap_chain_net_t *net,
                                                    const char *criteria,
                                                    uint32_t timeout_ms,
                                                    char **out_addr,
                                                    uint16_t *out_port);

/**
 * @brief Create payment transaction for VPN service
 * @param wallet Wallet for payment
 * @param net Network
 * @param token Token ticker
 * @param amount Payment amount
 * @param server_addr Server address
 * @param out_tx_hash Output transaction hash
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_create_payment(dap_chain_wallet_t *wallet,
                                                  dap_chain_net_t *net,
                                                  const char *token,
                                                  uint256_t amount,
                                                  const char *server_addr,
                                                  char **out_tx_hash);

/**
 * @brief Format connection status for CLI output
 * @param status Connection status
 * @param out_str Output formatted string
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_format_status(const void *status, char **out_str);

/**
 * @brief Format statistics for CLI output
 * @param stats Statistics structure
 * @param out_str Output formatted string
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_format_stats(const void *stats, char **out_str);

// --- Configuration ---

/**
 * @brief Load CLI configuration from file
 * @param config_path Path to configuration file
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_load_config(const char *config_path);

/**
 * @brief Save CLI configuration to file
 * @param config_path Path to configuration file
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_save_config(const char *config_path);

/**
 * @brief Get current CLI configuration
 * @return Pointer to configuration structure
 */
const dap_chain_net_vpn_client_cli_config_t* dap_chain_net_vpn_client_cli_get_config();

/**
 * @brief Set CLI configuration
 * @param config New configuration
 * @return 0 on success, negative error code otherwise
 */
int dap_chain_net_vpn_client_cli_set_config(const dap_chain_net_vpn_client_cli_config_t *config);

#ifdef __cplusplus
}
#endif

