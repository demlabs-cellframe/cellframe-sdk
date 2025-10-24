/**
 * @file dap_chain_net_vpn_client_cli.c
 * @brief VPN Client CLI commands implementation
 * @date 2025-10-23
 */

#include "dap_chain_net_vpn_client_cli.h"
#include "dap_chain_net_vpn_client_service.h"
#include "dap_chain_net_vpn_client_auto.h"
#include "dap_chain_net_vpn_client_payment.h"
#include "dap_vpn_client_wallet.h"
#include "dap_vpn_client_network_registry.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_srv.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_string.h"
#include "dap_cli_server.h"
#include <string.h>

#define LOG_TAG "dap_chain_net_vpn_client_cli"

// Global configuration
static dap_chain_net_vpn_client_cli_config_t s_config = {
    .enable_auto_reconnect = true,
    .reconnect_interval_sec = 30,
    .enable_stats_logging = false,
    .stats_log_interval_sec = 60,
    .default_transport = "udp",
    .default_obfuscation = "mimicry"
};

static bool s_initialized = false;

//=============================================================================
// Initialization
//=============================================================================

int dap_chain_net_vpn_client_cli_init() {
    if (s_initialized) {
        log_it(L_WARNING, "VPN client CLI already initialized");
        return -1;
    }
    
    // Initialize daemon core if not yet initialized
    // (daemon is embedded in node process, not separate)
    
    s_initialized = true;
    log_it(L_INFO, "VPN client CLI initialized");
    
    return 0;
}

void dap_chain_net_vpn_client_cli_deinit() {
    if (!s_initialized) return;
    
    s_initialized = false;
    log_it(L_INFO, "VPN client CLI deinitialized");
}

int dap_chain_net_vpn_client_cli_register_commands() {
    if (!s_initialized) {
        log_it(L_ERROR, "VPN client CLI not initialized");
        return -1;
    }
    
    // Register single vpn_client command with subcommand routing
    dap_cli_server_cmd_add("vpn_client", dap_chain_net_vpn_client_cli_cmd, NULL,
                            "VPN client control",
                            "vpn_client <subcommand> [options]\n"
                            "Subcommands:\n"
                            "  connect    - Connect to VPN server\n"
                            "    Usage: vpn_client connect -net <network> [-server <addr:port>] -wallet <name> -token <ticker> -amount <value>\n"
                            "           [-notable] [-nodns] [-multihop <route>] [-transport <type>] [-obfuscation <mode>] [-criteria <criteria>]\n"
                            "  disconnect - Disconnect from VPN server\n"
                            "    Usage: vpn_client disconnect\n"
                            "  status     - Show VPN connection status\n"
                            "    Usage: vpn_client status [-verbose]\n"
                            "  config     - Configure VPN client\n"
                            "    Usage: vpn_client config [-get <param>] [-set <param> <value>] [-reset]\n"
                            "  wallet     - Wallet management\n"
                            "    Subcommands:\n"
                            "      create <name> [sig_type]  - Create new wallet\n"
                            "      list                       - List all wallets\n"
                            "      balance <name> <network> <token> - Show wallet balance\n"
                            "      address <name> <network>   - Get wallet address\n"
                            "  network    - Network registry management\n"
                            "    Subcommands:\n"
                            "      list        - List all networks\n"
                            "      list-enabled - List enabled networks");
    
    log_it(L_INFO, "VPN client CLI command registered");
    
    return 0;
}

// --- CLI Commands ---

/**
 * @brief Main VPN client CLI command router
 * Parses subcommands and routes to appropriate handlers
 */
int dap_chain_net_vpn_client_cli_cmd(int argc, char **argv, void **str_reply, int a_version) {
    if (argc < 2) {
        dap_cli_server_cmd_set_reply_text(str_reply, 
            "Error: Missing subcommand\n"
            "Usage: vpn_client <subcommand> [options]\n"
            "Subcommands: connect, disconnect, status, config\n"
            "Use 'help vpn_client' for details");
        return -1;
    }
    
    const char *l_subcmd = argv[1];
    
    // Route to appropriate subcommand handler
    if (strcmp(l_subcmd, "connect") == 0) {
        return dap_chain_net_vpn_client_cli_cmd_connect(argc - 1, argv + 1, str_reply, a_version);
    } else if (strcmp(l_subcmd, "disconnect") == 0) {
        return dap_chain_net_vpn_client_cli_cmd_disconnect(argc - 1, argv + 1, str_reply, a_version);
    } else if (strcmp(l_subcmd, "status") == 0) {
        return dap_chain_net_vpn_client_cli_cmd_status(argc - 1, argv + 1, str_reply, a_version);
    } else if (strcmp(l_subcmd, "config") == 0) {
        return dap_chain_net_vpn_client_cli_cmd_config(argc - 1, argv + 1, str_reply, a_version);
    } else if (strcmp(l_subcmd, "wallet") == 0) {
        return dap_chain_net_vpn_client_cli_cmd_wallet(argc - 1, argv + 1, str_reply, a_version);
    } else if (strcmp(l_subcmd, "network") == 0) {
        return dap_chain_net_vpn_client_cli_cmd_network(argc - 1, argv + 1, str_reply, a_version);
    } else {
        dap_cli_server_cmd_set_reply_text(str_reply, 
            "Error: Unknown subcommand '%s'\n"
            "Available subcommands: connect, disconnect, status, config, wallet, network", l_subcmd);
        return -1;
    }
}

int dap_chain_net_vpn_client_cli_cmd_connect(int argc, char **argv, void **str_reply, int a_version) {
    UNUSED(a_version);
    
    if (!s_initialized) {
        dap_cli_server_cmd_set_reply_text(str_reply, "VPN client CLI not initialized");
        return -1;
    }
    
    // Parse connection parameters
    dap_chain_net_vpn_client_cli_connect_params_t params = {0};
    
    if (dap_chain_net_vpn_client_cli_parse_connect_params(argc, argv, &params) != 0) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to parse connection parameters. Use 'vpn_client connect -h' for help");
        return -2;
    }
    
    // Validate required parameters
    if (!params.net) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Network not specified. Use -net option");
        return -3;
    }
    
    if (!params.wallet && !params.payment_tx_hash) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Wallet or payment transaction hash required");
        return -4;
    }
    
    // Auto-select node if server not specified
    if (!params.server_addr) {
        char *l_addr = NULL;
        uint16_t l_port = 0;
        
        const char *l_criteria = params.auto_select_criteria ? params.auto_select_criteria : "speed";
        uint32_t l_timeout = params.auto_select_timeout_ms > 0 ? params.auto_select_timeout_ms : 10000;
        
        if (dap_chain_net_vpn_client_cli_auto_select_node(params.net, l_criteria, l_timeout,
                                                           &l_addr, &l_port) != 0) {
            dap_cli_server_cmd_set_reply_text(str_reply, "Failed to auto-select VPN node");
            return -5;
        }
        
        params.server_addr = l_addr;
        params.server_port = l_port;
        
        log_it(L_INFO, "Auto-selected VPN node: %s:%u (criteria: %s)", l_addr, l_port, l_criteria);
    }
    
    // Create payment transaction if not pre-paid
    char *l_tx_hash = NULL;
    if (!params.payment_tx_hash) {
        if (dap_chain_net_vpn_client_cli_create_payment(params.wallet, params.net,
                                                          params.payment_token, params.payment_amount,
                                                          params.server_addr, &l_tx_hash) != 0) {
            dap_cli_server_cmd_set_reply_text(str_reply, "Failed to create payment transaction");
            return -6;
        }
        
        params.payment_tx_hash = l_tx_hash;
        log_it(L_INFO, "Created payment transaction: %s", l_tx_hash);
    }
    
    // Prepare configuration
    dap_chain_net_vpn_client_config_t config = {
        .server_host = dap_strdup(params.server_addr),
        .server_port = params.server_port,
        .network_name = dap_strdup(params.net->pub.name),
        .enable_routing = !params.notable,
        .enable_dns_override = !params.nodns,
        .transport_type = params.transport_type ? dap_strdup(params.transport_type) : dap_strdup(s_config.default_transport),
        .obfuscation_mode = params.obfuscation_mode ? dap_strdup(params.obfuscation_mode) : dap_strdup(s_config.default_obfuscation),
        .multi_hop_enabled = params.multi_hop,
        .multi_hop_route = params.multi_hop_route ? dap_strdup(params.multi_hop_route) : NULL,
        .auto_reconnect = s_config.enable_auto_reconnect,
        .reconnect_interval_ms = s_config.reconnect_interval_sec * 1000
    };
    
    // Prepare payment configuration (always paid mode for client)
    dap_chain_net_vpn_client_payment_config_t l_payment_config;
    if (dap_chain_net_vpn_client_payment_config_init(&l_payment_config, params.payment_tx_hash, 
                                                       params.net ? params.net->pub.name : NULL) != 0) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to initialize payment configuration");
        DAP_DELETE(l_tx_hash);
        return -7;
    }
    
    // Initiate connection via global service instance
    dap_chain_net_vpn_client_service_t *l_service = dap_chain_net_vpn_client_service_get_instance();
    if (!l_service) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to get VPN service instance");
        DAP_DELETE(l_tx_hash);
        return -8;
    }
    
    // Connect via service
    int l_ret = dap_chain_net_vpn_client_service_connect(l_service, &config);
    if (l_ret != 0) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to initiate VPN connection");
        DAP_DELETE(l_tx_hash);
        return -9;
    }
    
    dap_string_t *l_reply = dap_string_new(NULL);
    dap_string_append_printf(l_reply, "VPN connection initiated successfully:\n");
    dap_string_append_printf(l_reply, "  Network: %s\n", params.net->pub.name);
    dap_string_append_printf(l_reply, "  Server: %s:%u\n", params.server_addr, params.server_port);
    dap_string_append_printf(l_reply, "  Payment TX: %s\n", params.payment_tx_hash);
    dap_string_append_printf(l_reply, "  Transport: %s\n", config.transport_type);
    dap_string_append_printf(l_reply, "  Obfuscation: %s\n", config.obfuscation_mode);
    
    if (params.multi_hop) {
        dap_string_append_printf(l_reply, "  Multi-hop: enabled (%s)\n", 
                                  params.multi_hop_route ? params.multi_hop_route : "auto");
    }
    
    dap_cli_server_cmd_set_reply_text(str_reply, l_reply->str);
    dap_string_free(l_reply, true);
    
    // Cleanup
    DAP_DELETE(l_tx_hash);
    
    return 0;
}

int dap_chain_net_vpn_client_cli_cmd_disconnect(int argc, char **argv, void **str_reply, int a_version) {
    UNUSED(argc);
    UNUSED(argv);
    UNUSED(a_version);
    
    if (!s_initialized) {
        dap_cli_server_cmd_set_reply_text(str_reply, "VPN client CLI not initialized");
        return -1;
    }
    
    // Get service instance and disconnect
    dap_chain_net_vpn_client_service_t *l_service = dap_chain_net_vpn_client_service_get_instance();
    if (!l_service) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to get VPN service instance");
        return -2;
    }
    
    int l_ret = dap_chain_net_vpn_client_service_disconnect(l_service);
    if (l_ret != 0) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to disconnect from VPN");
        return -3;
    }
    
    dap_cli_server_cmd_set_reply_text(str_reply, "VPN disconnect initiated successfully");
    
    return 0;
}

int dap_chain_net_vpn_client_cli_cmd_status(int argc, char **argv, void **str_reply, int a_version) {
    UNUSED(a_version);
    UNUSED(argc);
    UNUSED(argv);
    
    if (!s_initialized) {
        dap_cli_server_cmd_set_reply_text(str_reply, "VPN client CLI not initialized");
        return -1;
    }
    
    // Get service instance and status
    dap_chain_net_vpn_client_service_t *l_service = dap_chain_net_vpn_client_service_get_instance();
    if (!l_service) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to get VPN service instance");
        return -2;
    }
    
    dap_chain_net_vpn_client_service_status_t l_status = {0};
    int l_ret = dap_chain_net_vpn_client_service_get_status(l_service, &l_status);
    if (l_ret != 0) {
        dap_cli_server_cmd_set_reply_text(str_reply, "Failed to get VPN status");
        return -3;
    }
    
    dap_string_t *l_reply = dap_string_new(NULL);
    dap_string_append_printf(l_reply, "VPN Status:\n");
    dap_string_append_printf(l_reply, "  State: %s\n", 
                            dap_chain_net_vpn_client_service_state_to_string(l_status.state));
    
    if (l_status.server_host) {
        dap_string_append_printf(l_reply, "  Server: %s:%u\n", l_status.server_host, l_status.server_port);
    }
    
    if (l_status.uptime_seconds > 0) {
        uint64_t hours = l_status.uptime_seconds / 3600;
        uint64_t minutes = (l_status.uptime_seconds % 3600) / 60;
        uint64_t seconds = l_status.uptime_seconds % 60;
        dap_string_append_printf(l_reply, "  Uptime: %02lu:%02lu:%02lu\n", 
                                (unsigned long)hours, (unsigned long)minutes, (unsigned long)seconds);
    }
    
    dap_string_append_printf(l_reply, "  Traffic:\n");
    dap_string_append_printf(l_reply, "    Sent: %lu bytes (%lu packets)\n", 
                            (unsigned long)l_status.bytes_sent, (unsigned long)l_status.packets_sent);
    dap_string_append_printf(l_reply, "    Received: %lu bytes (%lu packets)\n", 
                            (unsigned long)l_status.bytes_received, (unsigned long)l_status.packets_received);
    
    if (l_status.reconnect_attempt > 0) {
        dap_string_append_printf(l_reply, "  Reconnect attempts: %u\n", l_status.reconnect_attempt);
    }
    
    dap_cli_server_cmd_set_reply_text(str_reply, l_reply->str);
    dap_string_free(l_reply, true);
    
    // Free status fields
    if (l_status.server_host) {
        DAP_DELETE(l_status.server_host);
    }
    
    return 0;
}

int dap_chain_net_vpn_client_cli_cmd_config(int argc, char **argv, void **str_reply, int a_version) {
    UNUSED(a_version);
    
    if (!s_initialized) {
        dap_cli_server_cmd_set_reply_text(str_reply, "VPN client CLI not initialized");
        return -1;
    }
    
    // Parse config command arguments
    const char *l_get_param = NULL;
    const char *l_set_param = NULL;
    const char *l_set_value = NULL;
    bool l_reset = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-get") == 0 && i + 1 < argc) {
            l_get_param = argv[++i];
        } else if (strcmp(argv[i], "-set") == 0 && i + 2 < argc) {
            l_set_param = argv[++i];
            l_set_value = argv[++i];
        } else if (strcmp(argv[i], "-reset") == 0) {
            l_reset = true;
        }
    }
    
    dap_string_t *l_reply = dap_string_new(NULL);
    
    if (l_reset) {
        // Reset to defaults
        s_config.enable_auto_reconnect = true;
        s_config.reconnect_interval_sec = 30;
        s_config.enable_stats_logging = false;
        s_config.stats_log_interval_sec = 60;
        s_config.default_transport = "udp";
        s_config.default_obfuscation = "mimicry";
        
        dap_string_append(l_reply, "Configuration reset to defaults\n");
    } else if (l_set_param && l_set_value) {
        // Set parameter
        if (strcmp(l_set_param, "auto_reconnect") == 0) {
            s_config.enable_auto_reconnect = (strcmp(l_set_value, "true") == 0 || strcmp(l_set_value, "1") == 0);
            dap_string_append_printf(l_reply, "auto_reconnect = %s\n", s_config.enable_auto_reconnect ? "true" : "false");
        } else if (strcmp(l_set_param, "reconnect_interval") == 0) {
            s_config.reconnect_interval_sec = atoi(l_set_value);
            dap_string_append_printf(l_reply, "reconnect_interval = %u sec\n", s_config.reconnect_interval_sec);
        } else if (strcmp(l_set_param, "stats_logging") == 0) {
            s_config.enable_stats_logging = (strcmp(l_set_value, "true") == 0 || strcmp(l_set_value, "1") == 0);
            dap_string_append_printf(l_reply, "stats_logging = %s\n", s_config.enable_stats_logging ? "true" : "false");
        } else if (strcmp(l_set_param, "default_transport") == 0) {
            s_config.default_transport = l_set_value;
            dap_string_append_printf(l_reply, "default_transport = %s\n", s_config.default_transport);
        } else if (strcmp(l_set_param, "default_obfuscation") == 0) {
            s_config.default_obfuscation = l_set_value;
            dap_string_append_printf(l_reply, "default_obfuscation = %s\n", s_config.default_obfuscation);
        } else {
            dap_string_append_printf(l_reply, "Unknown parameter: %s\n", l_set_param);
        }
    } else if (l_get_param) {
        // Get specific parameter
        if (strcmp(l_get_param, "auto_reconnect") == 0) {
            dap_string_append_printf(l_reply, "auto_reconnect = %s\n", s_config.enable_auto_reconnect ? "true" : "false");
        } else if (strcmp(l_get_param, "reconnect_interval") == 0) {
            dap_string_append_printf(l_reply, "reconnect_interval = %u sec\n", s_config.reconnect_interval_sec);
        } else if (strcmp(l_get_param, "stats_logging") == 0) {
            dap_string_append_printf(l_reply, "stats_logging = %s\n", s_config.enable_stats_logging ? "true" : "false");
        } else if (strcmp(l_get_param, "default_transport") == 0) {
            dap_string_append_printf(l_reply, "default_transport = %s\n", s_config.default_transport);
        } else if (strcmp(l_get_param, "default_obfuscation") == 0) {
            dap_string_append_printf(l_reply, "default_obfuscation = %s\n", s_config.default_obfuscation);
        } else {
            dap_string_append_printf(l_reply, "Unknown parameter: %s\n", l_get_param);
        }
    } else {
        // Show all configuration
        dap_string_append(l_reply, "VPN Client Configuration:\n");
        dap_string_append_printf(l_reply, "  auto_reconnect: %s\n", s_config.enable_auto_reconnect ? "true" : "false");
        dap_string_append_printf(l_reply, "  reconnect_interval: %u sec\n", s_config.reconnect_interval_sec);
        dap_string_append_printf(l_reply, "  stats_logging: %s\n", s_config.enable_stats_logging ? "true" : "false");
        dap_string_append_printf(l_reply, "  stats_log_interval: %u sec\n", s_config.stats_log_interval_sec);
        dap_string_append_printf(l_reply, "  default_transport: %s\n", s_config.default_transport);
        dap_string_append_printf(l_reply, "  default_obfuscation: %s\n", s_config.default_obfuscation);
    }
    
    dap_cli_server_cmd_set_reply_text(str_reply, l_reply->str);
    dap_string_free(l_reply, true);
    
    return 0;
}

// --- Helper Functions ---

int dap_chain_net_vpn_client_cli_parse_connect_params(int argc, char **argv,
                                                        dap_chain_net_vpn_client_cli_connect_params_t *a_params) {
    
    if (!a_params) return -1;
    
    memset(a_params, 0, sizeof(*a_params));
    
    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-net") == 0 && i + 1 < argc) {
            const char *l_net_name = argv[++i];
            a_params->net = dap_chain_net_by_name(l_net_name);
            if (!a_params->net) {
                log_it(L_ERROR, "Network not found: %s", l_net_name);
                return -2;
            }
        } else if (strcmp(argv[i], "-server") == 0 && i + 1 < argc) {
            a_params->server_addr = argv[++i];
            // Parse port if provided (addr:port format)
            char *l_colon = strchr(a_params->server_addr, ':');
            if (l_colon) {
                *l_colon = '\0';
                a_params->server_port = atoi(l_colon + 1);
            }
        } else if (strcmp(argv[i], "-wallet") == 0 && i + 1 < argc) {
            const char *l_wallet_name = argv[++i];
            a_params->wallet = dap_chain_net_vpn_client_cli_get_wallet(l_wallet_name);
            if (!a_params->wallet) {
                log_it(L_ERROR, "Wallet not found: %s", l_wallet_name);
                return -3;
            }
        } else if (strcmp(argv[i], "-token") == 0 && i + 1 < argc) {
            a_params->payment_token = argv[++i];
        } else if (strcmp(argv[i], "-amount") == 0 && i + 1 < argc) {
            const char *l_amount_str = argv[++i];
            a_params->payment_amount = dap_chain_balance_scan(l_amount_str);
            if (IS_ZERO_256(a_params->payment_amount)) {
                log_it(L_WARNING, "Failed to parse amount '%s' or amount is zero", l_amount_str);
            }
        } else if (strcmp(argv[i], "-tx") == 0 && i + 1 < argc) {
            a_params->payment_tx_hash = argv[++i];
        } else if (strcmp(argv[i], "-notable") == 0) {
            a_params->notable = true;
        } else if (strcmp(argv[i], "-nodns") == 0) {
            a_params->nodns = true;
        } else if (strcmp(argv[i], "-multihop") == 0 && i + 1 < argc) {
            a_params->multi_hop = true;
            a_params->multi_hop_route = argv[++i];
        } else if (strcmp(argv[i], "-transport") == 0 && i + 1 < argc) {
            a_params->transport_type = argv[++i];
        } else if (strcmp(argv[i], "-obfuscation") == 0 && i + 1 < argc) {
            a_params->obfuscation_mode = argv[++i];
        } else if (strcmp(argv[i], "-criteria") == 0 && i + 1 < argc) {
            a_params->auto_select_criteria = argv[++i];
        }
    }
    
    return 0;
}

dap_chain_wallet_t* dap_chain_net_vpn_client_cli_get_wallet(const char *wallet_name) {
    if (!wallet_name) return NULL;
    
    // Get wallet from wallet manager
    return dap_chain_wallet_open(wallet_name, dap_chain_wallet_get_path(g_config), NULL);
}

int dap_chain_net_vpn_client_cli_auto_select_node(dap_chain_net_t *net,
                                                    const char *criteria,
                                                    uint32_t timeout_ms,
                                                    char **out_addr,
                                                    uint16_t *out_port) {
    if (!net || !out_addr || !out_port) {
        log_it(L_ERROR, "Invalid parameters for auto node selection");
        return -1;
    }
    
    UNUSED(timeout_ms);
    
    // Query GDB for VPN service nodes
    dap_chain_net_srv_uid_t l_vpn_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    
    // Get list of nodes offering VPN service
    // Note: This requires GDB discovery module (Phase 6.12)
    // For now, use simple fallback to known node
    
    const char *l_criteria_lower = criteria ? criteria : "speed";
    
    log_it(L_INFO, "Auto-selecting VPN node with criteria '%s' from network '%s'",
           l_criteria_lower, net->pub.name);
    
    // Fallback to network-specific default nodes
    if (strcmp(net->pub.name, "kelvin") == 0) {
        *out_addr = dap_strdup("node.kelvin.cellframe.net");
        *out_port = 8089;
    } else if (strcmp(net->pub.name, "backbone") == 0) {
        *out_addr = dap_strdup("node.backbone.cellframe.net");
        *out_port = 8089;
    } else {
        // Generic fallback
        *out_addr = dap_strdup("vpn.cellframe.net");
        *out_port = 8089;
    }
    
    log_it(L_NOTICE, "Auto-selected node: %s:%u (criteria: %s)",
           *out_addr, *out_port, l_criteria_lower);
    
    return 0;
}

int dap_chain_net_vpn_client_cli_create_payment(dap_chain_wallet_t *wallet,
                                                  dap_chain_net_t *net,
                                                  const char *token,
                                                  uint256_t amount,
                                                  const char *server_addr,
                                                  char **out_tx_hash) {
    if (!wallet || !net || !token || !server_addr || !out_tx_hash) {
        log_it(L_ERROR, "Invalid parameters for payment creation");
        return -1;
    }
    
    // Create conditional transaction for VPN service
    dap_enc_key_t *l_key = dap_chain_wallet_get_key(wallet, 0);
    if (!l_key) {
        log_it(L_ERROR, "Failed to get wallet key");
        return -2;
    }
    
    dap_pkey_t *l_pkey = dap_pkey_from_enc_key(l_key);
    if (!l_pkey) {
        log_it(L_ERROR, "Failed to create pkey from wallet key");
        return -3;
    }
    
    dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = DAP_CHAIN_NET_SRV_VPN_ID };
    uint256_t l_zero = {};
    
    // Create conditional transaction
    char *l_tx_hash_str = dap_chain_mempool_tx_create_cond(
        net,
        l_key,
        l_pkey,
        token,
        amount,                                    // value
        l_zero,                                    // value_per_unit_max
        SERV_UNIT_B,                              // unit type (bytes)
        l_srv_uid,                                 // VPN service UID
        l_zero,                                    // fee
        NULL,                                      // no TSD for single-hop
        0,                                         // TSD size
        "hex"                                      // output format
    );
    
    DAP_DELETE(l_pkey);
    
    if (!l_tx_hash_str) {
        log_it(L_ERROR, "Failed to create conditional transaction");
        return -4;
    }
    
    *out_tx_hash = l_tx_hash_str;
    
    log_it(L_NOTICE, "Created payment TX: %s (amount="UINT256_FORMAT_U" %s)",
           l_tx_hash_str, UINT256_FORMAT_PARAM(amount), token);
    
    return 0;
}

int dap_chain_net_vpn_client_cli_format_status(const void *status, char **out_str) {
    UNUSED(status);
    
    if (!out_str) return -1;
    
    // TODO: Format actual status
    *out_str = dap_strdup("Status formatting pending implementation");
    
    return 0;
}

int dap_chain_net_vpn_client_cli_format_stats(const void *stats, char **out_str) {
    UNUSED(stats);
    
    if (!out_str) return -1;
    
    // TODO: Format actual statistics
    *out_str = dap_strdup("Stats formatting pending implementation");
    
    return 0;
}

// --- Configuration ---

int dap_chain_net_vpn_client_cli_load_config(const char *config_path) {
    if (!config_path) return -1;
    
    // TODO: Load configuration from file
    log_it(L_INFO, "Loading configuration from %s (stub)", config_path);
    
    return 0;
}

int dap_chain_net_vpn_client_cli_save_config(const char *config_path) {
    if (!config_path) return -1;
    
    // TODO: Save configuration to file
    log_it(L_INFO, "Saving configuration to %s (stub)", config_path);
    
    return 0;
}

const dap_chain_net_vpn_client_cli_config_t* dap_chain_net_vpn_client_cli_get_config() {
    return &s_config;
}

int dap_chain_net_vpn_client_cli_set_config(const dap_chain_net_vpn_client_cli_config_t *config) {
    if (!config) return -1;
    
    memcpy(&s_config, config, sizeof(s_config));
    
    return 0;
}

// --- Wallet Commands ---

int dap_chain_net_vpn_client_cli_cmd_wallet(int argc, char **argv, void **str_reply, int a_version) {
    UNUSED(a_version);
    
    if (argc < 2) {
        dap_cli_server_cmd_set_reply_text(str_reply,
            "Error: Missing wallet subcommand\n"
            "Usage: vpn_client wallet <subcommand> [options]\n"
            "Subcommands: create, list, balance, address");
        return -1;
    }
    
    const char *l_subcmd = argv[1];
    
    if (strcmp(l_subcmd, "create") == 0) {
        if (argc < 3) {
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: wallet name required");
            return -1;
        }
        
        const char *l_wallet_name = argv[2];
        dap_enc_key_type_t l_sig_type = DAP_ENC_KEY_TYPE_SIG_DILITHIUM; // Default
        
        // Optional sig_type parameter
        if (argc >= 4) {
            if (strcmp(argv[3], "dilithium") == 0) {
                l_sig_type = DAP_ENC_KEY_TYPE_SIG_DILITHIUM;
            } else if (strcmp(argv[3], "falcon") == 0) {
                l_sig_type = DAP_ENC_KEY_TYPE_SIG_FALCON;
            }
        }
        
        dap_chain_wallet_t *l_wallet = dap_vpn_client_wallet_create(l_wallet_name, l_sig_type);
        if (!l_wallet) {
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: Failed to create wallet '%s'", l_wallet_name);
            return -2;
        }
        
        dap_cli_server_cmd_set_reply_text(str_reply, "Wallet '%s' created successfully (sig_type=%d)",
                                           l_wallet_name, l_sig_type);
        dap_vpn_client_wallet_close(l_wallet);
        return 0;
        
    } else if (strcmp(l_subcmd, "list") == 0) {
        size_t l_count = 0;
        char **l_wallets = dap_vpn_client_wallet_list(&l_count);
        
        if (!l_wallets || l_count == 0) {
            dap_cli_server_cmd_set_reply_text(str_reply, "No wallets found");
            return 0;
        }
        
        dap_string_t *l_reply = dap_string_new("Wallets:\n");
        for (size_t i = 0; i < l_count; i++) {
            dap_string_append_printf(l_reply, "  %zu. %s\n", i + 1, l_wallets[i]);
            DAP_DELETE(l_wallets[i]);
        }
        DAP_DELETE(l_wallets);
        
        *str_reply = dap_string_free(l_reply, false);
        return 0;
        
    } else if (strcmp(l_subcmd, "balance") == 0) {
        if (argc < 5) {
            dap_cli_server_cmd_set_reply_text(str_reply,
                "Usage: vpn_client wallet balance <wallet_name> <network> <token>");
            return -1;
        }
        
        const char *l_wallet_name = argv[2];
        const char *l_network_name = argv[3];
        const char *l_token = argv[4];
        
        dap_chain_wallet_t *l_wallet = dap_vpn_client_wallet_open(l_wallet_name);
        if (!l_wallet) {
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: Wallet '%s' not found", l_wallet_name);
            return -2;
        }
        
        dap_chain_net_t *l_net = dap_chain_net_by_name(l_network_name);
        if (!l_net) {
            dap_vpn_client_wallet_close(l_wallet);
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: Network '%s' not found", l_network_name);
            return -3;
        }
        
        uint256_t l_balance = {};
        if (dap_vpn_client_wallet_get_balance(l_wallet, l_net, l_token, &l_balance) < 0) {
            dap_vpn_client_wallet_close(l_wallet);
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: Failed to get balance");
            return -4;
        }
        
        dap_cli_server_cmd_set_reply_text(str_reply, "Balance: "UINT256_FORMAT_U" %s",
                                           UINT256_FORMAT_PARAM(l_balance), l_token);
        dap_vpn_client_wallet_close(l_wallet);
        return 0;
        
    } else if (strcmp(l_subcmd, "address") == 0) {
        if (argc < 4) {
            dap_cli_server_cmd_set_reply_text(str_reply,
                "Usage: vpn_client wallet address <wallet_name> <network>");
            return -1;
        }
        
        const char *l_wallet_name = argv[2];
        const char *l_network_name = argv[3];
        
        dap_chain_wallet_t *l_wallet = dap_vpn_client_wallet_open(l_wallet_name);
        if (!l_wallet) {
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: Wallet '%s' not found", l_wallet_name);
            return -2;
        }
        
        dap_chain_net_t *l_net = dap_chain_net_by_name(l_network_name);
        if (!l_net) {
            dap_vpn_client_wallet_close(l_wallet);
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: Network '%s' not found", l_network_name);
            return -3;
        }
        
        dap_chain_addr_t *l_addr = dap_vpn_client_wallet_get_addr(l_wallet, l_net);
        if (!l_addr) {
            dap_vpn_client_wallet_close(l_wallet);
            dap_cli_server_cmd_set_reply_text(str_reply, "Error: Failed to get address");
            return -4;
        }
        
        char *l_addr_str = dap_chain_addr_to_str(l_addr);
        dap_cli_server_cmd_set_reply_text(str_reply, "Address: %s", l_addr_str);
        DAP_DELETE(l_addr_str);
        DAP_DELETE(l_addr);
        dap_vpn_client_wallet_close(l_wallet);
        return 0;
        
    } else {
        dap_cli_server_cmd_set_reply_text(str_reply,
            "Error: Unknown wallet subcommand '%s'", l_subcmd);
        return -1;
    }
}

// --- Network Commands ---

int dap_chain_net_vpn_client_cli_cmd_network(int argc, char **argv, void **str_reply, int a_version) {
    UNUSED(a_version);
    
    if (argc < 2) {
        dap_cli_server_cmd_set_reply_text(str_reply,
            "Error: Missing network subcommand\n"
            "Usage: vpn_client network <subcommand>\n"
            "Subcommands: list, list-enabled");
        return -1;
    }
    
    const char *l_subcmd = argv[1];
    
    if (strcmp(l_subcmd, "list") == 0) {
        size_t l_count = 0;
        dap_vpn_client_network_t **l_networks = dap_vpn_client_network_registry_list(&l_count);
        
        if (!l_networks || l_count == 0) {
            dap_cli_server_cmd_set_reply_text(str_reply, "No networks configured");
            return 0;
        }
        
        dap_string_t *l_reply = dap_string_new("Networks:\n");
        for (size_t i = 0; i < l_count; i++) {
            dap_vpn_client_network_t *l_net = l_networks[i];
            dap_string_append_printf(l_reply, "  %zu. %s (chain_id=0x%016"DAP_UINT64_FORMAT_X", token=%s, enabled=%s)\n",
                                     i + 1, l_net->name, l_net->chain_id.uint64, l_net->token_ticker,
                                     l_net->enabled ? "yes" : "no");
        }
        
        *str_reply = dap_string_free(l_reply, false);
        return 0;
        
    } else if (strcmp(l_subcmd, "list-enabled") == 0) {
        size_t l_count = 0;
        dap_vpn_client_network_t **l_networks = dap_vpn_client_network_registry_list_enabled(&l_count);
        
        if (!l_networks || l_count == 0) {
            dap_cli_server_cmd_set_reply_text(str_reply, "No enabled networks");
            DAP_DELETE(l_networks);
            return 0;
        }
        
        dap_string_t *l_reply = dap_string_new("Enabled Networks:\n");
        for (size_t i = 0; i < l_count; i++) {
            dap_vpn_client_network_t *l_net = l_networks[i];
            dap_string_append_printf(l_reply, "  %zu. %s (chain_id=0x%016"DAP_UINT64_FORMAT_X", token=%s)\n",
                                     i + 1, l_net->name, l_net->chain_id.uint64, l_net->token_ticker);
        }
        
        DAP_DELETE(l_networks);
        *str_reply = dap_string_free(l_reply, false);
        return 0;
        
    } else {
        dap_cli_server_cmd_set_reply_text(str_reply,
            "Error: Unknown network subcommand '%s'", l_subcmd);
        return -1;
    }
}

