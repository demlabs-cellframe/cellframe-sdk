#pragma once

#include <stdint.h>
#include <stdbool.h>
#include "dap_chain_net.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Node selection criteria
 */
typedef struct dap_chain_net_vpn_client_auto_criteria {
    char *region;                                   ///< Preferred region (e.g., "EU", "US", "AS")
    uint32_t min_speed_mbps;                        ///< Minimum speed in Mbps
    uint32_t max_latency_ms;                        ///< Maximum latency in ms
    bool require_payment;                           ///< Require paid mode support
    bool prefer_closest;                            ///< Prefer geographically closest nodes
} dap_chain_net_vpn_client_auto_criteria_t;

/**
 * @brief VPN node information
 */
typedef struct dap_chain_net_vpn_client_auto_node {
    char *addr;                                     ///< Node address (host:port)
    char *host;                                     ///< Hostname/IP
    uint16_t port;                                  ///< Port
    char *region;                                   ///< Region code
    uint32_t speed_mbps;                            ///< Speed in Mbps
    uint32_t latency_ms;                            ///< Latency in ms
    uint32_t load_percent;                          ///< Current load percentage
    bool payment_supported;                         ///< Supports paid mode
    uint64_t price_per_mb;                          ///< Price per MB (datoshi)
} dap_chain_net_vpn_client_auto_node_t;

/**
 * @brief Query available VPN nodes from GDB
 * @param a_net Network to query
 * @param a_criteria Selection criteria (optional)
 * @param a_out_nodes Output node array (caller must free)
 * @param a_out_count Output node count
 * @return 0 on success, negative on error
 */
int dap_chain_net_vpn_client_auto_query_nodes(dap_chain_net_t *a_net,
                                                const dap_chain_net_vpn_client_auto_criteria_t *a_criteria,
                                                dap_chain_net_vpn_client_auto_node_t **a_out_nodes,
                                                uint32_t *a_out_count);

/**
 * @brief Select best node based on criteria
 * @param a_nodes Available nodes
 * @param a_count Node count
 * @param a_criteria Selection criteria
 * @return Index of best node, or -1 if none found
 */
int dap_chain_net_vpn_client_auto_select_best(const dap_chain_net_vpn_client_auto_node_t *a_nodes,
                                                uint32_t a_count,
                                                const dap_chain_net_vpn_client_auto_criteria_t *a_criteria);

/**
 * @brief Free node array
 * @param a_nodes Node array
 * @param a_count Node count
 */
void dap_chain_net_vpn_client_auto_free_nodes(dap_chain_net_vpn_client_auto_node_t *a_nodes,
                                                uint32_t a_count);

#ifdef __cplusplus
} // extern "C"
#endif

