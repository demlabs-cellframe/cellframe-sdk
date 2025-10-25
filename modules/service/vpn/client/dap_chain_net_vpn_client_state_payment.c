/**
 * @file dap_chain_net_vpn_client_state_payment.c
 * @brief Payment transaction creation and validation for VPN client
 * @details Handles:
 *          - Payment TX creation (single-hop and multi-hop)
 *          - Payment parameter validation
 *          - Wallet management
 *          - Receipt collector integration
 * @date 2025-10-25
 * @copyright (c) 2025 Cellframe Network
 */

#include "include/dap_chain_net_vpn_client_state_internal.h"
#include "dap_chain_net_srv.h"

#define LOG_TAG "dap_chain_net_vpn_client_state_payment"

/**
 * @brief Validate payment parameters
 * @details Ensures all required payment parameters are specified and valid.
 *          Enforces NO DEFAULT VALUES - fail fast if not explicitly provided.
 * @param a_sm State machine context
 * @return 0 if valid, negative error code if invalid
 */
int vpn_client_payment_validate(dap_chain_net_vpn_client_sm_t *a_sm) {
    if (!a_sm || !a_sm->connect_params) {
        return -1;
    }
    
    // Payment token validation
    if (!a_sm->connect_params->payment_token || 
        strlen(a_sm->connect_params->payment_token) == 0) {
        log_it(L_ERROR, "Payment token not specified - cannot create payment TX");
        return -2;
    }
    
    // Service units validation
    if (a_sm->connect_params->service_units == 0) {
        log_it(L_ERROR, "Service units not specified - cannot create payment TX");
        return -3;
    }
    
    // Service unit type validation
    if (a_sm->connect_params->service_unit_type.enm == 0) {
        log_it(L_ERROR, "Service unit type not specified - cannot create payment TX");
        return -4;
    }
    
    log_it(L_DEBUG, "Payment parameters validated: %"DAP_UINT64_FORMAT_U" %s units in %s token",
           a_sm->connect_params->service_units,
           dap_chain_srv_unit_enum_to_str(a_sm->connect_params->service_unit_type.enm),
           a_sm->connect_params->payment_token);
    
    return 0;
}

/**
 * @brief Create payment transaction for VPN service
 * @details Handles both single-hop and multi-hop payment TX creation.
 *          Also creates receipt collector for payment verification.
 * @param a_sm State machine context
 * @param a_node_info Node information (unused, but kept for API consistency)
 * @param a_net_name Network name
 * @return 0 on success, negative error code on failure
 */
int vpn_client_payment_tx_create(dap_chain_net_vpn_client_sm_t *a_sm,
                                  dap_chain_node_info_t *a_node_info,
                                  const char *a_net_name) {
    UNUSED(a_node_info);
    
    if (!a_sm || !a_sm->connect_params || !a_net_name) {
        return -1;
    }
    
    // Validate payment parameters first
    int l_validation_result = vpn_client_payment_validate(a_sm);
    if (l_validation_result != 0) {
        return l_validation_result;
    }
    
    // Get network
    dap_chain_net_t *l_net = dap_chain_net_by_name(a_net_name);
    if (!l_net) {
        log_it(L_ERROR, "Network '%s' not found", a_net_name);
        return -5;
    }
    
    // Open wallet if not already open
    if (!a_sm->wallet) {
        if (!a_sm->connect_params->wallet_name) {
            log_it(L_ERROR, "Wallet name not specified");
            return -6;
        }
        
        a_sm->wallet = dap_vpn_client_wallet_open(a_sm->connect_params->wallet_name);
        if (!a_sm->wallet) {
            log_it(L_ERROR, "Failed to open wallet '%s'", a_sm->connect_params->wallet_name);
            return -7;
        }
        
        log_it(L_INFO, "Wallet '%s' opened successfully", a_sm->connect_params->wallet_name);
    }
    
    // Create payment TX set (works for both single-hop and multi-hop)
    log_it(L_INFO, "Creating payment TX set from wallet '%s' for %u-hop route",
           a_sm->connect_params->wallet_name, a_sm->connect_params->hop_count);
    
    log_it(L_INFO, "Payment parameters: %"DAP_UINT64_FORMAT_U" %s units in %s token",
           a_sm->connect_params->service_units,
           dap_chain_srv_unit_enum_to_str(a_sm->connect_params->service_unit_type.enm),
           a_sm->connect_params->payment_token);
    
    a_sm->connect_params->payment_tx_hashes = dap_chain_net_vpn_client_multihop_tx_set_create(
        a_sm->wallet,
        l_net,
        a_sm->connect_params->route,
        a_sm->connect_params->hop_count,
        a_sm->connect_params->tunnel_count,
        a_sm->connect_params->service_units,
        a_sm->connect_params->service_unit_type,
        a_sm->connect_params->payment_token,
        a_sm->connect_params->session_id
    );
    
    if (!a_sm->connect_params->payment_tx_hashes) {
        log_it(L_ERROR, "Failed to create payment TX set");
        return -8;
    }
    
    log_it(L_NOTICE, "Created %u payment TX(s) for route", a_sm->connect_params->hop_count);
    
    // Create receipt collector for payment verification
    if (a_sm->connect_params->hop_count > 0) {
        log_it(L_INFO, "Creating receipt collector for %u-hop route (session_id=%u)",
               a_sm->connect_params->hop_count, a_sm->connect_params->session_id);
        
        a_sm->receipt_collector = dap_vpn_client_receipt_collector_create(
            a_sm->connect_params->session_id,
            l_net,
            a_sm->connect_params->route,
            a_sm->connect_params->hop_count,
            a_sm->connect_params->payment_tx_hashes
        );
        
        if (!a_sm->receipt_collector) {
            log_it(L_ERROR, "Failed to create receipt collector");
            return -9;
        }
        
        log_it(L_INFO, "Receipt collector created successfully");
    }
    
    return 0;
}


