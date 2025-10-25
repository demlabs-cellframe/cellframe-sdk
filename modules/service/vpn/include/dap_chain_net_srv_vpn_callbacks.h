/**
 * @file dap_chain_net_srv_vpn_callbacks.h
 * @brief VPN Service Callbacks Module
 * @details Service lifecycle callbacks (requested, response_success, response_error, receipt_next_success, etc.)
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#pragma once

#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_chain_net_srv_client.h"
#include "dap_enc_key.h"

// Forward declaration (full definition with typedef in dap_chain_net_srv_vpn_internal.h)
struct dap_chain_net_srv_vpn_custom_data;

// Service lifecycle callbacks

/**
 * @brief Service request callback
 * @param a_srv Service instance
 * @param a_usage_id Usage ID
 * @param a_srv_client Client remote structure
 * @param a_custom_data Custom data from client
 * @param a_custom_data_size Custom data size
 * @return 0 on success, negative on error
 */
int vpn_srv_callback_requested(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_custom_data,
    size_t a_custom_data_size
);

/**
 * @brief Response success callback
 * @param a_srv Service instance
 * @param a_usage_id Usage ID
 * @param a_srv_client Client remote structure
 * @param a_custom_data Custom data for response
 * @param a_custom_data_size Custom data size
 * @return 0 on success, negative on error
 */
int vpn_srv_callback_response_success(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_custom_data,
    size_t a_custom_data_size
);

/**
 * @brief Response error callback
 * @param a_srv Service instance
 * @param a_usage_id Usage ID
 * @param a_srv_client Client remote structure
 * @param a_custom_data Custom data (error info)
 * @param a_custom_data_size Custom data size
 * @return 0 on success, negative on error
 */
int vpn_srv_callback_response_error(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_custom_data,
    size_t a_custom_data_size
);

/**
 * @brief Receipt next success callback
 * @param a_srv Service instance
 * @param a_usage_id Usage ID
 * @param a_srv_client Client remote structure
 * @param a_receipt_next Next receipt data
 * @param a_receipt_next_size Receipt data size
 * @return 0 on success, negative on error
 */
int vpn_srv_callback_receipt_next_success(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client,
    const void *a_receipt_next,
    size_t a_receipt_next_size
);

/**
 * @brief Get remaining service callback
 * @param a_srv Service instance
 * @param a_usage_id Usage ID
 * @param a_srv_client Client remote structure
 * @return Pointer to remain service store structure
 */
dap_stream_ch_chain_net_srv_remain_service_store_t *vpn_srv_callback_get_remain_service(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client
);

/**
 * @brief Save remaining service callback
 * @param a_srv Service instance
 * @param a_usage_id Usage ID
 * @param a_srv_client Client remote structure
 * @return 0 on success, negative on error
 */
int vpn_srv_callback_save_remain_service(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client
);

/**
 * @brief Timer callback wrapper for save_remain_service
 * @param a_arg Usage pointer
 * @return true on success
 */
bool vpn_srv_save_limits_timer_callback(void *a_arg);

/**
 * @brief Get server public key hash string
 * @param a_usage Usage structure
 * @return Allocated string with key hash (caller must free)
 */
char *vpn_srv_get_my_pkey_str(dap_chain_net_srv_usage_t *a_usage);

// Helper functions for custom data parsing

/**
 * @brief Payment data structure (legacy, simple version for receipts)
 */
typedef struct dap_chain_net_srv_vpn_payment_data {
    char *payment_tx_hash;
    char *network_name;
    char *payment_token;
    uint64_t service_units;
    int service_unit_type;
} dap_chain_net_srv_vpn_payment_data_t;

/**
 * @brief Parse VPN payment data from JSON (legacy receipt format)
 * @param a_json_str JSON string
 * @return Parsed structure (caller must free with vpn_srv_free_payment_data)
 */
dap_chain_net_srv_vpn_payment_data_t *vpn_srv_parse_payment_data(const char *a_json_str);

/**
 * @brief Free VPN payment data structure
 * @param a_data Structure to free
 */
void vpn_srv_free_payment_data(dap_chain_net_srv_vpn_payment_data_t *a_data);


