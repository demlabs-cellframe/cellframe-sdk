/**
 * @file dap_chain_net_srv_vpn_limits.c
 * @brief VPN Service Traffic Limits & Statistics Implementation
 * @details Bandwidth tracking, time-based limits, GDB persistence
 * 
 * @date 2025-10-25
 * @copyright (C) 2023-2025 Cellframe Network
 */

#include "dap_chain_net_srv_vpn_limits.h"
#include "dap_chain_net_srv_vpn_internal.h"
#include "dap_common.h"
#include "dap_strfuncs.h"
#include "dap_global_db.h"
#include "dap_enc_key.h"
#include "dap_hash.h"
#include "dap_chain_datum_tx_receipt.h"

#define LOG_TAG "dap_chain_net_srv_vpn_limits"

/**
 * @brief Get server public key hash string for GDB operations
 */
char* vpn_srv_limits_get_pkey_str(dap_chain_net_srv_usage_t *a_usage)
{
    if (!a_usage) {
        log_it(L_DEBUG, "Can't save remain service. Usage is NULL");
        return NULL;
    }

    dap_chain_net_srv_price_t *l_price = a_usage->price;
    if (!l_price || !l_price->receipt_sign_cert) {
        log_it(L_ERROR, "No price or certificate in usage");
        return NULL;
    }

    // Serialize public key
    size_t l_key_size = 0;
    uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(l_price->receipt_sign_cert->enc_key, &l_key_size);
    if (!l_pub_key || !l_key_size) {
        log_it(L_ERROR, "Can't get pkey from cert %s", l_price->receipt_sign_cert->name);
        return NULL;
    }

    // Hash public key
    dap_hash_fast_t l_pkey_hash = {};
    dap_hash_fast(l_pub_key, l_key_size, &l_pkey_hash);
    DAP_DELETE(l_pub_key);

    // Convert to string
    char *l_pkey_hash_str = dap_chain_hash_fast_to_str_new(&l_pkey_hash);
    return l_pkey_hash_str;
}

/**
 * @brief Get remaining service limits from GDB
 */
dap_stream_ch_chain_net_srv_remain_service_store_t* vpn_srv_limits_get_remain_service(
    dap_chain_net_srv_t *a_srv,
    uint32_t a_usage_id,
    dap_chain_net_srv_client_remote_t *a_srv_client)
{
    UNUSED(a_srv);

    // Get service session
    dap_chain_net_srv_stream_session_t *l_srv_session = 
        a_srv_client && a_srv_client->ch && a_srv_client->ch->stream && a_srv_client->ch->stream->session ?
        (dap_chain_net_srv_stream_session_t *)a_srv_client->ch->stream->session->_inheritor : NULL;

    if (!l_srv_session) {
        log_it(L_DEBUG, "Can't find srv session");
        return NULL;
    }

    // Find usage
    dap_chain_net_srv_usage_t *l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session, a_usage_id);
    if (!l_usage) {
        log_it(L_DEBUG, "Can't find usage");
        return NULL;
    }

    dap_chain_net_t *l_net = l_usage->net;

    // Get server public key hash
    char *l_server_pkey_hash = vpn_srv_limits_get_pkey_str(l_usage);
    if (!l_server_pkey_hash) {
        log_it(L_DEBUG, "Can't get server pkey hash");
        return NULL;
    }

    // Construct GDB group name
    char *l_remain_limits_gdb_group = dap_strdup_printf(
        "local.%s.0x%016"DAP_UINT64_FORMAT_x".remain_limits.%s",
        l_net->pub.gdb_groups_prefix, a_srv->uid.uint64, l_server_pkey_hash);
    DAP_DEL_Z(l_server_pkey_hash);

    // Get user key
    char *l_user_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
    debug_if(g_vpn_debug_more, L_DEBUG, "Checkout user %s in group %s", l_user_key, l_remain_limits_gdb_group);

    // Load from GDB
    size_t l_remain_service_size = 0;
    dap_stream_ch_chain_net_srv_remain_service_store_t *l_remain_service = 
        (dap_stream_ch_chain_net_srv_remain_service_store_t *)dap_global_db_get_sync(
            l_remain_limits_gdb_group, l_user_key, &l_remain_service_size, NULL, NULL);

    DAP_DELETE(l_remain_limits_gdb_group);
    DAP_DELETE(l_user_key);

    return l_remain_service;
}

/**
 * @brief Save remaining service limits to GDB
 */
int vpn_srv_limits_save_remain_service(dap_chain_net_srv_t *a_srv,
                                        uint32_t a_usage_id,
                                        dap_chain_net_srv_client_remote_t *a_srv_client)
{
    UNUSED(a_srv);

    // Get service session
    dap_chain_net_srv_stream_session_t *l_srv_session =
        a_srv_client && a_srv_client->ch && a_srv_client->ch->stream && a_srv_client->ch->stream->session ?
        (dap_chain_net_srv_stream_session_t *)a_srv_client->ch->stream->session->_inheritor : NULL;

    if (!l_srv_session) {
        log_it(L_DEBUG, "Can't find srv session");
        return -100;
    }

    // Find usage
    dap_chain_net_srv_usage_t *l_usage = dap_chain_net_srv_usage_find_unsafe(l_srv_session, a_usage_id);
    if (!l_usage) {
        log_it(L_DEBUG, "Can't find usage");
        return -101;
    }

    // Check if limits changed and service is active
    if (l_usage->service_state != DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL || !l_usage->is_limits_changed) {
        return -110;
    }

    dap_chain_net_t *l_net = l_usage->net;

    // Get server public key hash
    char *l_server_pkey_hash = vpn_srv_limits_get_pkey_str(l_usage);
    if (!l_server_pkey_hash) {
        log_it(L_DEBUG, "Can't get server pkey hash");
        return -101;
    }

    // Construct GDB group name
    char *l_remain_limits_gdb_group = dap_strdup_printf(
        "local.%s.0x%016"DAP_UINT64_FORMAT_x".remain_limits.%s",
        l_net->pub.gdb_groups_prefix, a_srv->uid.uint64, l_server_pkey_hash);
    DAP_DEL_Z(l_server_pkey_hash);

    // Get user key
    char *l_user_key = dap_chain_hash_fast_to_str_new(&l_usage->client_pkey_hash);
    debug_if(g_vpn_debug_more, L_DEBUG, "Save user %s remain service into group %s",
             l_user_key, l_remain_limits_gdb_group);

    // Prepare remain service structure
    dap_stream_ch_chain_net_srv_remain_service_store_t l_remain_service = {};

    // Get receipt sign
    dap_sign_t *l_receipt_sign = NULL;
    if (l_srv_session->usage_active->receipt_next &&
        l_usage->service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_NORMAL) {
        l_receipt_sign = dap_chain_datum_tx_receipt_sign_get(
            l_srv_session->usage_active->receipt_next,
            l_srv_session->usage_active->receipt_next->size, 1);
    }

    // Update time-based limits
    l_remain_service.limits_ts = l_srv_session->limits_ts >= 0 ? l_srv_session->limits_ts : 0;
    if (l_receipt_sign && l_srv_session->limits_units_type.enm == SERV_UNIT_SEC) {
        l_remain_service.limits_ts += l_srv_session->usage_active->receipt_next->receipt_info.units;
    }

    // Update byte-based limits
    l_remain_service.limits_bytes = l_srv_session->limits_bytes >= 0 ? l_srv_session->limits_bytes : 0;
    if (l_receipt_sign && l_srv_session->limits_units_type.enm == SERV_UNIT_B) {
        l_remain_service.limits_bytes += l_srv_session->usage_active->receipt_next->receipt_info.units;
    }

    log_it(L_INFO, "Save limits for user %s: sec: %"DAP_UINT64_FORMAT_U" bytes: %"DAP_UINT64_FORMAT_U,
           l_user_key, l_remain_service.limits_ts, l_remain_service.limits_bytes);

    // Save to GDB
    int l_ret = dap_global_db_set_sync(l_remain_limits_gdb_group, l_user_key,
                                        &l_remain_service, sizeof(l_remain_service), false);
    if (l_ret) {
        log_it(L_DEBUG, "Can't save remain limits into GDB. Error code: %d", l_ret);
        DAP_DELETE(l_remain_limits_gdb_group);
        DAP_DELETE(l_user_key);
        return -102;
    }

    DAP_DELETE(l_remain_limits_gdb_group);
    DAP_DELETE(l_user_key);

    return 0;
}

/**
 * @brief Save remaining limits to GDB (timer callback wrapper)
 */
bool vpn_srv_limits_save(void *a_arg)
{
    remain_limits_save_arg_t *l_args = (remain_limits_save_arg_t *)a_arg;

    vpn_srv_limits_save_remain_service(l_args->srv, l_args->usage_id, l_args->srv_client);

    return true;  // Continue timer
}

/**
 * @brief Update traffic limits after data transfer
 */
void vpn_srv_limits_update(dap_stream_ch_t *a_ch,
                            dap_chain_net_srv_stream_session_t *a_srv_session,
                            dap_chain_net_srv_usage_t *a_usage,
                            size_t a_bytes)
{
    if (!a_ch || !a_srv_session || !a_usage) {
        return;
    }

    // Update byte counter
    if (a_srv_session->limits_units_type.enm == SERV_UNIT_B) {
        if (a_srv_session->limits_bytes > (int64_t)a_bytes) {
            a_srv_session->limits_bytes -= a_bytes;
        } else {
            a_srv_session->limits_bytes = 0;
        }
        a_usage->is_limits_changed = true;
    }

    // Update time counter (if applicable, based on elapsed time)
    if (a_srv_session->limits_units_type.enm == SERV_UNIT_SEC) {
        // Time tracking is handled by timer mechanism
        a_usage->is_limits_changed = true;
    }

    // Check if limits exhausted
    if ((a_srv_session->limits_units_type.enm == SERV_UNIT_B && a_srv_session->limits_bytes <= 0) ||
        (a_srv_session->limits_units_type.enm == SERV_UNIT_SEC && a_srv_session->limits_ts <= 0)) {
        log_it(L_WARNING, "Service limits exhausted for channel");
        dap_stream_ch_set_ready_to_read_unsafe(a_ch, false);
    }

    if (g_vpn_debug_more) {
        log_it(L_DEBUG, "Updated limits: %"DAP_UINT64_FORMAT_U" bytes, %"DAP_UINT64_FORMAT_U" sec remaining",
               a_srv_session->limits_bytes, a_srv_session->limits_ts);
    }
}

