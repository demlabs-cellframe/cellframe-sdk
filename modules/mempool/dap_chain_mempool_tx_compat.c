/*
 * Compatibility wrappers for old mempool TX creation API
 * 
 * DEPRECATED: These functions redirect to net/tx module
 * TODO: Update all callers to use dap_chain_net_tx_* directly
 */

#include "dap_chain_mempool.h"
#include "dap_chain_net_tx_legacy.h"

// Forward all calls to net/tx module

char *dap_chain_mempool_tx_create(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
                                  const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t **a_addr_to,
                                  const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX], uint256_t *a_value,
                                  uint256_t a_value_fee, const char *a_hash_out_type,
                                  size_t a_tx_num, dap_time_t *a_time_unlock)
{
    return dap_chain_net_tx_create(a_chain, a_key_from, a_addr_from, a_addr_to, 
                                   a_token_ticker, a_value, a_value_fee, a_hash_out_type, 
                                   a_tx_num, a_time_unlock);
}

int dap_chain_mempool_tx_create_massive(dap_chain_t *a_chain, dap_enc_key_t *a_key_from,
                                         const dap_chain_addr_t *a_addr_from, const dap_chain_addr_t *a_addr_to,
                                         const char a_token_ticker[10], uint256_t a_value, uint256_t a_value_fee,
                                         size_t a_tx_num)
{
    return dap_chain_net_tx_create_massive(a_chain, a_key_from, a_addr_from, a_addr_to,
                                           a_token_ticker, a_value, a_value_fee, a_tx_num);
}

char* dap_chain_mempool_tx_create_cond_input(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_tx_prev_hash,
                                             const dap_chain_addr_t *a_addr_from,
                                             dap_enc_key_t *a_key, const dap_chain_addr_t *a_addr_to,
                                             dap_pkey_t *a_seller_pkey, const char *a_token_ticker,
                                             uint256_t a_value, uint256_t a_value_fee,
                                             const char *a_hash_out_type)
{
    return dap_chain_net_tx_create_cond_input(a_net, a_tx_prev_hash, a_addr_from, a_key, a_addr_to,
                                              a_seller_pkey, a_token_ticker, a_value, a_value_fee, a_hash_out_type);
}

char *dap_chain_mempool_tx_create_cond(dap_chain_net_t *a_net,
                                       dap_enc_key_t *a_key_from, dap_pkey_t *a_key_cond,
                                       const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                       uint256_t a_value, uint256_t a_value_per_unit_max, dap_chain_net_srv_price_unit_uid_t a_unit,
                                       dap_chain_net_srv_uid_t a_srv_uid, uint256_t a_value_fee,
                                       const void *a_cond, size_t a_cond_size,
                                       const char *a_hash_out_type)
{
    return dap_chain_net_tx_create_cond(a_net, a_key_from, a_key_cond, a_token_ticker,
                                       a_value, a_value_per_unit_max, a_unit, a_srv_uid, a_value_fee,
                                       a_cond, a_cond_size, a_hash_out_type);
}

char *dap_chain_mempool_base_tx_create(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_emission_hash,
                                       dap_chain_id_t a_emission_chain_id,
                                       uint256_t a_emission_value, const char *a_ticker,
                                       const dap_chain_addr_t *a_addr_to, uint256_t a_value,
                                       dap_enc_key_t *a_private_key, const char *a_hash_out_type)
{
    return dap_chain_net_base_tx_create(a_chain, a_emission_hash, a_emission_chain_id,
                                       a_emission_value, a_ticker, a_addr_to, a_value,
                                       a_private_key, a_hash_out_type);
}

char *dap_chain_mempool_tx_create_event(dap_chain_t *a_chain,
                                        dap_enc_key_t *a_key_from,
                                        dap_enc_key_t *a_service_key,
                                        dap_chain_net_srv_uid_t a_srv_uid,
                                        const char *a_event_name,
                                        dap_chain_tx_event_type_t a_event_type,
                                        const void *a_event_data, size_t a_event_data_size,
                                        uint256_t a_value_fee,
                                        const char *a_hash_out_type)
{
    return dap_chain_net_tx_create_event(a_chain, a_key_from, a_service_key, a_srv_uid,
                                        a_event_name, a_event_type, a_event_data, a_event_data_size,
                                        a_value_fee, a_hash_out_type);
}

