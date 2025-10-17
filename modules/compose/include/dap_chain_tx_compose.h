/*
 * Authors:
 * Roman Padenkov <roman.padenkov@demlabs.net>
 * Olzhas Zharasbaev <oljas.jarasbaev@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2025-2026
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

 DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 DAP is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once
#include "dap_chain_common.h"
#include "dap_list.h"
#include "dap_math_ops.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_wallet.h"
#include "dap_chain_net_srv_xchange.h"
#include "dap_json.h"


typedef struct dap_chain_tx_compose_config {
    dap_chain_net_id_t net_id;
    const char *net_name;
    const char *native_ticker;
    const char *url_str;
    const char *enc_cert_path;
    uint16_t port;
    dap_json_t *response_handler;
} dap_chain_tx_compose_config_t;

#ifdef __cplusplus
extern "C" {
#endif

int dap_tx_json_tsd_add(dap_json_t *json_tx, dap_json_t *json_add);
dap_json_t *dap_enc_request_command_to_rpc(const char *a_request, const char * a_url, uint16_t a_port, const char * a_cert_path);

bool s_dap_chain_tx_compose_check_token_in_ledger(dap_json_t *l_json_coins, const char *a_token);

dap_chain_tx_out_cond_t *dap_find_last_xchange_tx(dap_hash_fast_t *a_order_hash,  dap_chain_addr_t *a_seller_addr,  dap_chain_tx_compose_config_t * a_config, 
                                                  dap_time_t *a_ts_created, char **a_token_ticker, int32_t *a_prev_cond_idx, dap_hash_fast_t *a_hash_out);

dap_json_t *dap_chain_tx_compose_tx_create(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                  uint16_t a_port, const char *a_enc_cert_path, const char *a_token_ticker, const char *a_value_str, 
                                  const char *a_fee_str, const char *addr_base58_to, dap_chain_addr_t *a_addr_from);

dap_json_t *dap_chain_tx_compose_xchange_create(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                          uint16_t a_port, const char *a_enc_cert_path, const char *a_token_sell, const char *a_token_buy, 
                                          dap_chain_addr_t *a_wallet_addr, const char *a_value_str, const char *a_rate_str, const char *a_fee_str);

dap_json_t *dap_chain_tx_compose_tx_cond_create(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                        uint16_t a_port, const char *a_enc_cert_path, const char *a_token_ticker, dap_chain_addr_t *a_wallet_addr, const char *a_cert_str, 
                                        const char *a_value_datoshi_str, const char *a_value_fee_str, const char *a_unit_str, const char *a_value_per_unit_max_str,
                                        const char *a_srv_uid_str);

dap_json_t *dap_cli_xchange_purchase_compose(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                             uint16_t a_port, const char *a_enc_cert_path, const char *a_order_hash, const char* a_value, 
                                             const char* a_fee, const char *a_wallet_name, const char *a_wallet_path);

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_xchange_order_remove(dap_hash_fast_t *a_hash_tx, uint256_t a_fee,
                                                              dap_chain_addr_t *a_wallet_addr, dap_chain_tx_compose_config_t *a_config);

dap_json_t *dap_chain_tx_compose_xchange_order_remove(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                 uint16_t a_port, const char *a_enc_cert_path, const char *a_order_hash_str, const char *a_fee_str, 
                                                 dap_chain_addr_t *a_wallet_addr);

dap_chain_datum_tx_t *dap_xchange_tx_invalidate_compose( dap_chain_net_srv_xchange_price_t *a_price, dap_chain_tx_out_cond_t *a_cond_tx, 
                                                        dap_chain_addr_t *a_wallet_addr, dap_chain_addr_t *a_seller_addr, const char *a_tx_ticker, 
                                                        uint32_t a_prev_cond_idx, dap_chain_tx_compose_config_t *a_config);

dap_json_t *dap_chain_tx_compose_xchange_purchase(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                   uint16_t a_port, const char *a_enc_cert_path, const char *a_order_hash, const char* a_value, 
                                                   const char* a_fee, dap_chain_addr_t *a_wallet_addr);

dap_json_t *dap_chain_tx_compose_wallet_shared_hold(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                    uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_owner_addr, const char *a_token_str, const char *a_value_str, 
                                                    const char *a_fee_str, const char *a_signs_min_str, const char *a_pkeys_str, 
                                                    const char *a_tag_str);

dap_json_t *dap_chain_tx_compose_wallet_shared_refill(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                    uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_owner_addr, const char * a_value_str, 
                                                    const char * a_fee_str, const char * a_tx_in_hash_str);

dap_json_t *dap_chain_tx_compose_wallet_shared_take(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                    uint16_t a_port, const char *a_enc_cert_path, dap_chain_addr_t *a_owner_addr, const char *a_tx_in_hash_str, const char *a_value_str, const char *a_fee_str,
                                                    const char *a_to_addr_str);

dap_json_t *dap_chain_tx_compose_wallet_shared_sign(dap_chain_net_id_t a_net_id, const char *a_net_name, const char *a_native_ticker, const char *a_url_str,
                                                  uint16_t a_port, const char *a_enc_cert_path, const char *a_tx_in_hash_str, const char *a_wallet_str, const char *a_wallets_path, const char *a_pass_str, const char *a_cert_str);


dap_chain_datum_tx_t *dap_chain_tx_compose_datum_tx_create(dap_chain_addr_t* a_addr_from, dap_chain_addr_t** a_addr_to,
                                                       const char* a_token_ticker, uint256_t *a_value, uint256_t a_value_fee, 
                                                       size_t a_tx_num, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_xchange_create(const char *a_token_buy, const char *a_token_sell, 
                                                              uint256_t a_datoshi_sell, uint256_t a_rate, uint256_t a_fee, 
                                                              dap_chain_addr_t *a_wallet_addr, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_xchange_tx_create_request_compose(dap_chain_net_srv_xchange_price_t *a_price, 
                                                           dap_chain_addr_t *a_seller_addr, const char *a_native_ticker, 
                                                           dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_tx_cond_create(dap_chain_addr_t *a_wallet_addr, dap_pkey_t *a_key_cond,
                                                              const char a_token_ticker[DAP_CHAIN_TICKER_SIZE_MAX],
                                                              uint256_t a_value, uint256_t a_value_per_unit_max,
                                                              dap_chain_net_srv_price_unit_uid_t a_unit, 
                                                              dap_chain_srv_uid_t a_srv_uid, uint256_t a_value_fee, 
                                                              const void *a_cond, size_t a_cond_size, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_xchange_purchase(dap_hash_fast_t *a_order_hash, uint256_t a_value,
                                                                uint256_t a_fee, dap_chain_addr_t *a_wallet_addr, 
                                                                char **a_hash_out, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_xchange_tx_create_exchange_compose(dap_chain_net_srv_xchange_price_t *a_price, 
                                                            dap_chain_addr_t *a_buyer_addr, uint256_t a_datoshi_buy,
                                                            uint256_t a_datoshi_fee, dap_chain_tx_out_cond_t* a_cond_tx, 
                                                            uint32_t a_prev_cond_idx, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t * dap_chain_tx_compose_datum_wallet_shared_hold(dap_chain_addr_t *a_owner_addr, const char *a_token_ticker, uint256_t a_value, uint256_t a_fee, 
                                                      uint32_t a_signs_min, dap_hash_fast_t *a_pkey_hashes, size_t a_pkey_hashes_count, const char *a_tag_str, 
                                                      dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_wallet_shared_refill(dap_chain_addr_t *a_owner_addr, uint256_t a_value, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, 
                                                                            dap_list_t* a_tsd_items, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_wallet_shared_take(dap_chain_addr_t *a_owner_addr, dap_chain_addr_t *a_to_addr, uint256_t *a_value, uint32_t a_addr_count,
                                                                    uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t* a_tsd_items, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_chain_tx_compose_datum_wallet_shared_sign(const char *a_tx_in_hash_str, dap_enc_key_t *a_enc_key, dap_chain_tx_compose_config_t *a_config);

dap_chain_datum_tx_t *dap_chain_tx_compose_get_datum_from_rpc(
    const char *a_tx_str, dap_chain_tx_compose_config_t *a_config,
    dap_chain_tx_out_cond_subtype_t a_cond_subtype,
    dap_chain_tx_out_cond_t **a_cond_tx, char **a_spent_by_hash, 
    char **a_token_ticker, int *a_out_idx, bool a_is_ledger);

#ifdef __cplusplus
}
#endif
