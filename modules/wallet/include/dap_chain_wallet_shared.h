#pragma once

#define DAP_CHAIN_WALLET_SHARED_ID 0x07
#define DAP_CHAIN_WALLET_SHARED_TSD_WRITEOFF 0x14
#define DAP_CHAIN_WALLET_SHARED_TSD_REFILL 0x15
#define DAP_CHAIN_WALLET_SHARED_TSD_PREV_TX_HASH 0x16

#include "dap_chain_datum_tx.h"
#include "dap_chain_mempool.h"

int dap_chain_wallet_shared_init();

void dap_chain_wallet_shared_deinit();

int dap_chain_wallet_shared_cli(int a_argc, char **a_argv, void **a_str_reply, int a_version);

dap_chain_datum_tx_t *dap_chain_wallet_shared_taking_tx_create(json_object *a_json_arr_rweply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
                                                dap_chain_addr_t *a_addr_to, uint256_t *a_value, uint32_t a_addr_count, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t *tsd_items);
dap_chain_datum_tx_t *dap_chain_wallet_shared_refilling_tx_create(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
                                                    uint256_t a_value, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t* tsd_items);
dap_chain_datum_tx_t *dap_chain_wallet_shared_taking_tx_sign(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key, dap_chain_datum_tx_t *a_tx_in, const char *a_prev_tx_hash_str);
int dap_chain_wallet_shared_hold_tx_add(dap_chain_datum_tx_t *a_tx, const char *a_net_name);
json_object *dap_chain_wallet_shared_get_tx_hashes_json(dap_hash_fast_t *a_pkey_hash, const char *a_net_name);