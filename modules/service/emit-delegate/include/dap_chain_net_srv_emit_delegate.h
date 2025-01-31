#pragma once

#include "dap_chain_datum_tx.h"
#include "dap_chain_mempool.h"

#define DAP_CHAIN_NET_SRV_EMIT_DELEGATE_ID 0x07
#define DAP_CHAIN_NET_SRV_EMIT_DELEGATE_TSD_WRITEOFF 0x14

int dap_chain_net_srv_emit_delegate_init();
void dap_chain_net_srv_emit_delegate_deinit();

dap_chain_datum_tx_t *dap_chain_net_srv_emit_delegate_taking_tx_create(json_object *a_json_arr_rweply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key,
                                                dap_chain_addr_t *a_addr_to, uint256_t a_value, uint256_t a_fee, dap_hash_fast_t *a_tx_in_hash, dap_list_t *a_tsd_items);

dap_chain_datum_tx_t *dap_chain_net_srv_emit_delegate_taking_tx_sign(json_object *a_json_arr_reply, dap_chain_net_t *a_net, dap_enc_key_t *a_enc_key, dap_chain_datum_tx_t *a_tx_in);

