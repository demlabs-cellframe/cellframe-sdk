/*
 * Authors:
 * Roman Khlopkov <roman.khlopkov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://gitlab.demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
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

#include "dap_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_ledger.h"
#include "dap_chain_net_srv_emit_delegate.h"

#define LOG_TAG "dap_chain_net_srv_emit_delegate"

static int s_emit_delegate_verificator(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond, bool a_owner)
{
    size_t l_tsd_hashes_count = a_cond->tsd_size / (sizeof(dap_tsd_t) + sizeof(dap_hash_fast_t));
    dap_sign_t *l_signs[l_tsd_hashes_count];
    uint32_t l_signs_counter = 0, l_signs_verified = 0;
    byte_t *l_item; size_t l_tx_item_size;
    TX_ITEM_ITER_TX(l_item, l_tx_item_size, a_tx_in) {
        if (*l_item == TX_ITEM_TYPE_SIG) {
            dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig((dap_chain_tx_sig_t *)l_item);
            bool l_dup = false;
            for (uint32_t i = 0; i < l_signs_counter; i++)
                if (dap_sign_compare_pkeys(l_sign, l_signs[i])) {
                    l_dup = true;
                    break;
                }
            if (l_dup)
                continue;
            l_signs[l_signs_counter++] = l_sign;
            if (l_signs_counter > l_tsd_hashes_count) {
                log_it(L_WARNING, "Too many signs in tx %s, can't process more than %zu", dap_hash_fast_to_str_static(a_tx_in_hash), l_tsd_hashes_count);
                return -1;
            }
            dap_hash_fast_t l_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
            dap_tsd_t *l_tsd; size_t l_tsd_size;
            dap_tsd_iter(l_tsd, l_tsd_size, a_cond->tsd, a_cond->tsd_size) {
                if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t) &&
                        dap_hash_fast_compare(&l_pkey_hash, (dap_hash_fast_t *)l_tsd->data)) {
                    uint32_t l_orig_size = a_tx_in->header.tx_items_size;
                    a_tx_in->header.tx_items_size = 0;
                    if (dap_sign_verify(l_sign, a_tx_in, l_item - (byte_t *)a_tx_in))
                        l_signs_verified++;
                    a_tx_in->header.tx_items_size = l_orig_size;
                }
            }
        }
    }
    if (l_signs_verified < a_cond->subtype.srv_emit_delegate.signers_minimum) {
        log_it(L_WARNING, "Not enough valid signs (%u from %u) for delegated emission in tx %s",
                                    l_signs_verified, a_cond->subtype.srv_emit_delegate.signers_minimum, dap_hash_fast_to_str_static(a_tx_in_hash));
        return -2;
    }
    return 0;
}

static bool s_tag_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx,  dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action)
{   
    return a_items_grp->items_out_cond_srv_emit_delegate;
}

int dap_chain_net_srv_bridge_init()
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_EMIT_DELEGATE, s_emit_delegate_verificator, NULL, NULL, NULL, NULL, NULL);
    dap_cli_server_cmd_add("emit_delegate", s_cli_emit_delegate, "Emitting delegation service commands",
                "emit_delegate hold -net <net_name> -w <wallet_name> -token <ticker> -value <value> -fee <value>"
                            "[-chain <chain_name>] -signs_minimum <value_int> -pkey_hashes <hash1,hash2,...,hashN>\n"
                //"stake_lock take -net <net_name> -w <wallet_name> -tx <transaction_hash> -fee <value>"
                //            "[-chain <chain_name>]\n\n"
                            "Hint:\n"
                            "\texample value_coins (only natural) 1.0 123.4567\n"
                            "\texample value_datoshi (only integer) 1 20 0.4321e+4\n"
    );

    dap_chain_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_EMIT_DELEGATE_ID };
    dap_ledger_service_add(l_uid, "emit-delegate", s_tag_check);

    return 0;
}


