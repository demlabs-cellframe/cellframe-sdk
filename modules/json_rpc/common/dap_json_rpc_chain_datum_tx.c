#include <memory.h>
#include <assert.h>
#include "dap_common.h"
#include "dap_sign.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"

#include "dap_json_rpc_chain_datum_tx.h"
#include "dap_json_rpc_chain_datum_tx_items.h"
#include "dap_json_rpc_chain_datum_tx_receipt.h"
#include "json.h"
#include "dap_chain_datum_tx_voting.h"

#define LOG_TAG "dap_json_rpc_chain_datum_tx"



json_object *dap_chain_datum_tx_to_json(dap_chain_datum_tx_t *a_tx,dap_chain_net_id_t *a_net_id){
    json_object *l_obj_items = json_object_new_array();
    if (!l_obj_items) {
        dap_json_rpc_allocation_error;
        return NULL;
    }
    uint32_t l_tx_items_count = 0;
    uint32_t l_tx_items_size = a_tx->header.tx_items_size;
    while(l_tx_items_count < l_tx_items_size) {
        uint8_t *item = a_tx->tx_items + l_tx_items_count;
        size_t l_tx_item_size = dap_chain_datum_item_tx_get_size(item);
        if (l_tx_item_size == 0) {
            json_object_put(l_obj_items);
            l_obj_items = json_object_new_null();
            break;
        }
        dap_chain_tx_item_type_t l_item_type = dap_chain_datum_tx_item_get_type(item);
        json_object *l_obj_item_type = NULL, *l_obj_item_data = NULL;
        switch (l_item_type) {
            case TX_ITEM_TYPE_IN:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_IN");
                l_obj_item_data = dap_chain_datum_tx_item_in_to_json((dap_chain_tx_in_t*)item);
                break;
            case TX_ITEM_TYPE_OUT:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_OUT");
                l_obj_item_data = dap_chain_datum_tx_item_out_to_json((dap_chain_tx_out_t*)item);
                break;
            case TX_ITEM_TYPE_IN_REWARD:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_IN_REWARD");
                l_obj_item_data = dap_chain_datum_tx_item_in_reward_to_json((dap_chain_tx_in_reward_t*)item);
                break;
            case TX_ITEM_TYPE_IN_EMS:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_IN_EMS");
                l_obj_item_data = dap_chain_datum_tx_item_in_ems_to_json((dap_chain_tx_in_ems_t*)item);
                break;
            case TX_ITEM_TYPE_SIG:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_SIG");
                l_obj_item_data = dap_chain_datum_tx_item_sig_to_json((dap_chain_tx_sig_t*)item);
                break;
            case TX_ITEM_TYPE_RECEIPT:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_RECEIPT");
                l_obj_item_data = dap_chain_datum_tx_receipt_to_json((dap_chain_datum_tx_receipt_t*)item);
                break;
            case TX_ITEM_TYPE_IN_COND:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_IN_COND");
                l_obj_item_data = dap_chain_datum_tx_item_in_cond_to_json((dap_chain_tx_in_cond_t*)item);
                break;
            case TX_ITEM_TYPE_OUT_COND:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_OUT_COND");
                

                switch (((dap_chain_tx_out_cond_t*)item)->header.subtype) {
                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY:
                        l_obj_item_data = dap_chain_datum_tx_item_out_cond_srv_pay_to_json((dap_chain_tx_out_cond_t*)item);
                        break;
                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK:
                        l_obj_item_data = dap_chain_net_srv_stake_lock_cond_out_to_json((dap_chain_tx_out_cond_t*)item);
                        break;
                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_POS_DELEGATE:
                        l_obj_item_data = dap_chain_datum_tx_item_out_cond_srv_stake_to_json((dap_chain_tx_out_cond_t*)item);
                        break;
                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_XCHANGE:
                        l_obj_item_data = dap_chain_datum_tx_item_out_cond_srv_xchange_to_json((dap_chain_tx_out_cond_t*)item);
                        break;
                    case DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE:
                        l_obj_item_data = json_object_new_object();
                        break;
                   default:break;
                }
                // add time
                dap_time_t l_ts_exp = ((dap_chain_tx_out_cond_t*)item)->header.ts_expires;
                char l_time_str[32] = "never";
                if (l_ts_exp) {
                    dap_time_to_str_rfc822(l_time_str, DAP_TIME_STR_SIZE, l_ts_exp); /* Convert ts to  "Sat May 17 01:17:08 2014\n" */
                    l_time_str[strlen(l_time_str)-1] = '\0';                    /* Remove "\n"*/
                }
                json_object_object_add(l_obj_item_data, "ts_expires", json_object_new_string(l_time_str));
                json_object_object_add(l_obj_item_data, "subtype", json_object_new_string(dap_chain_tx_out_cond_subtype_to_str(((dap_chain_tx_out_cond_t*)item)->header.subtype)));
                char *l_val_str, *l_val_datoshi_str = dap_uint256_to_char(((dap_chain_tx_out_cond_t*)item)->header.value, &l_val_str);
                json_object_object_add(l_obj_item_data, "value", json_object_new_string(l_val_str));
                json_object_object_add(l_obj_item_data, "value_datoshi", json_object_new_string(l_val_datoshi_str));
                char uid_str[32];
                sprintf(uid_str, "0x%016"DAP_UINT64_FORMAT_x"", ((dap_chain_tx_out_cond_t*)item)->header.srv_uid.uint64);
                json_object_object_add(l_obj_item_data, "uid", json_object_new_string(uid_str));
                break;
            case TX_ITEM_TYPE_OUT_EXT:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_OUT_EXT");
                l_obj_item_data = dap_chain_datum_tx_item_out_ext_to_json((dap_chain_tx_out_ext_t*)item);
                break;
            case TX_ITEM_TYPE_TSD:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_TSD");
                l_obj_item_data = dap_chain_datum_tx_item_tsd_to_json((dap_chain_tx_tsd_t*)item);
                break;
            case TX_ITEM_TYPE_VOTE:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_VOTE");
                l_obj_item_data = dap_chain_datum_tx_item_vote_to_json((dap_chain_tx_vote_t*)item);
            break;
            case TX_ITEM_TYPE_VOTING:
                l_obj_item_type = json_object_new_string("TX_ITEM_TYPE_VOTING");
                l_obj_item_data = dap_chain_datum_tx_item_voting_tsd_to_json(a_tx);
            break;
            default: {
                char *l_hash_str;
                dap_get_data_hash_str_static(a_tx, dap_chain_datum_tx_get_size(a_tx), l_hash_str);
                log_it(L_NOTICE, "Transaction %s has an item whose type cannot be handled by the dap_chain_datum_tx_to_json function.", l_hash_str);
                break;
            }
        }
        if (!l_obj_item_type){
            json_object_array_add(l_obj_items, json_object_new_null());
        } else {
            if (!l_obj_item_data)
                l_obj_item_data = json_object_new_null();
            json_object *l_obj_item = json_object_new_object();
            if (!l_obj_item) {
                json_object_put(l_obj_item_type);
                json_object_put(l_obj_item_data);
                json_object_put(l_obj_items);
                dap_json_rpc_allocation_error;
                return NULL;
            }
            json_object_object_add(l_obj_item, "type", l_obj_item_type);
            json_object_object_add(l_obj_item, "data", l_obj_item_data);
            json_object_array_add(l_obj_items, l_obj_item);
        }

        l_tx_items_count += l_tx_item_size;
    }
    return l_obj_items;
}
