#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "dap_common.h"
#include "dap_string.h"
#include "dap_strfuncs.h"
#include "dap_chain_net_srv.h"
#include "dap_chain_net_srv_auctions.h"
#include "dap_chain_net_srv_order.h"
#include "dap_chain_net_tx.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_event.h"
#include "dap_chain_ledger.h"
#include "dap_chain_mempool.h"
#include "dap_chain_wallet.h"
#include "dap_config.h"
#include "json-c/json.h"

#define LOG_TAG "dap_chain_net_srv_auctions"

// Error codes
enum error_code {
    AUCTION_NO_ERROR = 0,
    NET_ARG_ERROR = 1,
    NET_ERROR = 2,
    AUCTION_HASH_ARG_ERROR = 3,
    AUCTION_HASH_FORMAT_ERROR = 4,
    WALLET_ARG_ERROR = 5,
    WALLET_OPEN_ERROR = 6,
    RANGE_ARG_ERROR = 7,
    RANGE_FORMAT_ERROR = 8,
    AMOUNT_ARG_ERROR = 9,
    AMOUNT_FORMAT_ERROR = 10,
    LOCK_ARG_ERROR = 11,
    LOCK_FORMAT_ERROR = 12,
    FEE_ARG_ERROR = 13,
    FEE_FORMAT_ERROR = 14,
    BID_TX_HASH_ARG_ERROR = 15,
    BID_TX_HASH_FORMAT_ERROR = 16,
    AUCTION_NOT_FOUND_ERROR = 17,
    BID_CREATE_ERROR = 18,
    WITHDRAW_CREATE_ERROR = 19,
    COMMAND_NOT_RECOGNIZED = 20
};

// Callbacks
static void s_auction_bid_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_prev_out_item);
static int s_auction_bid_callback_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, dap_chain_datum_tx_t *a_tx_in, bool a_owner);
static char *s_auction_bid_tx_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, const dap_hash_fast_t *a_auction_hash, 
                                     uint8_t a_range_end, uint256_t a_amount, dap_time_t a_lock_time, uint256_t a_fee);
int com_auction(int argc, char **argv, void **str_reply, int a_version);

/**
 * @brief Service initialization
 * @return Returns 0 on success
 */
int dap_chain_net_srv_auctions_init(void)
{
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID, s_auction_bid_callback_verificator, s_auction_bid_callback_updater, NULL);
    dap_cli_server_cmd_add ("auction", com_auction, "Auction commands",
                "bid -net <network> -auction <hash> -range <1..8> -amount <value> -lock <3..24> -fee <value> -w <wallet>\n"
                "\tPlace a bid on an auction\n\n"
                "withdraw -net <network> -bid_tx_hash <hash> -fee <value> -w <wallet>\n"
                "\tWithdraw a bid from an auction\n\n"
                "list -net <network> [-active_only]\n"
                "\tList all auctions or active auctions only\n\n"
                "info -net <network> -auction <hash>\n"
                "\tGet detailed information about an auction\n\n"
                "events -net <network> [-auction <hash>] [-type <event_type>] [-limit <count>]\n"
                "\tGet auction events with optional filtering\n\n"
                "Event types:\n"
                "  auction_created - New auction created\n"
                "  auction_started - Auction bidding started\n"
                "  auction_ended - Auction bidding ended\n"
                "  bid_placed - New bid placed\n"
                "  bid_withdrawn - Bid withdrawn\n"
                "  auction_completed - Auction completed with winner\n"
                "  auction_cancelled - Auction cancelled\n\n"
                "Rules:\n"
                "  - Range must be 1-8, higher range = higher priority\n"
                "  - Lock period: 3-24 hours, funds locked until withdrawal\n"
                "  - Minimum bid amount: 1 CELL\n"
                "  - Auction duration: 24-168 hours\n"
                "  - Winner determined by highest range, then highest amount\n"
                "  - Failed auctions: funds returned to bidders\n"
                "  - Withdrawal fee: 0.001 CELL");

        
    return 0;
}

/**
 * @brief Service deinitialization
 */
void dap_chain_net_srv_auctions_deinit(void)
{

}

static void s_auction_bid_callback_updater(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,
                                 dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_prev_out_item)
{

}

/**
 * @brief Verify auction bid conditional output
 * @param a_ledger Ledger instance
 * @param a_cond Conditional output to verify
 * @param a_tx_in Input transaction (withdrawal transaction)
 * @param a_owner Whether the transaction is from the owner (who created the lock)
 * @return Returns 0 on success, negative error code otherwise
 */
static int s_auction_bid_callback_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_cond, 
                                                    dap_chain_datum_tx_t *a_tx_in, bool a_owner)
{
    if (!a_cond) {
        log_it(L_WARNING, "NULL conditional output specified");
        return -1;
    }

    // Check if output type is auction bid
    if (a_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID) {
        log_it(L_WARNING, "Invalid conditional output subtype (expected auction bid)");
        return -2;
    }

    // Check range_end value
    if (a_cond->subtype.srv_auction_bid.range_end > 8) {
        log_it(L_WARNING, "Invalid range_end value %u (must be <= 8)", a_cond->subtype.srv_auction_bid.range_end);
        return -3;
    }

    // Only the owner (who created the bid/lock) can withdraw funds
    if (!a_owner) {
        log_it(L_WARNING, "Withdrawal denied: only the owner who created the bid can withdraw funds");
        return -9;
    }

    // 1. In withdrawal transaction, find the auction transaction hash from the conditional output
    dap_hash_fast_t l_auction_hash = a_cond->subtype.srv_auction_bid.auction_hash;
    char l_auction_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(&l_auction_hash, l_auction_hash_str, sizeof(l_auction_hash_str));
    
    log_it(L_DEBUG, "Verifying withdrawal for auction hash %s by owner", l_auction_hash_str);

    // 2. Find the auction transaction by hash
    dap_chain_datum_tx_t *l_auction_tx = dap_ledger_tx_find_by_hash(a_ledger, &l_auction_hash);
    if (!l_auction_tx) {
        log_it(L_WARNING, "Auction transaction %s not found in ledger", l_auction_hash_str);
        return -4;
    }

    // 3. Extract group name from the auction transaction
    char *l_group_name = NULL;
    
    // Look for event item in auction transaction to get group name
    byte_t *l_item = NULL;
    size_t l_item_size = 0;
    TX_ITEM_ITER_TX(l_item, l_item_size, l_auction_tx) {
        if (*l_item == TX_ITEM_TYPE_EVENT) {
            dap_chain_tx_item_event_t *l_event_item = (dap_chain_tx_item_event_t *)l_item;
            if (l_event_item->group_size > 0) {
                l_group_name = DAP_NEW_SIZE(char, l_event_item->group_size + 1);
                if (l_group_name) {
                    memcpy(l_group_name, l_event_item->group_name, l_event_item->group_size);
                    l_group_name[l_event_item->group_size] = '\0';
                }
                break;
            }
        }
    }

    if (!l_group_name) {
        log_it(L_WARNING, "Could not extract group name from auction transaction %s", l_auction_hash_str);
        return -5;
    }

    log_it(L_DEBUG, "Auction group name: %s", l_group_name);

    // 4. Use dap_ledger_event_get_list to get auction events
    dap_list_t *l_events_list = dap_ledger_event_get_list(a_ledger, l_group_name);
    if (!l_events_list) {
        log_it(L_WARNING, "No events found for auction group %s", l_group_name);
        DAP_DELETE(l_group_name);
        return -6;
    }

    DAP_DELETE(l_group_name);
    int ret_code = 0;
    // 5. Iterate through events to determine auction status
    dap_time_t l_auction_end_time = 0;
    
    for (dap_list_t *l_item = l_events_list; l_item; l_item = l_item->next) {
        dap_chain_tx_event_t *l_event = (dap_chain_tx_event_t *)l_item->data;
        if (!l_event) continue;

        switch (l_event->event_type){
            case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_CANCELLED:
                log_it(L_DEBUG, "Withdrawal allowed: auction %s was cancelled", l_auction_hash_str);
                ret_code = 0;
                break;   

            case DAP_CHAIN_TX_EVENT_TYPE_AUCTION_ENDED:
                // TODO:
                // 1. Get project id from bid transaction
                // 2. Check project won or lost
                // 3. Make decision about withdrawal validity

                dap_time_t l_current_time = dap_ledger_get_blockchain_time(a_ledger);
                dap_time_t l_lock_end_time = l_auction_end_time + a_cond->subtype.srv_auction_bid.lock_time;
                
                if (l_current_time >= l_lock_end_time) {
                    log_it(L_DEBUG, "Withdrawal allowed: auction %s won and lock period expired", l_auction_hash_str);
                    ret_code = 0;
                    break;
                } else {
                    log_it(L_WARNING, "Withdrawal denied: auction %s won but lock period not expired (current: %"DAP_UINT64_FORMAT_U", lock_end: %"DAP_UINT64_FORMAT_U")", 
                        l_auction_hash_str, l_current_time, l_lock_end_time);
                    ret_code = -7;
                    break;
                }
            default:
                break;
        }
    }

    // Clean up events list
    dap_list_free_full(l_events_list, dap_chain_datum_tx_event_delete);
    
    // Case 4: Auction status unknown or still active - withdrawal not valid
    log_it(L_WARNING, "Withdrawal denied: auction %s status unclear or still active", l_auction_hash_str);
    ret_code = -8;
    return ret_code;
}

/**
 * @brief Create auctions service
 * @param a_srv Parent service
 * @return Returns service instance or NULL on error
 */
dap_chain_net_srv_auctions_t *dap_chain_net_srv_auctions_create(dap_chain_net_srv_t *a_srv)
{
    dap_chain_net_srv_auctions_t *l_auctions = DAP_NEW_Z(dap_chain_net_srv_auctions_t);
    if(!l_auctions) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_auctions->parent = a_srv;
    return l_auctions;
}

/**
 * @brief Find auction by hash
 * @param a_auctions Service instance
 * @param a_hash Auction hash
 * @return Returns auction instance or NULL if not found
 */
dap_chain_net_srv_auction_t *dap_chain_net_srv_auctions_find(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_hash)
{
    if(!a_net || !a_hash)
        return NULL;
    
    // TODO: Implement auction search
    
    return NULL;
} 

/**
 * @brief Create auction bid transaction
 * @param a_net Network instance
 * @param a_key_from Wallet key for signing
 * @param a_auction_hash Hash of the auction being bid on
 * @param a_range_end CellSlot range end (1-8)
 * @param a_amount Bid amount in datoshi
 * @param a_lock_time Lock time duration in seconds
 * @param a_fee Validator fee
 * @return Returns transaction hash string or NULL on error
 */
static char *s_auction_bid_tx_create(dap_chain_net_t *a_net, dap_enc_key_t *a_key_from, const dap_hash_fast_t *a_auction_hash, 
                                     uint8_t a_range_end, uint256_t a_amount, dap_time_t a_lock_time, uint256_t a_fee)
{
    if (!a_net || !a_key_from || !a_auction_hash || IS_ZERO_256(a_amount) || a_range_end < 1 || a_range_end > 8)
        return NULL;

    dap_ledger_t *l_ledger = dap_ledger_by_net_name(a_net->pub.name);
    if (!l_ledger) {
        log_it(L_ERROR, "Can't find ledger for network %s", a_net->pub.name);
        return NULL;
    }

    const char *l_native_ticker = a_net->pub.native_ticker;
    dap_chain_addr_t l_addr_from = {};
    dap_chain_addr_fill_from_key(&l_addr_from, a_key_from, a_net->pub.id);

    // 1. Verify auction exists and is valid
    dap_chain_datum_tx_t *l_auction_tx = dap_ledger_tx_find_by_hash(l_ledger, a_auction_hash);
    if (!l_auction_tx) {
        log_it(L_ERROR, "Auction transaction not found");
        return NULL;
    }

    // Calculate total costs: bid amount + network fee + validator fee
    uint256_t l_net_fee = {}, l_total_cost = a_amount;
    dap_chain_addr_t l_addr_net_fee = {};
    bool l_net_fee_used = dap_chain_net_tx_get_fee(a_net->pub.id, &l_net_fee, &l_addr_net_fee);
    
    if (l_net_fee_used)
        SUM_256_256(l_total_cost, l_net_fee, &l_total_cost);
    SUM_256_256(l_total_cost, a_fee, &l_total_cost);

    // 2. Find UTXOs to cover the total cost (native tokens)
    dap_list_t *l_list_used_out = NULL;
    uint256_t l_value_transfer = {};
    if (dap_chain_wallet_cache_tx_find_outs_with_val(l_ledger->net, l_native_ticker, &l_addr_from, 
                                                    &l_list_used_out, l_total_cost, &l_value_transfer) == -101) {
        l_list_used_out = dap_ledger_get_list_tx_outs_with_val(l_ledger, l_native_ticker,
                                                              &l_addr_from, l_total_cost, &l_value_transfer);
    }
    if (!l_list_used_out) {
        log_it(L_ERROR, "Not enough funds to place bid");
        return NULL;
    }

    // 3. Create empty transaction
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if (!l_tx) {
        log_it(L_ERROR, "Failed to create transaction");
        dap_list_free_full(l_list_used_out, NULL);
        return NULL;
    }

    // 4. Add 'in' items (native tokens)
    uint256_t l_value_added = dap_chain_datum_tx_add_in_item_list(&l_tx, l_list_used_out);
    dap_list_free_full(l_list_used_out, NULL);
    if (!EQUAL_256(l_value_added, l_value_transfer)) {
        log_it(L_ERROR, "Failed to add input items");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // 5. Add 'in_ems' item (emission input for m-tokens)
    dap_chain_id_t l_chain_id = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX)->id;
    dap_hash_fast_t l_blank_hash = {};
    dap_chain_tx_in_ems_t *l_in_ems = dap_chain_datum_tx_item_in_ems_create(l_chain_id, &l_blank_hash, "mCAPS");
    if (l_in_ems) {
        dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_in_ems);
        DAP_DELETE(l_in_ems);
    }

    // 6. Add conditional output (auction bid lock)
    dap_chain_net_srv_uid_t l_srv_uid = {.uint64 = DAP_CHAIN_NET_SRV_AUCTION_ID};
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        l_srv_uid, a_amount, a_auction_hash, a_range_end, a_lock_time, NULL, 0);
    if (!l_out_cond) {
        log_it(L_ERROR, "Failed to create auction bid conditional output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)l_out_cond);
    DAP_DELETE(l_out_cond);

    // 7. Add m-tokens output
    uint256_t l_mcaps_amount = a_amount; // 1:1 ratio for now
    if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_from, l_mcaps_amount, "mCAPS") != 1) {
        log_it(L_ERROR, "Failed to add m-tokens output");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // 8. Add network fee output
    if (l_net_fee_used) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_net_fee, l_net_fee, l_native_ticker) != 1) {
            log_it(L_ERROR, "Failed to add network fee output");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // 9. Add validator fee
    if (!IS_ZERO_256(a_fee)) {
        if (dap_chain_datum_tx_add_fee_item(&l_tx, a_fee) != 1) {
            log_it(L_ERROR, "Failed to add validator fee");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // 10. Add change output if needed
    uint256_t l_change = {};
    SUBTRACT_256_256(l_value_transfer, l_total_cost, &l_change);
    if (!IS_ZERO_256(l_change)) {
        if (dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr_from, l_change, l_native_ticker) != 1) {
            log_it(L_ERROR, "Failed to add change output");
            dap_chain_datum_tx_delete(l_tx);
            return NULL;
        }
    }

    // 11. Add auction bid placed event
    char l_auction_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
    dap_chain_hash_fast_to_str(a_auction_hash, l_auction_hash_str, sizeof(l_auction_hash_str));
    
    dap_chain_tx_item_event_t *l_event_item = dap_chain_datum_tx_event_create(
        l_auction_hash_str, DAP_CHAIN_TX_EVENT_TYPE_AUCTION_BID_PLACED);
    if (!l_event_item) {
        log_it(L_ERROR, "Failed to create auction bid event");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    if (dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*)l_event_item) != 1) {
        log_it(L_ERROR, "Failed to add auction bid event");
        DAP_DELETE(l_event_item);
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }
    DAP_DELETE(l_event_item);

    // 12. Sign transaction
    if (dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from) != 1) {
        log_it(L_ERROR, "Failed to sign transaction");
        dap_chain_datum_tx_delete(l_tx);
        return NULL;
    }

    // 13. Create datum and add to mempool
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_chain_datum_tx_delete(l_tx);
    
    if (!l_datum) {
        log_it(L_ERROR, "Failed to create transaction datum");
        return NULL;
    }

    // 14. Add to mempool
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    
    if (!l_ret) {
        log_it(L_ERROR, "Failed to add auction bid transaction to mempool");
        return NULL;
    }
    
    log_it(L_INFO, "Successfully created and added auction bid transaction to mempool: %s", l_ret);
    return l_ret;
}

/**
 * @brief Handle error codes and output error messages
 * @param a_err_code Error code
 * @param a_str_reply String for reply
 * @param a_args Additional arguments for error message
 */
static void s_error_handler(enum error_code a_err_code, dap_string_t *a_str_reply, const char *a_args)
{
    dap_string_append_printf(a_str_reply, "ERROR!\n");
    switch(a_err_code) {
        case NET_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction command requires parameter -net");
            break;
        case NET_ERROR:
            dap_string_append_printf(a_str_reply, "Network '%s' not found", a_args);
            break;
        case AUCTION_HASH_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction command requires parameter -auction");
            break;
        case AUCTION_HASH_FORMAT_ERROR:
            dap_string_append_printf(a_str_reply, "Invalid auction hash format");
            break;
        case WALLET_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction command requires parameter -w");
            break;
        case WALLET_OPEN_ERROR:
            dap_string_append_printf(a_str_reply, "Can't open wallet '%s'", a_args);
            break;
        case RANGE_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction bid command requires parameter -range");
            break;
        case RANGE_FORMAT_ERROR:
            dap_string_append_printf(a_str_reply, "Range must be between 1 and 8");
            break;
        case AMOUNT_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction bid command requires parameter -amount");
            break;
        case AMOUNT_FORMAT_ERROR:
            dap_string_append_printf(a_str_reply, "Invalid amount format");
            break;
        case LOCK_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction bid command requires parameter -lock");
            break;
        case LOCK_FORMAT_ERROR:
            dap_string_append_printf(a_str_reply, "Lock period must be between 3 and 24 months");
            break;
        case FEE_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction command requires parameter -fee");
            break;
        case FEE_FORMAT_ERROR:
            dap_string_append_printf(a_str_reply, "Invalid fee format");
            break;
        case BID_TX_HASH_ARG_ERROR:
            dap_string_append_printf(a_str_reply, "auction withdraw command requires parameter -bid_tx_hash");
            break;
        case BID_TX_HASH_FORMAT_ERROR:
            dap_string_append_printf(a_str_reply, "Invalid bid transaction hash format");
            break;
        case AUCTION_NOT_FOUND_ERROR:
            dap_string_append_printf(a_str_reply, "Auction '%s' not found", a_args);
            break;
        case BID_CREATE_ERROR:
            dap_string_append_printf(a_str_reply, "Error creating bid transaction");
            break;
        case WITHDRAW_CREATE_ERROR:
            dap_string_append_printf(a_str_reply, "Error creating withdraw transaction");
            break;
        case COMMAND_NOT_RECOGNIZED:
            dap_string_append_printf(a_str_reply, "Command '%s' not recognized", a_args);
            break;
        default:
            dap_string_append_printf(a_str_reply, "Unknown error");
            break;
    }
    dap_string_append_printf(a_str_reply, "\n");
}

/**
 * @brief Main auction command handler
 * @param argc Argument count
 * @param argv Arguments array
 * @param str_reply Reply string
 * @param a_version Protocol version
 * @return Error code
 */
int com_auction(int argc, char **argv, void **str_reply, int a_version)
{
    enum {
        CMD_NONE, CMD_BID, CMD_WITHDRAW, CMD_LIST, CMD_INFO, CMD_EVENTS
    };

    int arg_index = 1;
    int cmd_num = CMD_NONE;
    const char *str_tmp = NULL;
    json_object **l_json_arr_reply = (json_object **) str_reply;
    
    // Parse command
    if(arg_index >= argc) {
        dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Command not specified");
        return -1;
    }

    str_tmp = argv[arg_index];
    if(!strcmp(str_tmp, "bid"))
        cmd_num = CMD_BID;
    else if(!strcmp(str_tmp, "withdraw"))
        cmd_num = CMD_WITHDRAW;
    else if(!strcmp(str_tmp, "list"))
        cmd_num = CMD_LIST;
    else if(!strcmp(str_tmp, "info"))
        cmd_num = CMD_INFO;
    else if(!strcmp(str_tmp, "events"))
        cmd_num = CMD_EVENTS;
    else {
        dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Command %s not recognized", str_tmp);
        return -1;
    }

    arg_index++;

    // Parse network
    dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-net", &str_tmp);
    if(!str_tmp) {
        dap_json_rpc_error_add(*l_json_arr_reply, NET_ARG_ERROR, "Network not specified");
        return -1;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_name(str_tmp);
    if(!l_net) {
        dap_json_rpc_error_add(*l_json_arr_reply, NET_ERROR, "Network '%s' not found", str_tmp);
        return -1;
    }

    switch(cmd_num) {
        case CMD_BID: {
            // Parse auction hash
            const char *l_auction_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-auction", &l_auction_hash_str);
            if(!l_auction_hash_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_HASH_ARG_ERROR, "Auction hash not specified");
                return -1;
            }

            // Parse wallet
            const char *l_wallet_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_str);
            if(!l_wallet_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, WALLET_ARG_ERROR, "Wallet not specified");
                return -1;
            }

            // Parse range
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-range", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, RANGE_ARG_ERROR, "Range not specified");
                return -1;
            }
            uint8_t l_range_end = (uint8_t)atoi(str_tmp);
            if(l_range_end < 1 || l_range_end > 8) {
                dap_json_rpc_error_add(*l_json_arr_reply, RANGE_FORMAT_ERROR, "Range must be between 1 and 8");
                return -1;
            }

            // Parse amount
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-amount", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, AMOUNT_ARG_ERROR, "Amount not specified");
                return -1;
            }
            uint256_t l_amount = dap_chain_balance_scan(str_tmp);
            if(IS_ZERO_256(l_amount)) {
                dap_json_rpc_error_add(*l_json_arr_reply, AMOUNT_FORMAT_ERROR, "Invalid amount format");
                return -1;
            }

            // Parse lock period
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-lock", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, LOCK_ARG_ERROR, "Lock period not specified");
                return -1;
            }
            uint8_t l_lock_months = (uint8_t)atoi(str_tmp);
            if(l_lock_months < 3 || l_lock_months > 24) {
                dap_json_rpc_error_add(*l_json_arr_reply, LOCK_FORMAT_ERROR, "Lock period must be between 3 and 24 months");
                return -1;
            }

            // Parse fee
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_ARG_ERROR, "Fee not specified");
                return -1;
            }
            uint256_t l_fee = dap_chain_balance_scan(str_tmp);
            if(IS_ZERO_256(l_fee)) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_FORMAT_ERROR, "Invalid fee format");
                return -1;
            }

            // Parse auction hash and convert to hash
            dap_hash_fast_t l_auction_hash = {};
            if (dap_chain_hash_fast_from_str(l_auction_hash_str, &l_auction_hash) != 0) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_HASH_FORMAT_ERROR, "Invalid auction hash format");
                return -1;
            }

            // Convert lock period from months to seconds
            dap_time_t l_lock_time = (dap_time_t)l_lock_months * 30 * 24 * 3600; // months to seconds

            // Open wallet
            dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_chain_wallet_get_path(g_config), NULL);
            if (!l_wallet) {
                dap_json_rpc_error_add(*l_json_arr_reply, WALLET_OPEN_ERROR, "Can't open wallet '%s'", l_wallet_str);
                return -1;
            }

            // Create auction bid transaction
            char *l_tx_hash_str = s_auction_bid_tx_create(l_net, l_wallet->key, &l_auction_hash, 
                                                         l_range_end, l_amount, l_lock_time, l_fee);
            
            // Close wallet
            dap_chain_wallet_close(l_wallet);

            if (l_tx_hash_str) {
                // Success - return transaction hash
                json_object *l_json_obj = json_object_new_object();
                json_object_object_add(l_json_obj, "command", json_object_new_string("bid"));
                json_object_object_add(l_json_obj, "status", json_object_new_string("success"));
                json_object_object_add(l_json_obj, "tx_hash", json_object_new_string(l_tx_hash_str));
                json_object_object_add(l_json_obj, "auction_hash", json_object_new_string(l_auction_hash_str));
                json_object_object_add(l_json_obj, "range_end", json_object_new_int(l_range_end));
                
                char *l_amount_str; dap_uint256_to_char(l_amount, &l_amount_str);
                json_object_object_add(l_json_obj, "amount", json_object_new_string(l_amount_str));
                
                char *l_fee_str; dap_uint256_to_char(l_fee, &l_fee_str);
                json_object_object_add(l_json_obj, "fee", json_object_new_string(l_fee_str));
                
                json_object_object_add(l_json_obj, "lock_months", json_object_new_int(l_lock_months));
                json_object_array_add(*l_json_arr_reply, l_json_obj);
                
                DAP_DELETE(l_tx_hash_str);
            } else {
                // Error creating transaction
                dap_json_rpc_error_add(*l_json_arr_reply, BID_CREATE_ERROR, "Error creating bid transaction");
                return -1;
            }
        } break;

        case CMD_WITHDRAW: {
            // Parse bid transaction hash
            const char *l_bid_tx_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-bid_tx_hash", &l_bid_tx_hash_str);
            if(!l_bid_tx_hash_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, BID_TX_HASH_ARG_ERROR, "Bid transaction hash not specified");
                return -1;
            }

            // Parse wallet
            const char *l_wallet_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-w", &l_wallet_str);
            if(!l_wallet_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, WALLET_ARG_ERROR, "Wallet not specified");
                return -1;
            }

            // Parse fee
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-fee", &str_tmp);
            if(!str_tmp) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_ARG_ERROR, "Fee not specified");
                return -1;
            }
            uint256_t l_fee = dap_chain_balance_scan(str_tmp);
            if(IS_ZERO_256(l_fee)) {
                dap_json_rpc_error_add(*l_json_arr_reply, FEE_FORMAT_ERROR, "Invalid fee format");
                return -1;
            }

            // TODO: Implement withdraw logic
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("withdraw"));
            json_object_object_add(l_json_obj, "status", json_object_new_string("not_implemented"));
            json_object_object_add(l_json_obj, "bid_tx_hash", json_object_new_string(l_bid_tx_hash_str));
            json_object_object_add(l_json_obj, "fee", json_object_new_string(str_tmp));
            json_object_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        case CMD_LIST: {
            bool l_active_only = dap_cli_server_cmd_check_option(argv, arg_index, argc, "-active_only");
            
            // TODO: Implement auction listing logic
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("list"));
            json_object_object_add(l_json_obj, "status", json_object_new_string("not_implemented"));
            json_object_object_add(l_json_obj, "active_only", json_object_new_boolean(l_active_only));
            json_object_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        case CMD_INFO: {
            // Parse auction hash
            const char *l_auction_hash_str = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-auction", &l_auction_hash_str);
            if(!l_auction_hash_str) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_HASH_ARG_ERROR, "Auction hash not specified");
                return -1;
            }
            dap_hash_fast_t l_auction_hash;
            dap_chain_hash_fast_from_str(l_auction_hash_str, &l_auction_hash);
            dap_chain_net_srv_auction_t *l_auction = dap_chain_net_srv_auctions_find(l_net, &l_auction_hash);
            if(!l_auction) {
                dap_json_rpc_error_add(*l_json_arr_reply, AUCTION_NOT_FOUND_ERROR, "Auction not found");
                return -1;
            }

            // TODO: Implement auction info logic
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("info"));
            json_object_object_add(l_json_obj, "status", json_object_new_string("not_implemented"));
            json_object_object_add(l_json_obj, "auction_hash", json_object_new_string(l_auction_hash_str));
            json_object_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        case CMD_EVENTS: {
            // Parse optional parameters
            const char *l_auction_hash_str = NULL;
            const char *l_event_type = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-auction", &l_auction_hash_str);
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-type", &l_event_type);
            
            str_tmp = NULL;
            dap_cli_server_cmd_find_option_val(argv, arg_index, argc, "-limit", &str_tmp);
            uint32_t l_limit = str_tmp ? (uint32_t)atoi(str_tmp) : 50;

            // TODO: Implement events listing logic
            json_object *l_json_obj = json_object_new_object();
            json_object_object_add(l_json_obj, "command", json_object_new_string("events"));
            json_object_object_add(l_json_obj, "status", json_object_new_string("not_implemented"));
            if(l_auction_hash_str)
                json_object_object_add(l_json_obj, "auction_hash", json_object_new_string(l_auction_hash_str));
            if(l_event_type)
                json_object_object_add(l_json_obj, "event_type", json_object_new_string(l_event_type));
            json_object_object_add(l_json_obj, "limit", json_object_new_int(l_limit));
            json_object_array_add(*l_json_arr_reply, l_json_obj);
        } break;

        default:
            dap_json_rpc_error_add(*l_json_arr_reply, COMMAND_NOT_RECOGNIZED, "Unknown command");
            return -1;
    }

    return 0;
}