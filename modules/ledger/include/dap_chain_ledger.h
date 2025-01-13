/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
 * All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once
#include <stdint.h>
#include <stdbool.h>
#include "dap_common.h"
#include "dap_hash.h"
#include "dap_list.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_token.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_datum_anchor.h"
#include "dap_chain_net.h"

#define DAP_CHAIN_NET_SRV_TRANSFER_ID 0x07
#define DAP_CHAIN_NET_SRV_BLOCK_REWARD_ID 0x08

typedef struct dap_ledger {
    dap_chain_net_t *net;
    bool is_hardfork_state;
    void *_internal;
} dap_ledger_t;

typedef struct dap_ledger_tracker {
    dap_hash_fast_t voting_hash;
    uint256_t colored_value;
} DAP_ALIGN_PACKED dap_ledger_tracker_t;

typedef struct dap_ledger_hardfork_balances {
    dap_chain_addr_t addr;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t value;
    dap_list_t *trackers;
    struct dap_ledger_hardfork_balances *prev, *next;
} dap_ledger_hardfork_balances_t;

typedef struct dap_ledger_hardfork_condouts {
    dap_hash_fast_t hash;
    dap_chain_tx_out_cond_t *cond;
    dap_chain_tx_sig_t *sign;
    const char *ticker;
    dap_list_t *trackers;
    struct dap_ledger_hardfork_condouts *prev, *next;
} dap_ledger_hardfork_condouts_t;

typedef struct dap_ledger_hardfork_anchors {
    uint16_t decree_subtype;
    dap_chain_datum_anchor_t *anchor;
    struct dap_ledger_hardfork_anchors *prev, *next;
} dap_ledger_hardfork_anchors_t;
/**
 * @brief Error codes for accepting a transaction to the ledger.
 */
typedef enum dap_ledger_check_error {
    DAP_LEDGER_CHECK_OK = 0,
    DAP_LEDGER_CHECK_INVALID_ARGS,
    DAP_LEDGER_CHECK_INVALID_SIZE,
    DAP_LEDGER_CHECK_ALREADY_CACHED,
    DAP_LEDGER_CHECK_PARSE_ERROR,
    DAP_LEDGER_CHECK_APPLY_ERROR,
    DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY,
    DAP_LEDGER_CHECK_INTEGER_OVERFLOW,
    DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS,
    DAP_LEDGER_CHECK_TICKER_NOT_FOUND,
    DAP_LEDGER_CHECK_INVALID_TICKER,
    DAP_LEDGER_CHECK_ZERO_VALUE,
    DAP_LEDGER_CHECK_ADDR_FORBIDDEN,
    DAP_LEDGER_CHECK_WHITELISTED,
    /* TX check return codes */
    DAP_LEDGER_TX_CHECK_IN_EMS_ALREADY_USED,
    DAP_LEDGER_TX_CHECK_STAKE_LOCK_IN_EMS_ALREADY_USED,
    DAP_LEDGER_TX_CHECK_EMISSION_NOT_FOUND,
    DAP_LEDGER_TX_CHECK_TX_NO_VALID_INPUTS,
    DAP_LEDGER_TX_CHECK_STAKE_LOCK_INVALID_TOKEN,
    DAP_LEDGER_TX_CHECK_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS,
    DAP_LEDGER_TX_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS,
    DAP_LEDGER_TX_CHECK_NO_OUT_ITEMS_FOR_BASE_TX,
    DAP_LEDGER_TX_CHECK_STAKE_LOCK_UNEXPECTED_VALUE,
    DAP_LEDGER_TX_CHECK_STAKE_LOCK_OTHER_TICKER_EXPECTED,
    DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED,
    DAP_LEDGER_TX_CHECK_PREV_TX_NOT_FOUND,
    DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_NOT_FOUND,
    DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_MISSTYPED,
    DAP_LEDGER_TX_CHECK_PKEY_HASHES_DONT_MATCH,
    DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX,
    DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET,
    DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE,
    DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS,
    DAP_LEDGER_TX_CHECK_REWARD_ITEM_ALREADY_USED,
    DAP_LEDGER_TX_CHECK_REWARD_ITEM_ILLEGAL,
    DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER,
    DAP_LEDGER_TX_CHECK_UNEXPECTED_TOKENIZED_OUT,
    DAP_LEDGER_TX_CHECK_NOT_ENOUGH_FEE,
    DAP_LEDGER_TX_CHECK_NOT_ENOUGH_TAX,
    DAP_LEDGER_TX_CHECK_FOR_REMOVING_CANT_FIND_TX,
    /* Emisssion check return codes */
    DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY,
    DAP_LEDGER_EMISSION_CHECK_LEGACY_FORBIDDEN,
    /* Token declaration/update return codes */
    DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS,
    DAP_LEDGER_TOKEN_ADD_CHECK_LEGACY_FORBIDDEN,
    DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_SUPPLY,
    DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR,
    DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH,
    DAP_LEDGER_TOKEN_ADD_CHECK_TSD_PKEY_MISMATCH,
    DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN,
    DAP_LEDGER_TOKEN_ADD_CHECK_TSD_OTHER_TICKER_EXPECTED,
    DAP_LEDGER_TX_CHECK_MULTIPLE_OUTS_TO_OTHER_NET
} dap_ledger_check_error_t;

DAP_STATIC_INLINE const char *dap_ledger_check_error_str(dap_ledger_check_error_t a_error)
{
    switch (a_error) {
    case DAP_LEDGER_CHECK_OK: return "No error";
    case DAP_LEDGER_CHECK_INVALID_ARGS: return "Invalid arguments";
    case DAP_LEDGER_CHECK_INVALID_SIZE: return "Incorrect size of datum or datum's content";
    case DAP_LEDGER_CHECK_ALREADY_CACHED: return "Datum already cached in ledger";
    case DAP_LEDGER_CHECK_PARSE_ERROR: return "Incorrect datum interrnal structure, can't pasre it";
    case DAP_LEDGER_CHECK_APPLY_ERROR: return "Datum can't be applied";
    case DAP_LEDGER_CHECK_NOT_ENOUGH_MEMORY: return "Not enough memory";
    case DAP_LEDGER_CHECK_INTEGER_OVERFLOW: return "Incorrect datum values relationship lead to integer overflow, can't process";
    case DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS: return "No enough valid signatures in datum";
    case DAP_LEDGER_CHECK_TICKER_NOT_FOUND: return "Can't find specified token ticker";
    case DAP_LEDGER_CHECK_INVALID_TICKER: return "Specified token ticker is invalid";
    case DAP_LEDGER_CHECK_ZERO_VALUE: return "Unacceptable zero value";
    case DAP_LEDGER_CHECK_ADDR_FORBIDDEN: return "Specified address is forbidden";
    case DAP_LEDGER_CHECK_WHITELISTED: return "Datum is in hard accept list";
    /* TX check return codes */
    case DAP_LEDGER_TX_CHECK_IN_EMS_ALREADY_USED: return "Double spend attempt for emission";
    case DAP_LEDGER_TX_CHECK_STAKE_LOCK_IN_EMS_ALREADY_USED: return "Double spend attempt for stake-lock emission";
    case DAP_LEDGER_TX_CHECK_EMISSION_NOT_FOUND: return "Specified emission not found in ledger";
    case DAP_LEDGER_TX_CHECK_TX_NO_VALID_INPUTS: return "Transaction has no valid inputs, can't process";
    case DAP_LEDGER_TX_CHECK_STAKE_LOCK_INVALID_TOKEN: return "Incorrect deledated token specified in stake-lock transaction";
    case DAP_LEDGER_TX_CHECK_STAKE_LOCK_NO_OUT_COND_FOR_IN_EMS: return "Condtional output for stake-lock emission not found";
    case DAP_LEDGER_TX_CHECK_NO_OUT_EXT_FOR_GIRDLED_IN_EMS: return "Tokenized output for stake-lock girdled emission not found";
    case DAP_LEDGER_TX_CHECK_NO_OUT_ITEMS_FOR_BASE_TX: return "Output for basic transaction not found";
    case DAP_LEDGER_TX_CHECK_STAKE_LOCK_UNEXPECTED_VALUE: return "Incorrect value for stake-lock emission, should be stake * rate";
    case DAP_LEDGER_TX_CHECK_STAKE_LOCK_OTHER_TICKER_EXPECTED: return "Incorrect token ticker for stake-lock emission";
    case DAP_LEDGER_TX_CHECK_OUT_ITEM_ALREADY_USED: return "Double spend attempt for transaction output";
    case DAP_LEDGER_TX_CHECK_PREV_TX_NOT_FOUND: return "No previous transaction found";
    case DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_NOT_FOUND: return "Specified output number not found in previous transaction";
    case DAP_LEDGER_TX_CHECK_PREV_OUT_ITEM_MISSTYPED: return "Previuos transaction output has unknown type, possible ledger corruption";
    case DAP_LEDGER_TX_CHECK_PKEY_HASHES_DONT_MATCH: return "Trying to spend transaction output from wrongful wallet";
    case DAP_LEDGER_TX_CHECK_PREV_OUT_ALREADY_USED_IN_CURRENT_TX: return "Double spend attempt within single transaction";
    case DAP_LEDGER_TX_CHECK_NO_VERIFICATOR_SET: return "No verificator found for specified conditional ipnput";
    case DAP_LEDGER_TX_CHECK_VERIFICATOR_CHECK_FAILURE: return "Verificator check return error";
    case DAP_LEDGER_TX_CHECK_SUM_INS_NOT_EQUAL_SUM_OUTS: return "Sum of transaction outputs isn't equal to sum of its inputs";
    case DAP_LEDGER_TX_CHECK_REWARD_ITEM_ALREADY_USED: return "Double spend attempt for reward";
    case DAP_LEDGER_TX_CHECK_REWARD_ITEM_ILLEGAL: return "Wrongful reward item in transaction";
    case DAP_LEDGER_TX_CHECK_NO_MAIN_TICKER: return "Can't calculate main ticker found for transaction";
    case DAP_LEDGER_TX_CHECK_UNEXPECTED_TOKENIZED_OUT: return "Tokenized out is forbidden for single-channel trandactions";
    case DAP_LEDGER_TX_CHECK_NOT_ENOUGH_FEE: return "Not enough network fee for transaction processing";
    case DAP_LEDGER_TX_CHECK_NOT_ENOUGH_TAX: return "Not enough sovereign tax provided with current transaction";
    case DAP_LEDGER_TX_CHECK_FOR_REMOVING_CANT_FIND_TX: return "Can't find tx in ledger for removing.";
    case DAP_LEDGER_TX_CHECK_MULTIPLE_OUTS_TO_OTHER_NET: return "The transaction was rejected because it contains multiple outputs to other networks.";
    /* Emisssion check return codes */
    case DAP_LEDGER_EMISSION_CHECK_VALUE_EXCEEDS_CURRENT_SUPPLY: return "Value of emission execeeds current token supply";
    case DAP_LEDGER_EMISSION_CHECK_LEGACY_FORBIDDEN: return "Legacy type of emissions are present for old chains comliance only";
    /* Token declaration/update return codes */
    case DAP_LEDGER_TOKEN_ADD_CHECK_NOT_ENOUGH_UNIQUE_SIGNS: return "Not all token signs is unique";
    case DAP_LEDGER_TOKEN_ADD_CHECK_LEGACY_FORBIDDEN: return "Legacy type of tokens are present for old chains comliance only";
    case DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_SUPPLY: return "Specified supply must be greater than current one";
    case DAP_LEDGER_TOKEN_ADD_CHECK_TSD_INVALID_ADDR: return "Specified address has invalid format";
    case DAP_LEDGER_TOKEN_ADD_CHECK_TSD_ADDR_MISMATCH: return "Specified address can't be processed cause double (for adding) or absent (for removing)";
    case DAP_LEDGER_TOKEN_ADD_CHECK_TSD_PKEY_MISMATCH: return "Specified public key or its hash can't be processed cause double (for adding) or absent (for removing)";
    case DAP_LEDGER_TOKEN_ADD_CHECK_TSD_FORBIDDEN: return "Specified TSD section type is not allowed in datum token of specified type";
    case DAP_LEDGER_TOKEN_ADD_CHECK_TSD_OTHER_TICKER_EXPECTED: return "Incorrect token ticker for delegated token";
    default: return "Unknown error";
    }
}

typedef enum dap_ledger_notify_opcodes {
    DAP_LEDGER_NOTIFY_OPCODE_ADDED = 'a', // 0x61
    DAP_LEDGER_NOTIFY_OPCODE_DELETED = 'd', // 0x64 
} dap_ledger_notify_opcodes_t;
typedef enum dap_chain_tx_tag_action_type {    

    //subtags, till 32
    DAP_CHAIN_TX_TAG_ACTION_UNKNOWN  =              1 << 1,
    
    DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REGULAR =      1 << 2,
    DAP_CHAIN_TX_TAG_ACTION_TRANSFER_COMISSION =    1 << 3,
    DAP_CHAIN_TX_TAG_ACTION_TRANSFER_CROSSCHAIN =   1 << 4,
    DAP_CHAIN_TX_TAG_ACTION_TRANSFER_REWARD =       1 << 5,

    DAP_CHAIN_TX_TAG_ACTION_OPEN =                  1 << 6,
    DAP_CHAIN_TX_TAG_ACTION_USE =                   1 << 7,
    DAP_CHAIN_TX_TAG_ACTION_EXTEND =                1 << 8,
    DAP_CHAIN_TX_TAG_ACTION_CHANGE =                1 << 9,
    DAP_CHAIN_TX_TAG_ACTION_CLOSE =                 1 << 10,

    DAP_CHAIN_TX_TAG_ACTION_VOTING =                1 << 11,
    DAP_CHAIN_TX_TAG_ACTION_VOTE =                  1 << 12,
   
    DAP_CHAIN_TX_TAG_ACTION_ALL =                          ~0,
} dap_chain_tx_tag_action_type_t;

typedef struct dap_ledger_datum_iter {
    dap_chain_net_t *net;
    dap_chain_datum_tx_t *cur;
    dap_chain_hash_fast_t cur_hash;
    bool is_unspent;
    int ret_code;
    void *cur_ledger_tx_item;
} dap_ledger_datum_iter_t;

typedef struct dap_ledger_datum_iter_data {
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint32_t action;
    dap_chain_srv_uid_t uid;
} dap_ledger_datum_iter_data_t;

typedef int   (*dap_ledger_cond_in_verify_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,  dap_hash_fast_t *a_tx_in_hash,  dap_chain_tx_out_cond_t *a_prev_cond, bool a_owner);
typedef int  (*dap_ledger_cond_out_verify_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_out, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond);
typedef void     (*dap_ledger_cond_in_add_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,  dap_hash_fast_t *a_tx_in_hash,  dap_chain_tx_out_cond_t *a_prev_cond);
typedef void    (*dap_ledger_cond_out_add_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_out, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond);
typedef void  (*dap_ledger_cond_in_delete_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in,  dap_hash_fast_t *a_tx_in_hash,  dap_chain_tx_out_cond_t *a_prev_cond);
typedef void (*dap_ledger_cond_out_delete_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_out, dap_hash_fast_t *a_tx_out_hash, dap_chain_tx_out_cond_t *a_cond);
typedef void (* dap_ledger_tx_add_notify_t)(void *a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_ledger_notify_opcodes_t a_opcode);
typedef void (* dap_ledger_bridged_tx_notify_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg, dap_ledger_notify_opcodes_t a_opcode);
typedef bool (*dap_ledger_cache_tx_check_callback_t)(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash);
typedef int (*dap_ledger_voting_callback_t)(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_apply);
typedef bool (*dap_ledger_voting_delete_callback_t)(dap_ledger_t *a_ledger, dap_chain_tx_item_type_t a_type, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash);
typedef dap_time_t (*dap_ledger_voting_expire_callback_t)(dap_ledger_t *a_ledger, dap_hash_fast_t *a_voting_hash);
typedef bool (*dap_ledger_tag_check_callback_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_datum_tx_item_groups_t *a_items_grp, dap_chain_tx_tag_action_type_t *a_action);
typedef bool (*dap_ledger_tax_callback_t)(dap_chain_net_id_t a_net_id, dap_hash_fast_t *a_signer_pkey_hash, dap_chain_addr_t *a_tax_addr, uint256_t *a_tax_value);

//Change this UUID to automatically reload ledger cache on next node startup
#define DAP_LEDGER_CACHE_RELOAD_ONCE_UUID "0c92b759-a565-448f-b8bd-99103dacf7fc"

// Checks the emission of the token, usualy on zero chain
#define DAP_LEDGER_CHECK_TOKEN_EMISSION     0x0001

// Check double spending in local cell
#define DAP_LEDGER_CHECK_LOCAL_DS           0x0002

// Check the double spending in all cells
#define DAP_LEDGER_CHECK_CELLS_DS           0x0100

#define DAP_LEDGER_CACHE_ENABLED            0x0200

#define DAP_LEDGER_MAPPED                   0x0400

#define DAP_LEDGER_THRESHOLD_ENABLED        0x0800

// Error code for no previous transaction (for stay in mempool)
#define DAP_CHAIN_CS_VERIFY_CODE_TX_NO_PREVIOUS     DAP_LEDGER_TX_CHECK_PREV_TX_NOT_FOUND
// Error code for no emission for a transaction (for stay in mempool)
#define DAP_CHAIN_CS_VERIFY_CODE_TX_NO_EMISSION     DAP_LEDGER_TX_CHECK_EMISSION_NOT_FOUND
// Error code for not enough valid emission signs (for stay in mempool)
#define DAP_CHAIN_CS_VERIFY_CODE_NOT_ENOUGH_SIGNS   DAP_LEDGER_CHECK_NOT_ENOUGH_VALID_SIGNS
// Error code for no decree for anchor (for stay in mempool)
#define DAP_CHAIN_CS_VERIFY_CODE_NO_DECREE          -1113

#define DAP_LEDGER_TOKENS_STR              "tokens"
#define DAP_LEDGER_EMISSIONS_STR           "emissions"
#define DAP_LEDGER_STAKE_LOCK_STR          "stake_lock"
#define DAP_LEDGER_TXS_STR                 "txs"
#define DAP_LEDGER_SPENT_TXS_STR           "spent_txs"
#define DAP_LEDGER_BALANCES_STR            "balances"

int dap_ledger_init();
void dap_ledger_deinit();

dap_ledger_t *dap_ledger_create(dap_chain_net_t *a_net, uint16_t a_flags);

// Clear & remove dap_ledger_t structure
void dap_ledger_handle_free(dap_ledger_t *a_ledger);

DAP_STATIC_INLINE char *dap_ledger_get_gdb_group(dap_ledger_t *a_ledger, const char *a_suffix)
{
    return a_ledger && a_ledger->net && a_suffix
            ? dap_strdup_printf("local.ledger-cache.%s.%s", a_ledger->net->pub.name, a_suffix)
            : NULL;
}

/**
 * Add new transaction to the cache
 *
 * return 1 OK, -1 error
 */
int dap_ledger_tx_add(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, bool a_from_threshold, dap_ledger_datum_iter_data_t *a_datum_index_data);
int dap_ledger_tx_load_hardfork_data(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash, dap_ledger_datum_iter_data_t *a_datum_index_data);
int dap_ledger_tx_load(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_chain_hash_fast_t *a_tx_hash, dap_ledger_datum_iter_data_t *a_datum_index_data);
int dap_ledger_tx_remove(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash);
int dap_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, size_t a_datum_size, dap_hash_fast_t *a_datum_hash);

/**
 * Print list transaction from ledger
 *
 */

json_object * dap_ledger_token_tx_item_list(dap_ledger_t * a_ledger, dap_chain_addr_t *a_addr, const char *a_hash_out_type, bool a_unspent_only);

/**
 * Check token ticker existance
 *
 */

dap_chain_datum_token_t *dap_ledger_token_ticker_check(dap_ledger_t * a_ledger, const char *a_token_ticker);

/**
 * Add new token datum
 *
 */

int dap_ledger_token_add(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size);
int dap_ledger_token_load(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size);
int dap_ledger_token_add_check(dap_ledger_t *a_ledger, byte_t *a_token, size_t a_token_size);
json_object *dap_ledger_token_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset);
json_object *dap_ledger_token_info_by_name(dap_ledger_t *a_ledger, const char *a_token_ticker);

// Get all token-declarations
dap_list_t* dap_ledger_token_decl_all(dap_ledger_t *a_ledger);

json_object *dap_ledger_threshold_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, dap_hash_fast_t *a_threshold_hash, bool a_head);
json_object *dap_ledger_balance_info(dap_ledger_t *a_ledger, size_t a_limit, size_t a_offset, bool a_head);

size_t dap_ledger_token_get_auth_signs_valid(dap_ledger_t *a_ledger, const char *a_token_ticker);
size_t dap_ledger_token_get_auth_signs_total(dap_ledger_t *a_ledger, const char *a_token_ticker);
dap_list_t *dap_ledger_token_get_auth_pkeys_hashes(dap_ledger_t *a_ledger, const char *a_token_ticker);
uint256_t dap_ledger_token_get_emission_rate(dap_ledger_t *a_ledger, const char *a_token_ticker);

/**
 * Add token emission datum
 */
int dap_ledger_token_emission_add(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_hash_fast_t *a_emission_hash);
int dap_ledger_token_emission_load(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_hash_fast_t *a_token_emission_hash);

// Checking a new transaction before adding to the cache
int dap_ledger_token_emission_add_check(dap_ledger_t *a_ledger, byte_t *a_token_emission, size_t a_token_emission_size, dap_chain_hash_fast_t *a_emission_hash);

/* Add stake-lock item */
int dap_ledger_emission_for_stake_lock_item_add(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash);

dap_chain_datum_token_emission_t *dap_ledger_token_emission_find(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_token_emission_hash);

const char* dap_ledger_tx_get_token_ticker_by_hash(dap_ledger_t *a_ledger,dap_chain_hash_fast_t *a_tx_hash);

void dap_ledger_addr_get_token_ticker_all_depricated(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size);

void dap_ledger_addr_get_token_ticker_all(dap_ledger_t *a_ledger, dap_chain_addr_t * a_addr,
        char *** a_tickers, size_t * a_tickers_size);

const char *dap_ledger_get_description_by_ticker(dap_ledger_t *a_ledger, const char *a_token_ticker);

bool dap_ledger_tx_poa_signed(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx);

//TX service-tags
bool dap_ledger_deduct_tx_tag(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, char **a_service_name, dap_chain_srv_uid_t *uid, dap_chain_tx_tag_action_type_t *action);
const char *dap_ledger_tx_action_str(dap_chain_tx_tag_action_type_t a_tag);
dap_chain_tx_tag_action_type_t dap_ledger_tx_action_str_to_action_t(const char *a_str);
const char *dap_ledger_tx_tag_str_by_uid(dap_chain_srv_uid_t a_service_uid);

bool dap_ledger_tx_service_info(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash, 
                                dap_chain_srv_uid_t *a_uid, char **a_service_name,  dap_chain_tx_tag_action_type_t *a_action);


int dap_ledger_service_add(dap_chain_srv_uid_t a_uid, char *tag_str, dap_ledger_tag_check_callback_t a_callback);

dap_chain_token_ticker_str_t dap_ledger_tx_calculate_main_ticker_(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, int *a_ledger_rc);
#define dap_ledger_tx_calculate_main_ticker(l, tx, rc) dap_ledger_tx_calculate_main_ticker_(l, tx, rc).s

/**
 * Delete all transactions from the cache
 */
void dap_ledger_purge(dap_ledger_t *a_ledger, bool a_preserve_db);

/**
 * Return number transactions from the cache
 */
unsigned dap_ledger_count(dap_ledger_t *a_ledger);
uint64_t dap_ledger_count_from_to(dap_ledger_t * a_ledger, dap_nanotime_t a_ts_from, dap_nanotime_t a_ts_to);

/**
 * Check whether used 'out' items
 */
bool dap_ledger_tx_hash_is_used_out_item(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash, int a_idx_out, dap_hash_fast_t *a_out_spender);

/**
 * Retun true if reward was collected before
 */
bool dap_ledger_is_used_reward(dap_ledger_t *a_ledger, dap_hash_fast_t *a_block_hash, dap_hash_fast_t *a_sign_pkey_hash);

/**
 * Calculate balance of addr
 *
 */
uint256_t dap_ledger_calc_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
        const char *a_token_ticker);

uint256_t dap_ledger_calc_balance_full(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr,
            const char *a_token_ticker);
/**
 * Get transaction in the cache by hash
 *
 * return transaction, or NULL if transaction not found in the cache
 */
dap_chain_datum_tx_t *dap_ledger_tx_find_by_hash(dap_ledger_t *a_ledger, const dap_chain_hash_fast_t *a_tx_hash);
dap_chain_datum_tx_t *dap_ledger_tx_unspent_find_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_tx_hash);

dap_hash_fast_t dap_ledger_get_final_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash, bool a_unspent_only);
dap_hash_fast_t dap_ledger_get_first_chain_tx_hash(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_hash_fast_t *a_tx_hash);

 // Get the transaction in the cache by the addr in out item
dap_chain_datum_tx_t* dap_ledger_tx_find_by_addr(dap_ledger_t *a_ledger, const char * a_token,
         const dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_tx_first_hash);

bool dap_ledger_tx_check_recipient(dap_ledger_t* a_ledger, dap_chain_hash_fast_t* a_tx_prev_hash, dap_chain_addr_t *a_addr);

// Get the transaction in the cache by the public key that signed the transaction, starting with a_tx_first_hash
const dap_chain_datum_tx_t* dap_ledger_tx_find_by_pkey(dap_ledger_t *a_ledger,
        char *a_public_key, size_t a_public_key_size, dap_chain_hash_fast_t *a_tx_first_hash);

// Get the transaction in the cache with the out_cond item
dap_chain_datum_tx_t* dap_ledger_tx_cache_find_out_cond(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type,
                                                              dap_chain_hash_fast_t *a_tx_first_hash, dap_chain_tx_out_cond_t **a_out_cond,
                                                              int *a_out_cond_idx, char *a_token_ticker);

// Get all transactions from the cache with the specified out_cond items
dap_list_t* dap_ledger_tx_cache_find_out_cond_all(dap_ledger_t *a_ledger, dap_chain_srv_uid_t a_srv_uid);

// Get the value from all transactions in the cache with out_cond item
uint256_t dap_ledger_tx_cache_get_out_cond_value(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_subtype_t a_cond_type, dap_chain_addr_t *a_addr,
                                                       dap_chain_tx_out_cond_t **tx_out_cond);

dap_list_t *dap_ledger_get_list_tx_outs(dap_ledger_t *a_ledger, const char *a_token_ticker, const dap_chain_addr_t *a_addr_from,
                                        uint256_t *a_value_transfer);
// Get the list of 'out_cond' items with summary value >= than a_value_need
dap_list_t *dap_ledger_get_list_tx_cond_outs_with_val(dap_ledger_t *a_ledger, const char *a_token_ticker,  const dap_chain_addr_t *a_addr_from,
        dap_chain_tx_out_cond_subtype_t a_subtype, uint256_t a_value_need, uint256_t *a_value_transfer);

dap_list_t *dap_ledger_get_list_tx_cond_outs(dap_ledger_t *a_ledger,  const dap_chain_addr_t *a_addr_from);
// Add new verificator callback with associated subtype. Returns 1 if callback replaced, overwise returns 0
int dap_ledger_verificator_add(dap_chain_tx_out_cond_subtype_t a_subtype,
                               dap_ledger_cond_in_verify_callback_t a_callback_in_verify, dap_ledger_cond_out_verify_callback_t a_callback_out_verify,
                               dap_ledger_cond_in_add_callback_t a_callback_in_add, dap_ledger_cond_out_add_callback_t a_callback_out_add,
                               dap_ledger_cond_in_delete_callback_t a_callback_in_delete, dap_ledger_cond_out_delete_callback_t a_callback_out_delete);
// Add new verificator callback for voting. Returns 1 if callback replaced, overwise returns 0
int dap_ledger_voting_verificator_add(dap_ledger_voting_callback_t a_callback, dap_ledger_voting_delete_callback_t a_callback_delete, dap_ledger_voting_expire_callback_t a_callback_expire);
int dap_ledger_tax_callback_set(dap_ledger_tax_callback_t a_callback);
// Getting a list of transactions from the ledger.
dap_list_t * dap_ledger_get_txs(dap_ledger_t *a_ledger, size_t a_count, size_t a_page, bool a_reverse, bool a_unspent_only);

dap_ledger_datum_iter_t *dap_ledger_datum_iter_create(dap_chain_net_t *a_net);
void dap_ledger_datum_iter_delete(dap_ledger_datum_iter_t *a_iter);
dap_chain_datum_tx_t *dap_ledger_datum_iter_get_first(dap_ledger_datum_iter_t *a_iter);
dap_chain_datum_tx_t *dap_ledger_datum_iter_get_next(dap_ledger_datum_iter_t *a_iter);
dap_chain_datum_tx_t *dap_ledger_datum_iter_get_last(dap_ledger_datum_iter_t *a_iter);

void dap_ledger_tx_add_notify(dap_ledger_t *a_ledger, dap_ledger_tx_add_notify_t a_callback, void *a_arg);
void dap_ledger_bridged_tx_notify_add(dap_ledger_t *a_ledger, dap_ledger_bridged_tx_notify_t a_callback, void *a_arg);

bool dap_ledger_datum_is_blacklisted(dap_ledger_t *a_ledger, dap_hash_fast_t a_hash);

bool dap_ledger_cache_enabled(dap_ledger_t *a_ledger);
void dap_ledger_set_cache_tx_check_callback(dap_ledger_t *a_ledger, dap_ledger_cache_tx_check_callback_t a_callback);
dap_chain_tx_out_cond_t* dap_chain_ledger_get_tx_out_cond_linked_to_tx_in_cond(dap_ledger_t *a_ledger, dap_chain_tx_in_cond_t *a_in_cond);
void dap_ledger_load_end(dap_ledger_t *a_ledger);

int dap_ledger_decree_create(dap_ledger_t *a_ledger);
void dap_ledger_decree_purge(dap_ledger_t *a_ledger);

uint16_t dap_ledger_decree_get_min_num_of_signers(dap_ledger_t *a_ledger);
uint16_t dap_ledger_decree_get_num_of_owners(dap_ledger_t *a_ledger);
const dap_list_t *dap_ledger_decree_get_owners_pkeys(dap_ledger_t *a_ledger);

int dap_ledger_decree_apply(dap_hash_fast_t *a_decree_hash, dap_chain_datum_decree_t *a_decree, dap_chain_t *a_chain, dap_hash_fast_t *a_anchor_hash);
int dap_ledger_decree_verify(dap_chain_net_t *a_net, dap_chain_datum_decree_t *a_decree, size_t a_data_size, dap_chain_hash_fast_t *a_decree_hash);
int dap_ledger_decree_load(dap_chain_datum_decree_t * a_decree, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_decree_hash);
dap_chain_datum_decree_t *dap_ledger_decree_get_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_hash, bool *is_applied);
int dap_ledger_decree_reset_applied(dap_chain_net_t *a_net, dap_chain_hash_fast_t *a_decree_hash);

int dap_ledger_anchor_verify(dap_chain_net_t *a_net, dap_chain_datum_anchor_t * a_anchor, size_t a_data_size);
int dap_ledger_anchor_load(dap_chain_datum_anchor_t * a_anchor, dap_chain_t *a_chain, dap_hash_fast_t *a_anchor_hash);
int dap_ledger_anchor_unload(dap_chain_datum_anchor_t * a_anchor, dap_chain_t *a_chain, dap_hash_fast_t *a_anchor_hash);
dap_chain_datum_anchor_t *dap_ledger_anchor_find(dap_ledger_t *a_ledger, dap_hash_fast_t *a_anchor_hash);

dap_ledger_hardfork_balances_t *dap_ledger_states_aggregate(dap_ledger_t *a_ledger, dap_time_t a_hardfork_decree_creation_time, dap_ledger_hardfork_condouts_t **l_cond_outs_list);
dap_ledger_hardfork_anchors_t *dap_ledger_anchors_aggregate(dap_ledger_t *a_ledger);

uint256_t dap_ledger_coin_get_uncoloured_value(dap_ledger_t *a_ledger, dap_hash_fast_t *a_voting_hash, dap_hash_fast_t *a_tx_prev_hash, int a_out_idx);
void dap_ledger_tx_clear_colour(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash);
dap_pkey_t *dap_ledger_find_pkey_by_hash(dap_ledger_t *a_ledger, dap_chain_hash_fast_t *a_pkey_hash);
