/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * Alexander Lysikov <alexander.lysikov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2019
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

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_tx.h"
#include "dap_chain_common.h"
#include "dap_tsd.h"
#include "uthash.h"

// Forward declarations
struct dap_ledger;
typedef struct dap_ledger dap_ledger_t;
struct dap_chain_tx_event;
typedef struct dap_chain_tx_event dap_chain_tx_event_t;

/**
 * @brief Ledger notification opcodes
 */
typedef enum dap_chan_ledger_notify_opcodes{
    DAP_LEDGER_NOTIFY_OPCODE_ADDED = 'a', // 0x61
    DAP_LEDGER_NOTIFY_OPCODE_DELETED = 'd', // 0x64 
} dap_chan_ledger_notify_opcodes_t;

/**
 * @brief Transaction tag action types
 */
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

    DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_HOLD =    1 << 13,
    DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_TAKE =    1 << 14,
    DAP_CHAIN_TX_TAG_ACTION_EMIT_DELEGATE_REFILL =  1 << 15,
    DAP_CHAIN_TX_TAG_ACTION_EVENT =                 1 << 16,
   
    DAP_CHAIN_TX_TAG_ACTION_ALL =                          ~0,
} dap_chain_tx_tag_action_type_t;

// ============================================================================
// Ledger transaction cache item (moved from dap_chain_ledger.h in master)
// ============================================================================

/**
 * @brief Ledger cache item - one of unspent outputs
 */
typedef struct dap_ledger_tx_item {
    dap_chain_hash_fast_t tx_hash_fast;
    dap_chain_datum_tx_t *tx;
    dap_nanotime_t ts_added;
    UT_hash_handle hh;
    struct {
        dap_time_t ts_created;      // Transaction datum timestamp mirrored & cached
        uint32_t n_outs;
        uint32_t n_outs_used;
        char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        byte_t padding[6];
        byte_t multichannel;
        dap_time_t ts_spent;
        byte_t pad[7];
        dap_chain_net_srv_uid_t tag; //tag (or service this tx is belong to)
        dap_chain_tx_tag_action_type_t action;
        dap_chain_hash_fast_t tx_hash_spent_fast[]; // spent outs list
    } DAP_ALIGN_PACKED cache_data;
} dap_ledger_tx_item_t;

// ============================================================================
// Callback types
// ============================================================================

/**
 * @brief Callback type for transaction add notifications
 */
typedef void (*dap_ledger_tx_add_notify_t)(void *a_arg, dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode);

/**
 * @brief Callback type for bridged transaction notifications
 */
typedef void (*dap_ledger_bridged_tx_notify_t)(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx, dap_hash_fast_t *a_tx_hash, void *a_arg, dap_chan_ledger_notify_opcodes_t a_opcode);

/**
 * @brief Callback type for event notifications (added in master)
 */
typedef void (*dap_ledger_event_notify_t)(void *a_arg, dap_ledger_t *a_ledger, dap_chain_tx_event_t *a_event, dap_hash_fast_t *a_tx_hash, dap_chan_ledger_notify_opcodes_t a_opcode);

/**
 * @brief Callback type for cache transaction check
 * @note TODO remove this callback
 */
typedef bool (*dap_ledger_cache_tx_check_callback_t)(dap_ledger_t *a_ledger, dap_hash_fast_t *a_tx_hash);

/**
 * @brief Callback type for service decree processing (added in master)
 */
typedef int (*dap_ledger_srv_callback_decree_t)(dap_ledger_t *a_ledger, bool a_apply, dap_tsd_t *a_params, size_t a_params_size);

/**
 * @brief Callback type for event verification (added in master)
 */
typedef int (*dap_ledger_srv_callback_event_verify_t)(dap_ledger_t *a_ledger, const char *a_event_group_name, int a_event_type,
                                                      void *a_event_data, size_t a_event_data_size, dap_hash_fast_t *a_event_tx_hash);

