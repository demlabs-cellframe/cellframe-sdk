/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2020
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

#include "dap_chain.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"

#define DAP_REWARD_INIT_TIMESTAMP 1700870400UL // 25 Nov 2023 00:00:00 GMT

typedef struct dap_chain_cs_blocks dap_chain_cs_blocks_t;

typedef void (*dap_chain_cs_blocks_callback_t)(dap_chain_cs_blocks_t *);
typedef void (*dap_chain_cs_blocks_callback_op_results_t)(dap_chain_cs_blocks_t * a_cs_blocks, int a_rc, void * a_arg);
typedef int (*dap_chain_cs_blocks_callback_block_verify_t)(dap_chain_cs_blocks_t *a_cs_blocks, dap_chain_block_t *a_block, dap_hash_fast_t *a_block_hash, size_t a_block_size);
typedef size_t (*dap_chain_cs_blocks_callback_block_sign_t)(dap_chain_cs_blocks_t *, dap_chain_block_t **, size_t);
typedef dap_chain_block_t *(*dap_chain_cs_block_move_t)(dap_chain_cs_blocks_t *, size_t *);
typedef void (*dap_chain_cs_blocks_callback_fork_resolved_t)(dap_chain_t *a_chain, dap_hash_fast_t a_block_before_fork_hash, dap_list_t *a_reverted_blocks, 
                                                                uint64_t a_reverted_blocks_cnt, uint64_t a_main_blocks_cnt, void * a_arg);
typedef struct dap_chain_cs_blocks
{
   dap_chain_t * chain;
   // For new block creating
   dap_chain_block_t * block_new;
   size_t block_new_size;

   dap_chain_cs_blocks_callback_t callback_delete;
   dap_chain_cs_block_move_t callback_block_create;
   dap_chain_cs_blocks_callback_block_verify_t callback_block_verify;
   dap_chain_cs_blocks_callback_block_sign_t callback_block_sign;
   dap_chain_cs_block_move_t callback_new_block_move;

   void * _pvt;
   void * _inheritor;
} dap_chain_cs_blocks_t;

typedef enum s_com_blocks_err{
    DAP_CHAIN_NODE_CLI_COM_BLOCK_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_CHAIN_TYPE_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_DATUM_DEL_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_MEMORY_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_VERIF_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_FIND_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_DATUM_SIZE_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_PUB_KEY_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_PVT_KEY_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_SIGN_ERR,
    DAP_CHAIN_NODE_CLI_COM_BLOCK_NET_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_BLOCK_UNKNOWN /* MAX */
} s_com_blocks_err_t;

typedef struct dap_chain_cs_blocks_reward
{
    dap_hash_fast_t pkey_hash;
    uint256_t reward;
} dap_chain_cs_block_rewards_t;


#define DAP_CHAIN_CS_BLOCKS(a) ((dap_chain_cs_blocks_t *)(a)->_inheritor)
typedef int (*dap_chain_blocks_block_callback_ptr_t)(dap_chain_cs_blocks_t *, dap_chain_block_t *);

int dap_chain_cs_blocks_init();
void dap_chain_cs_blocks_deinit();
dap_chain_block_cache_t *dap_chain_block_cache_get_by_hash(dap_chain_cs_blocks_t *a_blocks, dap_chain_hash_fast_t *a_block_hash);

int dap_chain_block_add_fork_notificator(dap_chain_cs_blocks_callback_fork_resolved_t a_callback, void *a_arg);

DAP_STATIC_INLINE char *dap_chain_cs_blocks_get_fee_group(const char *a_net_name)
{
    return dap_strdup_printf("local.%s.fees", a_net_name);
}

DAP_STATIC_INLINE char *dap_chain_cs_blocks_get_reward_group(const char *a_net_name)
{
    return dap_strdup_printf("local.%s.rewards", a_net_name);
}

dap_pkey_t *dap_chain_cs_blocks_get_pkey_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_pkey_hash);

dap_list_t *dap_chain_cs_blocks_get_block_signers_rewards(dap_chain_t *a_chain, dap_hash_fast_t *a_block_hash);

/**
 * @brief dap_chain_cs_blocks_get_tip
 *        Current tip of the block chain: number and hash of the last loaded
 *        block. Used by the ledger snapshot cache to anchor its position.
 * @return false if the chain carries no loaded blocks.
 */
bool dap_chain_cs_blocks_get_tip(dap_chain_t *a_chain, uint64_t *a_block_num, dap_chain_hash_fast_t *a_block_hash);

// Chain cache management (the 'chain cache' CLI command). All of them answer
// with a human-readable report and return 0 on success.
int dap_chain_cs_blocks_state_info(dap_chain_t *a_chain, char *a_buf, size_t a_buf_size);
// Datum location from the chain-state index (no block read): the block hash the
// datum belongs to and its ordinal inside the block. Used by the ledger snapshot
// to store atom links and to attach restored datums lazily.
int dap_chain_cs_blocks_datum_location(dap_chain_t *a_chain, const dap_hash_fast_t *a_hash,
                                       dap_chain_hash_fast_t *a_atom_hash, uint32_t *a_datum_idx);
// Datum bytes by location (block hash + ordinal), without a chain scan. Returns
// 0 and a pointer valid for the block cache lifetime; -2 when the block is not
// in the cache/index (the caller may fall back to reading the cell file).
int dap_chain_cs_blocks_datum_at(dap_chain_t *a_chain, const dap_chain_hash_fast_t *a_atom_hash,
                                 uint32_t a_datum_idx, dap_chain_datum_t **a_datum, size_t *a_size);
// Builds the block cache from the chain-state index (no cell-body reads). Blocks
// are thin until dap_chain_block_cache_ensure() parses them. Returns the number
// of restored blocks or <0.
int64_t dap_chain_cs_blocks_restore_index(dap_chain_t *a_chain);
// Datum-index entries for the no-scan start: the ledger snapshot carries the
// atom links, the block cache provides block_ref (thin entry is enough).
int dap_chain_cs_blocks_index_restored_datum(dap_chain_t *a_chain, const dap_hash_fast_t *a_datum_hash,
                                             const dap_hash_fast_t *a_atom_hash, uint32_t a_datum_idx);
size_t dap_chain_cs_blocks_datum_index_count(dap_chain_t *a_chain);
int dap_chain_cs_blocks_state_verify(dap_chain_t *a_chain, char *a_buf, size_t a_buf_size);
int dap_chain_cs_blocks_state_flush(dap_chain_t *a_chain);
int dap_chain_cs_blocks_state_drop(dap_chain_t *a_chain);
// Clears the datum hash -> block index; 'rebuild' repopulates it (and the tx
// counter) from the in-memory block cache, re-applying each datum to the ledger
// (already-cached transactions are cheap no-ops). Both are management actions.
int dap_chain_cs_blocks_state_drop_datums(dap_chain_t *a_chain);
int dap_chain_cs_blocks_state_rebuild(dap_chain_t *a_chain);