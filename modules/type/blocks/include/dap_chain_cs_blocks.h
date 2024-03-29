/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP (Demlabs Application Protocol) the open source project

    DAP (Demlabs Application Protocol) is free software: you can redistribute it and/or modify
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

#ifdef DAP_TPS_TEST
#define DAP_CHAIN_CS_BLOCKS_MAX_BLOCK_SIZE (100 * 1024 * 1024)
#else
#define DAP_CHAIN_CS_BLOCKS_MAX_BLOCK_SIZE (256 * 1024) // 256 KB
#endif

#define DAP_REWARD_INIT_TIMESTAMP 1700870400UL // 25 Nov 00:00:00 GMT

typedef struct dap_chain_cs_blocks dap_chain_cs_blocks_t;

typedef void (*dap_chain_cs_blocks_callback_t)(dap_chain_cs_blocks_t *);
typedef void (*dap_chain_cs_blocks_callback_op_results_t)(dap_chain_cs_blocks_t * a_cs_blocks, int a_rc, void * a_arg);
typedef int (*dap_chain_cs_blocks_callback_block_t)(dap_chain_cs_blocks_t *, dap_chain_block_t *, size_t);
typedef size_t (*dap_chain_cs_blocks_callback_block_sign_t)(dap_chain_cs_blocks_t *, dap_chain_block_t **, size_t);
typedef dap_chain_block_t *(*dap_chain_cs_block_move_t)(dap_chain_cs_blocks_t *, size_t *);
typedef dap_chain_block_t * (*dap_chain_cs_blocks_callback_block_create_t)(dap_chain_cs_blocks_t *,
                                                                               dap_chain_datum_t *,
                                                                               dap_chain_hash_fast_t *,
                                                                               size_t, size_t*);
typedef struct dap_chain_cs_blocks
{
   dap_chain_t * chain;
   // For new block creating
   dap_chain_block_t * block_new;
   size_t block_new_size;

   dap_chain_cs_blocks_callback_t callback_delete;
   dap_chain_cs_blocks_callback_block_create_t callback_block_create;
   dap_chain_cs_blocks_callback_block_t callback_block_verify;
   dap_chain_cs_blocks_callback_block_sign_t callback_block_sign;
   dap_chain_cs_block_move_t callback_new_block_move;

   void * _pvt;
   void * _inheritor;
} dap_chain_cs_blocks_t;

#define DAP_CHAIN_CS_BLOCKS(a) ((dap_chain_cs_blocks_t *)(a)->_inheritor)
typedef int (*dap_chain_blocks_block_callback_ptr_t)(dap_chain_cs_blocks_t *, dap_chain_block_t *);

int dap_chain_cs_blocks_init();
void dap_chain_cs_blocks_deinit();

int dap_chain_cs_blocks_new(dap_chain_t * a_chain, dap_config_t * a_chain_config);
void dap_chain_cs_blocks_delete(dap_chain_t * a_chain);
dap_chain_block_cache_t *dap_chain_block_cache_get_by_hash(dap_chain_cs_blocks_t *a_blocks, dap_chain_hash_fast_t *a_block_hash);

DAP_STATIC_INLINE char *dap_chain_cs_blocks_get_fee_group(const char *a_net_name)
{
    return dap_strdup_printf("local.%s.fees", a_net_name);
}

DAP_STATIC_INLINE char *dap_chain_cs_blocks_get_reward_group(const char *a_net_name)
{
    return dap_strdup_printf("local.%s.rewards", a_net_name);
}
