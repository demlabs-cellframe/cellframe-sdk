/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
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


#pragma once
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"

struct dap_chain;

typedef void (*dap_chain_callback_t)(struct dap_chain *);
typedef void (*dap_chain_callback_ptr_t)(struct dap_chain *, void * );
typedef size_t (*dap_chain_callback_dataop_t)(struct dap_chain *, const void * , const size_t ,void *);

typedef struct dap_chain{
    dap_chain_id_t id;
    dap_chain_block_cache_t * block_first; // Mapped area start
    dap_chain_block_cache_t * block_last; // Last block in mapped area
    uint64_t blocks_count;
    uint64_t difficulty;

    dap_chain_callback_t callback_delete;
    void * _internal;
    void * _inhertor;
} dap_chain_t;

#define DAP_CHAIN(a) ( (dap_chain_t *) (a)->_inheritor)

int dap_chain_init();
void dap_chain_deinit();

dap_chain_t * dap_chain_open(const char * a_file_storage,const char * a_file_cache);
void dap_chain_remap(dap_chain_t * a_chain, size_t a_offset);
void dap_chain_save(dap_chain_t * a_chain);
void dap_chain_info_dump_log(dap_chain_t * a_chain);



//работа с файлом
void dap_chain_file_open(dap_chain_block_cache_t* last_g, dap_chain_block_cache_t* last_s, dap_chain_block_cache_t* last_c);
void dap_chain_file_write(dap_chain_block_cache_t *l_block_cache);
void dap_chain_update(dap_chain_block_cache_t *l_block_cache);
void dap_chain_mine_stop();
void dap_chain_settot();
void dap_chain_count_new_block(dap_chain_block_cache_t *l_block_cache);
//работа с файлом

dap_chain_block_cache_t* dap_chain_allocate_next_block(dap_chain_t * a_chain);


void dap_chain_close(dap_chain_t * a_chain);
