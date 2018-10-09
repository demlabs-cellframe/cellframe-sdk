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



#include "dap_chain_internal.h"
#include "dap_chain.h"

#define LOG_TAG "chain"


FILE* my_file_to_wite_gold;
void* gold_mem;
FILE* my_file_to_wite_silver;
void* silver_mem;
FILE* my_file_to_wite_copper;
void* copper_mem;

int blocks_mined;
int blocks_mined_gold;
int blocks_mined_silver;
int blocks_mined_copper;

double total_mining_time;
double total_mining_hashes; //хз че делать пока
double total_hashes_in_minute;

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init()
{

}

/**
 * @brief dap_chain_deinit
 */
void dap_chain_deinit()
{

}


void dap_chain_mine_stop(){
    log_it(L_INFO, "Total hashes for gold coins %s B", ftell(my_file_to_wite_gold) );
    fclose(my_file_to_wite_gold);
    log_it(L_INFO, "Total hashes for silver coins %s B", ftell(my_file_to_wite_silver));
    fclose(my_file_to_wite_silver);
    log_it(L_INFO, "Total hashes for copper coins %s B", ftell(my_file_to_wite_copper));
    fclose(my_file_to_wite_copper);
    log_it(L_INFO, "Total blocks mined %s ", blocks_mined);
    log_it(L_INFO, "Gold blocks mined %s ", blocks_mined_gold);
    log_it(L_INFO, "Silver blocks mined %s ", blocks_mined_silver);
    log_it(L_INFO, "Copper blocks mined %s ", blocks_mined_copper);
    log_it(L_INFO, "Totla mining speed %s ", total_hashes_in_minute/blocks_mined);
}

void dap_chain_settot(){
    blocks_mined = 0;
    blocks_mined_copper = 0;
    blocks_mined_silver = 0;
    blocks_mined_gold = 0;
    total_hashes_in_minute = 0;
}

void dap_chain_count_new_block(dap_chain_block_cache_t *l_block_cache)
{
    blocks_mined+=1;
    total_hashes_in_minute = total_hashes_in_minute + sizeof(l_block_cache->block_hash)/l_block_cache->block_mine_time;
}


/**
 * @brief dap_chain_open
 * @param a_file_storage
 * @param a_file_cache
 * @return
 */
dap_chain_t * dap_chain_open(const char * a_file_storage,const char * a_file_cache)
{
    dap_chain_t * l_chain = DAP_NEW_Z(dap_chain_t);

    l_chain->difficulty = 2;

    DAP_CHAIN_INTERNAL_LOCAL_NEW(l_chain);

    l_chain_internal->file_storage_type = 0x0000; // TODO compressed format
    l_chain_internal->file_storage = fopen(a_file_storage,"a+");

    return l_chain;
}

/**
 * @brief dap_chain_remap
 * @param a_chain
 * @param a_offset
 */
void dap_chain_remap(dap_chain_t * a_chain, size_t a_offset)
{

}

/**
 * @brief dap_chain_save
 * @param a_chain
 */
void dap_chain_save(dap_chain_t * a_chain)
{

}

/**
 * @brief dap_chain_file_write
 * @param l_block_cache
 */

void dap_chain_file_write(dap_chain_block_cache_t *l_block_cache){
    if (dap_chain_hash_kind_check(&l_block_cache->block_hash, l_block_cache->block->header.difficulty)==HASH_GOLD){
                                               fwrite(l_block_cache->block, l_block_cache->block->header.size+sizeof(l_block_cache->block->header), 1, my_file_to_wite_gold);
                                               blocks_mined_gold += 1;
                                               /*gold_mem=mmap(0, l_block_cache->block->header.size, PROT_WRITE, MAP_SHARED, my_file_to_wite_gold, 0);
                                               memcpy(gold_mem, l_block_cache, l_block_cache->block->header.size);
                                               munmap(gold_mem, l_block_cache->block->header.size);*/
                                           }
                                           else if (dap_chain_hash_kind_check(&l_block_cache->block_hash, l_block_cache->block->header.difficulty)==HASH_SILVER){
                                               fwrite(l_block_cache->block, l_block_cache->block->header.size+sizeof(l_block_cache->block->header), 1, my_file_to_wite_silver);
                                               blocks_mined_silver += 1;
                                               /*silver_mem=mmap(0, l_block_cache->block->header.size, PROT_WRITE, MAP_SHARED, my_file_to_wite_silver, 0);
                                               memcpy(silver_mem, l_block_cache, l_block_cache->block->header.size);
                                               munmap(silver_mem, l_block_cache->block->header.size);*/
                                           }
                                           else {
                                               fwrite(l_block_cache->block, l_block_cache->block->header.size+sizeof(l_block_cache->block->header), 1, my_file_to_wite_copper);
                                               blocks_mined_copper += 1;
                                               /*copper_mem=mmap(0, l_block_cache->block->header.size, PROT_WRITE, MAP_SHARED, my_file_to_wite_copper, 0);
                                               memcpy(copper_mem, l_block_cache, l_block_cache->block->header.size);
                                               munmap(copper_mem, l_block_cache->block->header.size);*/
                                           }
}

/**
 * @brief dap_chain_file_open
 * @param last_g
 * @param last_s
 * @param last_c
 */

void dap_chain_file_open(dap_chain_block_cache_t* last_g, dap_chain_block_cache_t* last_s, dap_chain_block_cache_t* last_c)
{
                   dap_chain_block_cache_t * l_block_gold;
                   dap_chain_block_cache_t *l_block_silver;
                   dap_chain_block_cache_t *l_block_copper;
                   uint32_t size_of_gold, size_of_silver, size_of_copper;
                   size_t result;

}


/**
 * @brief dap_chain_close
 * @param a_chain
 */
void dap_chain_close(dap_chain_t * a_chain)
{
    if(a_chain){
        if(a_chain->callback_delete)
            a_chain->callback_delete(a_chain);
    }else
        log_it(L_WARNING,"Tried to close null pointer");
}

/**
 * @brief dap_chain_update
 * @param l_block_cache
 */
void dap_chain_update(dap_chain_block_cache_t *l_block_cache){
    dap_chain_file_write(l_block_cache);

}

/**
 * @brief dap_chain_info_dump_log
 * @param a_chain
 */
void dap_chain_info_dump_log(dap_chain_t * a_chain)
{

}

dap_chain_block_cache_t* dap_chain_allocate_next_block(dap_chain_t * a_chain)
{
    dap_chain_block_t* l_block = NULL;
    dap_chain_block_cache_t* l_block_cache = NULL;
    if ( a_chain->block_last )
        l_block = dap_chain_block_new( &a_chain->block_last->block_hash );
    else
        l_block = dap_chain_block_new( NULL );

    if( l_block ){
        l_block->header.difficulty = a_chain->difficulty;
        l_block_cache = dap_chain_block_cache_new(l_block);
        return l_block_cache;
    }else{
        log_it(L_ERROR, "Can't allocate next block!");
        return NULL;
    }
}
