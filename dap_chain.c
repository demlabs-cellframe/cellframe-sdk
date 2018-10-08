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

#include <unistd.h>

#include "dap_chain_internal.h"
#include "dap_chain.h"
#include <pthread.h>

#define LOG_TAG "dap_chain"


FILE* g_gold_hash_blocks_file;
FILE* g_silver_hash_blocks_file;

double total_mining_time;
double total_mining_hashes;
double total_hashes_in_minute;

dap_chain_t g_gold_chain;
dap_chain_t g_silver_chain;

dap_chain_file_header_t g_gold_header;
dap_chain_file_header_t g_silver_header;

#define GOLD_HASH_FILE_NAME "/opt/"NODE_NETNAME"-node/data/goldhash.bin"
#define SILVER_HASH_FILE_NAME "/opt/"NODE_NETNAME"-node/data/silverhash.bin"

static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;

/**
 * @brief dap_chain_init
 * @return
 */
int dap_chain_init()
{
    int ret = dap_chain_prepare_env();

    //dap_chain_show_hash_blocks_file(g_gold_hash_blocks_file);
    //dap_chain_show_hash_blocks_file(g_silver_hash_blocks_file);
    return 0;
}

/**
 * @brief dap_chain_deinit
 */
void dap_chain_deinit()
{

}


void dap_chain_mine_stop(){
    //log_it(L_INFO, "Total hashes for gold coins %s B", ftell(g_gold_hash_blocks_file) );
    //fclose(g_gold_hash_blocks_file);
    //log_it(L_INFO, "Total hashes for silver coins %s B", ftell(g_silver_hash_blocks_file));
    //fclose(g_silver_hash_blocks_file);
    //log_it(L_INFO, "Total blocks mined %s ", blocks_mined);
    //log_it(L_INFO, "Gold blocks mined %s ", blocks_mined_gold);
    //log_it(L_INFO, "Silver blocks mined %s ", blocks_mined_silver);
    //log_it(L_INFO, "Totla mining speed %s ", total_hashes_in_minute/blocks_mined);
}

void dap_chain_set_default(bool a_is_gold){

    if (true == a_is_gold){
        g_gold_chain.difficulty = 1;
        g_gold_chain.blocks_count = 0;

        g_gold_header.chain_id = DAP_CHAIN_CHAIN_ID;
        g_gold_header.signature = DAP_CHAIN_FILE_SIGNATURE;
        g_gold_header.type = DAP_CHAIN_FILE_TYPE_RAW;
        g_gold_header.version = 1;

        fwrite(&g_gold_chain.blocks_count, sizeof(g_gold_chain.blocks_count), 1, g_gold_hash_blocks_file);
        fwrite(&g_gold_chain.difficulty, sizeof(g_gold_chain.difficulty), 1, g_gold_hash_blocks_file);
        fwrite(&g_gold_header, sizeof(g_gold_header), 1, g_gold_hash_blocks_file);
    } else {
        g_silver_chain.difficulty = 1;
        g_silver_chain.blocks_count = 0;

        g_silver_header.chain_id = DAP_CHAIN_CHAIN_ID;
        g_silver_header.signature = DAP_CHAIN_FILE_SIGNATURE;
        g_silver_header.type = DAP_CHAIN_FILE_TYPE_RAW;
        g_silver_header.version = 1;

        fwrite(&g_silver_chain.blocks_count, sizeof(g_silver_chain.blocks_count), 1, g_silver_hash_blocks_file);
        fwrite(&g_silver_chain.difficulty, sizeof(g_silver_chain.difficulty), 1, g_silver_hash_blocks_file);
        fwrite(&g_silver_header, sizeof(g_silver_header), 1, g_silver_hash_blocks_file);
    }

}

void dap_chain_count_new_block(dap_chain_block_cache_t *l_block_cache)
{
    //blocks_mined+=1;
    total_hashes_in_minute = total_hashes_in_minute + sizeof(l_block_cache->block_hash)/l_block_cache->block_mine_time;
}


/**
 * @brief dap_chain_open
 * @param a_file_storage
 * @param a_file_cache
 * @return
 */
int dap_chain_prepare_env()
{
    dap_chain_block_t *l_new_block = dap_chain_block_new(NULL);
    dap_chain_block_cache_t *l_new_block_cache = dap_chain_block_cache_new(l_new_block);
    g_gold_chain.block_cache_first = l_new_block_cache;

    l_new_block = dap_chain_block_new(NULL);
    l_new_block_cache = dap_chain_block_cache_new(l_new_block);
    g_gold_chain.block_cache_last = l_new_block_cache;

    g_gold_chain.difficulty = 1;
    //DAP_CHAIN_INTERNAL_LOCAL_NEW(g_gold_chain);


    l_new_block = dap_chain_block_new(NULL);
    l_new_block_cache = dap_chain_block_cache_new(l_new_block);
    g_silver_chain.block_cache_first = l_new_block_cache;

    l_new_block = dap_chain_block_new(NULL);
    l_new_block_cache = dap_chain_block_cache_new(l_new_block);
    g_silver_chain.block_cache_last = l_new_block_cache;

    g_silver_chain.difficulty = 1;
    //DAP_CHAIN_INTERNAL_LOCAL_NEW(g_silver_chain);


    //l_chain_internal->file_storage_type = 0x0000; // TODO compressed format
    //l_chain_internal->file_storage = fopen(a_file_storage,"a+");

    int ret = dap_chain_files_open();
    return ret;
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

void dap_chain_block_write(dap_chain_block_cache_t *l_block_cache){
    FILE * l_hash_type_file;
    dap_chain_t * l_hash_type_chain;
    if (dap_chain_hash_kind_check(&l_block_cache->block_hash, l_block_cache->block->header.difficulty)==HASH_GOLD){
        l_hash_type_file = g_gold_hash_blocks_file;
        l_hash_type_chain = &g_gold_chain;
    } else if (dap_chain_hash_kind_check(&l_block_cache->block_hash, l_block_cache->block->header.difficulty)==HASH_SILVER){
        l_hash_type_file = g_silver_hash_blocks_file;
        l_hash_type_chain = &g_silver_chain;
    } else
        return;

    pthread_mutex_lock(&s_mutex);

    fseek(l_hash_type_file, 0, SEEK_SET);
    l_hash_type_chain->blocks_count++;
    fwrite(&l_hash_type_chain->blocks_count, sizeof(l_hash_type_chain->blocks_count), 1, l_hash_type_file);

    fseek(l_hash_type_file, 0, SEEK_END);
    int ret = fwrite(&(l_block_cache->block->header), sizeof(l_block_cache->block->header), 1, l_hash_type_file);
    //log_it(L_ERROR, "Dap_chain_write_block - %d blocks written", ret);

    memcpy(l_hash_type_chain->block_cache_last->block, l_block_cache->block, sizeof (dap_chain_block_t));

    l_hash_type_chain->block_cache_last->block_hash = l_block_cache->block_hash;
    l_hash_type_chain->block_cache_last->block_mine_time = l_block_cache->block_mine_time;
    l_hash_type_chain->block_cache_last->sections_size = l_block_cache->sections_size;

    pthread_mutex_unlock(&s_mutex);
}

/**
 * @brief dap_chain_file_open
 * @param last_g
 * @param last_s
 * @param last_c
 */
int dap_chain_files_open()
{
    //bool l_is_need_set_gold = false, l_is_need_set_silver = false;
    size_t l_file_header_size = sizeof(g_gold_chain.blocks_count) + sizeof(g_gold_chain.difficulty)
                 + sizeof(dap_chain_file_header_t);
    //log_it(L_ERROR, "Dap_chain_size of header - %u Bytes", l_file_header_size);

    //--------------------------------------------------------------------
    //Init/load gold_hash_file
    if( access( GOLD_HASH_FILE_NAME, F_OK ) == -1 )
        g_gold_hash_blocks_file = fopen(GOLD_HASH_FILE_NAME, "w+b");
    else
        g_gold_hash_blocks_file = fopen(GOLD_HASH_FILE_NAME, "r+b");
    if (g_gold_hash_blocks_file == NULL){
        log_it(L_ERROR, "Can't open goldhash block file!");
        return -1;
    }

    fseek(g_gold_hash_blocks_file, 0, SEEK_END);
    if (ftell(g_gold_hash_blocks_file) < l_file_header_size){
        fseek(g_gold_hash_blocks_file, 0, SEEK_SET);
        dap_chain_set_default(true);
    }else{
        fseek(g_gold_hash_blocks_file, 0, SEEK_SET);
        fread(&g_gold_chain.blocks_count, sizeof(g_gold_chain.blocks_count), 1, g_gold_hash_blocks_file);
        fread(&g_gold_chain.difficulty, sizeof(g_gold_chain.difficulty), 1, g_gold_hash_blocks_file);
        fread(&g_gold_header, sizeof(g_gold_header), 1, g_gold_hash_blocks_file);
    }

    fseek(g_gold_hash_blocks_file, 0, SEEK_END);
    long int l_file_blocks_sz = ftell(g_gold_hash_blocks_file) - (long int)l_file_header_size;
    long int l_block_header_size = sizeof (g_gold_chain.block_cache_first->block->header);
    if (0 != l_file_blocks_sz % l_block_header_size){
        log_it(L_ERROR, "Gold hash file is corrupted!");

        // to get rid of extra trash bytes at the end of the file
        ftruncate( fileno(g_gold_hash_blocks_file), (l_file_blocks_sz - l_file_blocks_sz % l_block_header_size ) + l_file_header_size);

        // or just return an error
        //return -2;
    }
    if (l_file_blocks_sz > 0) {
        fseek(g_gold_hash_blocks_file, l_file_header_size, SEEK_SET);
        fread(&g_gold_chain.block_cache_first->block->header, l_block_header_size, 1, g_gold_hash_blocks_file);
        dap_chain_block_cache_dump(g_gold_chain.block_cache_first);

        fseek(g_gold_hash_blocks_file, -l_block_header_size, SEEK_END);
        fread(&g_gold_chain.block_cache_last->block->header, l_block_header_size, 1, g_gold_hash_blocks_file);
        dap_chain_block_cache_dump(g_gold_chain.block_cache_last);
    }
    //log_it(L_INFO, "Header size - %d. Header and hash size - %d. Total file size - %d.",
    //       l_header_size, l_header_and_hash_size, ftell(file_gold_hash_blocks));

    //End of init/load gold_hash_file
    //-------------------------------------------------------------


    //--------------------------------------------------------------------
    //Init/load silver_hash_file
    if( access( SILVER_HASH_FILE_NAME, F_OK ) == -1 )
        g_silver_hash_blocks_file = fopen(SILVER_HASH_FILE_NAME, "w+b");
    else
        g_silver_hash_blocks_file = fopen(SILVER_HASH_FILE_NAME, "r+b");
    if (g_silver_hash_blocks_file == NULL){
        log_it(L_ERROR, "Can't open silverhash file block!");
        return -3;
    }

    fseek(g_silver_hash_blocks_file, 0, SEEK_END);
    if (ftell(g_silver_hash_blocks_file) < l_file_header_size){
        fseek(g_silver_hash_blocks_file, 0, SEEK_SET);
        dap_chain_set_default(false);
    }else{
        fseek(g_silver_hash_blocks_file, 0, SEEK_SET);
        fread(&g_silver_chain.blocks_count, sizeof(g_silver_chain.blocks_count), 1, g_silver_hash_blocks_file);
        fread(&g_silver_chain.difficulty, sizeof(g_silver_chain.difficulty), 1, g_silver_hash_blocks_file);
        fread(&g_silver_header, sizeof(g_silver_header), 1, g_silver_hash_blocks_file);
    }

    fseek(g_silver_hash_blocks_file, 0, SEEK_END);
    l_file_blocks_sz = ftell(g_silver_hash_blocks_file) - (long int)l_file_header_size;
    if (0 != l_file_blocks_sz % l_block_header_size){
        log_it(L_ERROR, "Silver hash file is corrupted!");

        // to get rid of extra trash bytes at the end of the file
        ftruncate( fileno(g_silver_hash_blocks_file), (l_file_blocks_sz - l_file_blocks_sz % l_block_header_size ) + l_file_header_size);

        // or just return an error
        //return -4;
    }
    if (l_file_blocks_sz > 0) {
        fseek(g_silver_hash_blocks_file, l_file_header_size, SEEK_SET);
        fread(g_silver_chain.block_cache_first->block, sizeof(dap_chain_block_t), 1, g_silver_hash_blocks_file);
        dap_chain_block_cache_dump(g_silver_chain.block_cache_first);

        fseek(g_silver_hash_blocks_file, -(int)sizeof(dap_chain_block_t), SEEK_END);
        fread(g_silver_chain.block_cache_last->block, sizeof(dap_chain_block_t), 1, g_silver_hash_blocks_file);
        dap_chain_block_cache_dump(g_silver_chain.block_cache_last);
    }
    //log_it(L_INFO, "Header size - %d. Header and hash size - %d. Total file size - %d.",
    //       l_header_size, l_header_and_hash_size, ftell(file_silver_hash_blocks));

    //End of init/load silver_hash_file
    //-------------------------------------------------------------

     return 0;
}


/**
 * @brief dap_chain_close
 * @param a_chain
 */
void dap_chain_close(dap_chain_t * a_chain)
{

}

/**
 * @brief dap_chain_update
 * @param l_block_cache
 */
void dap_chain_update(dap_chain_block_cache_t *l_block_cache){
    //dap_chain_file_write(l_block_cache);

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
    if ( a_chain->block_cache_last )
        l_block = dap_chain_block_new( &a_chain->block_cache_last->block_hash );
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

void dap_chain_show_hash_blocks_file(FILE *a_hash_blocks_file)
{
    if (NULL == a_hash_blocks_file)
        return;

    dap_chain_t l_chain;
    dap_chain_file_header_t l_header;
    dap_chain_block_t l_block;

    pthread_mutex_lock(&s_mutex);

    fseek(a_hash_blocks_file, 0, SEEK_SET);
    fread(&l_chain.blocks_count, sizeof(l_chain.blocks_count), 1, a_hash_blocks_file);
    fread(&l_chain.difficulty, sizeof(l_chain.difficulty), 1, a_hash_blocks_file);
    fread(&l_header, sizeof(l_header), 1, a_hash_blocks_file);

    fseek(a_hash_blocks_file, 40, SEEK_SET);
    char buf[PATH_MAX];
    snprintf(buf, sizeof buf, "/proc/self/fd/%d", fileno(a_hash_blocks_file));
    readlink(buf, buf, sizeof buf);
    log_it(L_INFO, " Start of hash sequense from file %s", buf);

    size_t l_ret_sz = fread(&l_block, sizeof(l_block.header), 1, a_hash_blocks_file);
    while (l_ret_sz > 0){
        char * l_prev_hash_str = dap_chain_hash_to_str_new(&l_block.header.prev_block);
        log_it(L_INFO, "  **    prev_block      %s", l_prev_hash_str);
        DAP_DELETE(l_prev_hash_str);
        l_ret_sz = fread(&l_block, sizeof(l_block.header), 1, a_hash_blocks_file);
    }
    log_it(L_INFO, " End of hash sequense!\n");

    pthread_mutex_unlock(&s_mutex);

}

dap_chain_block_t *dap_chain_get_last_mined_block(bool a_is_gold)
{
    dap_chain_block_t *l_new_block = dap_chain_block_new(NULL);

    pthread_mutex_lock(&s_mutex);
    if (true == a_is_gold)
        memcpy(l_new_block, g_gold_chain.block_cache_last->block, sizeof (dap_chain_block_t));
    else
        memcpy(l_new_block, g_silver_chain.block_cache_last->block, sizeof (dap_chain_block_t));
    pthread_mutex_unlock(&s_mutex);

    return l_new_block;
}

int dap_chain_get_mined_block_count(bool a_is_gold)
{
    if (true == a_is_gold)
        return g_gold_chain.blocks_count;
    else
        return g_silver_chain.blocks_count;
}
