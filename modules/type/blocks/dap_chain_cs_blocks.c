/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017-2020
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <pthread.h>
#include "dap_common.h"
#include "dap_enc_base58.h"
#include "dap_chain.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_block_chunk.h"
#include "dap_timerfd.h"
#include "dap_cli_server.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_chain_mempool.h"

#define LOG_TAG "dap_chain_cs_blocks"

typedef struct dap_chain_block_datum_index {
    dap_chain_hash_fast_t datum_hash;
    int ret_code;
    time_t ts_added;
    dap_chain_block_cache_t *block_cache;
    size_t datum_index;
    UT_hash_handle hh;
} dap_chain_block_datum_index_t;

struct cs_blocks_hal_item {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
};

typedef struct dap_chain_cs_blocks_pvt
{
    // Parent link
    dap_chain_cs_blocks_t * cs_blocks;

    // All the blocks are here. In feature should be limited with 1000 when the rest would be loaded from file when needs them
    dap_chain_block_cache_t * blocks;

    // Chunks treshold
    dap_chain_block_chunks_t * chunks;
    dap_chain_block_datum_index_t *datum_index; // To find datum in blocks

    dap_chain_hash_fast_t genesis_block_hash;
    dap_chain_hash_fast_t static_genesis_block_hash;

    uint64_t blocks_count;

    time_t time_between_blocks_minimum; // Minimal time between blocks
    bool is_celled;

    dap_timerfd_t *fill_timer;
    uint64_t fill_timeout;

    pthread_rwlock_t rwlock, datums_rwlock;
    struct cs_blocks_hal_item *hal;
} dap_chain_cs_blocks_pvt_t;

#define PVT(a) ((dap_chain_cs_blocks_pvt_t *)(a)->_pvt )

static int s_cli_parse_cmd_hash(char ** a_argv, int a_arg_index, int a_argc, char **a_str_reply,const char * a_param, dap_chain_hash_fast_t * a_datum_hash);
static void s_cli_meta_hash_print(  dap_string_t * a_str_tmp, const char * a_meta_title, dap_chain_block_meta_t * a_meta);
static int s_cli_blocks(int a_argc, char ** a_argv, char **a_str_reply);

// Setup BFT consensus and select the longest chunk
static void s_bft_consensus_setup(dap_chain_cs_blocks_t * a_blocks);

// Callbacks
static void s_callback_delete(dap_chain_t * a_chain);
// Accept new block
static dap_chain_atom_verify_res_t s_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);
//    Verify new block
static dap_chain_atom_verify_res_t s_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);

//    Get block header size
static size_t s_callback_atom_get_static_hdr_size(void);

static dap_chain_atom_iter_t *s_callback_atom_iter_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold);
static dap_chain_atom_iter_t* s_callback_atom_iter_create_from(dap_chain_t *  ,
                                                                     dap_chain_atom_ptr_t , size_t);
static dap_chain_atom_ptr_t s_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
static dap_chain_datum_t *s_callback_datum_find_by_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                        dap_chain_hash_fast_t *a_block_hash, int *a_ret_code);

static dap_chain_atom_ptr_t s_callback_block_find_by_tx_hash(dap_chain_t * a_chain, dap_chain_hash_fast_t * a_tx_hash, size_t *a_block_size);

static dap_chain_datum_t** s_callback_atom_get_datums(dap_chain_atom_ptr_t a_atom, size_t a_atom_size, size_t * a_datums_count);
static dap_time_t s_chain_callback_atom_get_timestamp(dap_chain_atom_ptr_t a_atom) { return ((dap_chain_block_t *)a_atom)->hdr.ts_created; }
//    Get blocks
static dap_chain_atom_ptr_t s_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size ); //    Get the fisrt block
static dap_chain_atom_ptr_t s_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter,size_t *a_atom_size );  //    Get the next block
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter , size_t *a_links_size,
                                                                  size_t ** a_links_size_ptr );  //    Get list of linked blocks
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_lasts( dap_chain_atom_iter_t * a_atom_iter ,size_t *a_links_size,
                                                                  size_t ** a_lasts_size_ptr );  //    Get list of linked blocks
//Get list of hashes
static dap_list_t *s_block_parse_str_list(const char * a_hash_str,size_t * a_hash_size, dap_chain_t * a_chain, dap_cert_t * a_cert);

// Delete iterator
static void s_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt block

// Datum ops
static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain);
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter);
static dap_chain_datum_t *s_chain_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter); // Get the fisrt datum from blocks
static dap_chain_datum_t *s_chain_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter); // Get the next datum from blocks

static size_t s_callback_add_datums(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_count);

static void s_callback_cs_blocks_purge(dap_chain_t *a_chain);

static dap_chain_block_t *s_new_block_move(dap_chain_cs_blocks_t *a_blocks, size_t *a_new_block_size);

//Work with atoms
static size_t s_callback_count_atom(dap_chain_t *a_chain);
static dap_list_t *s_callback_get_atoms(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);

static bool s_seed_mode = false;
static bool s_debug_more = false;


/**
 * @brief dap_chain_cs_blocks_init
 * @return
 */
int dap_chain_cs_blocks_init()
{
    dap_chain_cs_type_add("blocks", dap_chain_cs_blocks_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    s_debug_more = dap_config_get_item_bool_default(g_config, "blocks", "debug_more", false);
    dap_cli_server_cmd_add ("block", s_cli_blocks, "Create and explore blockchains",
        "New block create, fill and complete commands:\n"
            "block -net <net_name> -chain <chain_name> new\n"
                "\t\tCreate new block and flush memory if was smth formed before\n\n"

            "block -net <net_name> -chain <chain_name> new_datum_add <datum_hash>\n"
                "\t\tAdd block section from datum <datum hash> taken from the mempool\n\n"

            "block -net <net_name> -chain <chain_name> new_datum_del <datum_hash>\n"
                "\t\tDel block section with datum <datum hash>\n\n"

            "block -net <net_name> -chain <chain_name> new_datum_list\n"
                "\t\tList block sections and show their datums hashes\n\n"

            "block -net <net_name> -chain <chain_name> new_datum\n\n"
                "\t\tComplete the current new round, verify it and if everything is ok - publish new blocks in chain\n\n"

        "Blockchain explorer:\n"
            "block -net <net_name> -chain <chain_name> dump <block_hash>\n"
                "\t\tDump block info\n\n"

            "block -net <net_name> -chain <chain_name> list [-from_hash <block_hash>] [-to_hash <block_hash>]"
            "[-from_dt <in YYMMDD>] [-to_dt <in YYMMDD>] [-cert <priv_cert_name> -unspent]\n"
                "\t\t List blocks\n\n"
        "Commission collect:\n"
            "block -net <net_name> -chain <chain_name> fee collect\n"
            "-cert <priv_cert_name> -addr <addr> -hashes <hashes list> -fee <value>\n"
                "\t\t Take the whole commission\n\n"

                                        );
    if( dap_chain_block_cache_init() ) {
        log_it(L_WARNING, "Can't init blocks cache");
    }
    log_it(L_NOTICE,"Initialized blocks(m) chain type");

    return 0;
}

/**
 * @brief dap_chain_cs_blocks_deinit
 */
void dap_chain_cs_blocks_deinit()
{
    dap_chain_block_cache_deinit();
}

int dap_chain_cs_blocks_new(dap_chain_t * a_chain, dap_config_t * a_chain_config)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_NEW_Z(dap_chain_cs_blocks_t);
    if (!l_cs_blocks) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    a_chain->_inheritor = l_cs_blocks;
    l_cs_blocks->chain = a_chain;

    a_chain->callback_delete = s_callback_delete;

    // Atom element callbacks
    a_chain->callback_atom_add = s_callback_atom_add ;  // Accept new element in chain
    a_chain->callback_atom_verify = s_callback_atom_verify ;  // Verify new element in chain
    a_chain->callback_atom_get_hdr_static_size = s_callback_atom_get_static_hdr_size; // Get block hdr size

    a_chain->callback_atom_iter_create = s_callback_atom_iter_create;
    a_chain->callback_atom_iter_create_from = s_callback_atom_iter_create_from;
    a_chain->callback_atom_iter_delete = s_callback_atom_iter_delete;
    // Linear pass through
    a_chain->callback_atom_iter_get_first = s_callback_atom_iter_get_first; // Get the fisrt element from chain
    a_chain->callback_atom_iter_get_next = s_callback_atom_iter_get_next; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_links = s_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_callback_atom_iter_get_lasts;

    // Datum operations callbacks
    a_chain->callback_datum_iter_create = s_chain_callback_datum_iter_create; // Datum iterator create
    a_chain->callback_datum_iter_delete = s_chain_callback_datum_iter_delete; // Datum iterator delete
    a_chain->callback_datum_iter_get_first = s_chain_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_chain_callback_datum_iter_get_next; // Get the next datum from chain from the current one

    a_chain->callback_atom_get_datums = s_callback_atom_get_datums;
    a_chain->callback_atom_get_timestamp = s_chain_callback_atom_get_timestamp;

    a_chain->callback_atom_find_by_hash = s_callback_atom_iter_find_by_hash;
    a_chain->callback_datum_find_by_hash = s_callback_datum_find_by_hash;

    a_chain->callback_block_find_by_tx_hash = s_callback_block_find_by_tx_hash;

    a_chain->callback_add_datums = s_callback_add_datums;
    a_chain->callback_purge = s_callback_cs_blocks_purge;

    a_chain->callback_count_atom = s_callback_count_atom;
    a_chain->callback_get_atoms = s_callback_get_atoms;

    l_cs_blocks->callback_new_block_move = s_new_block_move;

    dap_chain_cs_blocks_pvt_t *l_cs_blocks_pvt = DAP_NEW_Z(dap_chain_cs_blocks_pvt_t);
    if (!l_cs_blocks_pvt) {
        log_it(L_CRITICAL, "Memory allocation error");
        return -1;
    }
    l_cs_blocks->_pvt = l_cs_blocks_pvt;
    pthread_rwlock_init(&l_cs_blocks_pvt->rwlock,NULL);
    pthread_rwlock_init(&l_cs_blocks_pvt->datums_rwlock, NULL);

    const char * l_genesis_blocks_hash_str = dap_config_get_item_str_default(a_chain_config,"blocks","genesis_block",NULL);
    if ( l_genesis_blocks_hash_str ){
        int lhr;
        if ( (lhr= dap_chain_hash_fast_from_str(l_genesis_blocks_hash_str,&l_cs_blocks_pvt->genesis_block_hash) )!= 0 ){
            log_it( L_ERROR, "Can't read hash from genesis_block \"%s\", ret code %d ", l_genesis_blocks_hash_str, lhr);
        }
    }
    l_cs_blocks_pvt->is_celled = dap_config_get_item_bool_default(a_chain_config,"blocks","is_celled",false);
    const char * l_static_genesis_blocks_hash_str = dap_config_get_item_str_default(a_chain_config,"blocks","static_genesis_block",NULL);
    if ( l_static_genesis_blocks_hash_str ){
        int lhr;
        if ( (lhr= dap_chain_hash_fast_from_str(l_static_genesis_blocks_hash_str,&l_cs_blocks_pvt->static_genesis_block_hash) )!= 0 ){
            log_it( L_ERROR, "Can't read hash from static_genesis_block \"%s\", ret code %d ", l_static_genesis_blocks_hash_str, lhr);
        }
    }
    l_cs_blocks_pvt->chunks = dap_chain_block_chunks_create(l_cs_blocks);

    l_cs_blocks_pvt->fill_timeout = dap_config_get_item_uint64_default(a_chain_config, "blocks", "fill_timeout", 60) * 1000; // 1 min
    l_cs_blocks_pvt->blocks_count = 0;

    uint16_t l_list_len = 0;
    char **l_hard_accept_list = dap_config_get_array_str(a_chain_config, "blocks", "hard_accept_list", &l_list_len);
    log_it(L_MSG, "HAL for blocks contains %d whitelisted events", l_list_len);
    for (uint16_t i = 0; i < l_list_len; i++) {
        struct cs_blocks_hal_item *l_hal_item = DAP_NEW_Z(struct cs_blocks_hal_item);
        if (!l_hal_item){
        log_it(L_CRITICAL, "Memory allocation error");
            DAP_DEL_Z(l_cs_blocks_pvt);
            DAP_DELETE(l_cs_blocks);
            return -10;
        }
        dap_chain_hash_fast_from_str(l_hard_accept_list[i], &l_hal_item->hash);
        HASH_ADD(hh, l_cs_blocks_pvt->hal, hash, sizeof(l_hal_item->hash), l_hal_item);
    }

    return 0;
}

/**
 * @brief dap_chain_cs_blocks_delete
 * @param a_chain
 */
void dap_chain_cs_blocks_delete(dap_chain_t * a_chain)
{
    s_callback_delete(a_chain);
}

/**
 * @brief dap_chain_block_cs_cache_get_by_hash
 * @param a_blocks
 * @param a_block_hash
 * @return
 */
dap_chain_block_cache_t * dap_chain_block_cs_cache_get_by_hash(dap_chain_cs_blocks_t * a_blocks,  dap_chain_hash_fast_t *a_block_hash)
{
    dap_chain_block_cache_t * l_ret = NULL;
    pthread_rwlock_rdlock(& PVT(a_blocks)->rwlock);
    HASH_FIND(hh, PVT(a_blocks)->blocks,a_block_hash, sizeof (*a_block_hash), l_ret );
    pthread_rwlock_unlock(& PVT(a_blocks)->rwlock);
    return l_ret;
}

/**
 * @brief s_cli_parse_cmd_hash
 * @param a_argv
 * @param a_arg_index
 * @param a_argc
 * @param a_str_reply
 * @param a_param
 * @param a_datum_hash
 * @return
 */
static int s_cli_parse_cmd_hash(char ** a_argv, int a_arg_index, int a_argc, char **a_str_reply,const char * a_param,
                                dap_chain_hash_fast_t * a_datum_hash)
{
    assert(a_datum_hash);

    const char *l_datum_hash_str = NULL;
    dap_cli_server_cmd_find_option_val(a_argv, a_arg_index, a_argc, a_param, &l_datum_hash_str);

    return dap_chain_hash_fast_from_str(l_datum_hash_str, a_datum_hash);
}

/**
 * @brief s_cli_meta_hash_print
 * @param a_str_tmp
 * @param a_meta_title
 * @param a_meta
 */
static void s_cli_meta_hash_print(  dap_string_t * a_str_tmp, const char * a_meta_title, dap_chain_block_meta_t * a_meta)
{
    if (a_meta->hdr.data_size == sizeof (dap_chain_hash_fast_t)) {
        char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_chain_hash_fast_to_str((dap_chain_hash_fast_t*)a_meta->data, l_hash_str, sizeof(l_hash_str));
        dap_string_append_printf(a_str_tmp,"\t\tPREV: \"%s\": %s\n", a_meta_title,l_hash_str);
    } else {
        char *l_data_hex = DAP_NEW_Z_SIZE(char,a_meta->hdr.data_size * 2 + 3);
        dap_bin2hex(l_data_hex, a_meta->data, a_meta->hdr.data_size);
        dap_string_append_printf(a_str_tmp,"\t\t\%s: 0x%s\n", a_meta_title, l_data_hex);
        DAP_DELETE(l_data_hex);
    }
}

/**
 * @brief s_cli_meta_hex_print
 * @param a_str_tmp
 * @param a_meta_title
 * @param a_meta
 */
static void s_cli_meta_hex_print(  dap_string_t * a_str_tmp, const char * a_meta_title, dap_chain_block_meta_t * a_meta)
{
    char *l_data_hex = DAP_NEW_Z_SIZE(char, a_meta->hdr.data_size * 2 + 3);
    dap_bin2hex(l_data_hex, a_meta->data, a_meta->hdr.data_size);
    dap_string_append_printf(a_str_tmp,"\t\t\%s: 0x%s\n", a_meta_title, l_data_hex);
    DAP_DELETE(l_data_hex);
}

/**
 * @brief s_cli_blocks
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
static int s_cli_blocks(int a_argc, char ** a_argv, char **a_str_reply)
{
    enum {
        SUBCMD_UNDEFINED =0,
        SUBCMD_NEW_FLUSH,
        SUBCMD_NEW_DATUM_ADD,
        SUBCMD_NEW_DATUM_DEL,
        SUBCMD_NEW_DATUM_LIST,
        SUBCMD_NEW_COMPLETE,
        SUBCMD_DUMP,
        SUBCMD_LIST,
        SUBCMD_FEE,
        SUBCMD_DROP
    } l_subcmd={0};

    const char* l_subcmd_strs[]={
        [SUBCMD_NEW_FLUSH]="new",
        [SUBCMD_NEW_DATUM_ADD]="new_datum_add",
        [SUBCMD_NEW_DATUM_DEL]="new_datum_del",
        [SUBCMD_NEW_DATUM_LIST]="new_datum_list",
        [SUBCMD_NEW_COMPLETE]="new_complete",
        [SUBCMD_DUMP]="dump",
        [SUBCMD_LIST]="list",
        [SUBCMD_FEE]="fee",
        [SUBCMD_DROP]="drop",
        [SUBCMD_UNDEFINED]=NULL
    };
    const size_t l_subcmd_str_count=sizeof(l_subcmd_strs)/sizeof(*l_subcmd_strs);
    const char* l_subcmd_str_args[l_subcmd_str_count];
	for(size_t i=0;i<l_subcmd_str_count;i++)
        l_subcmd_str_args[i]=NULL;
    const char* l_subcmd_str_arg;
    const char* l_subcmd_str = NULL;

    int arg_index = 1;

    dap_chain_t * l_chain = NULL;
    dap_chain_cs_blocks_t * l_blocks = NULL;
    dap_chain_net_t * l_net = NULL;

    // Parse default values
    if(dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net) < 0)
        return -11;

    const char *l_chain_type = dap_chain_net_get_type(l_chain);

    if (!strstr(l_chain_type, "block_") && strcmp(l_chain_type, "esbocs")){
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Type of chain %s is not block. This chain with type %s is not supported by this command",
                        l_chain->name, l_chain_type);
            return -42;
    }

    l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);

    // Parse commands
    for (size_t i=0; i<l_subcmd_str_count; i++){
        int l_opt_idx = dap_cli_server_cmd_check_option(a_argv, arg_index,a_argc, l_subcmd_strs[i]);
        if( l_opt_idx >= 0 ){
            dap_cli_server_cmd_find_option_val(a_argv, l_opt_idx, a_argc, l_subcmd_strs[i], &l_subcmd_str_args[i] );
            l_subcmd = i;
            l_subcmd_str = l_subcmd_strs[i];
            l_subcmd_str_arg = l_subcmd_str_args[i];
        }
    }
    int ret=-1000;
    // Do subcommand action
    switch ( l_subcmd ){
        // Flush memory for the new block
        case SUBCMD_NEW_FLUSH:{
            pthread_rwlock_wrlock( &PVT(l_blocks)->rwlock );
            if ( l_blocks->block_new )
                DAP_DELETE( l_blocks->block_new );
            dap_chain_block_cache_t *l_bcache_last = PVT(l_blocks)->blocks ? PVT(l_blocks)->blocks->hh.tbl->tail->prev : NULL;
            l_bcache_last = l_bcache_last ? l_bcache_last->hh.next : PVT(l_blocks)->blocks;
            l_blocks->block_new = dap_chain_block_new(l_bcache_last ? &l_bcache_last->block_hash : NULL,
                                                      &l_blocks->block_new_size);
            pthread_rwlock_unlock( &PVT(l_blocks)->rwlock );
        } break;

        // Add datum to the forming new block
        case SUBCMD_NEW_DATUM_LIST:{
            pthread_rwlock_wrlock( &PVT(l_blocks)->rwlock );
            pthread_rwlock_unlock( &PVT(l_blocks)->rwlock );
        }break;
        case SUBCMD_NEW_DATUM_DEL:{
            pthread_rwlock_wrlock( &PVT(l_blocks)->rwlock );
            if ( l_blocks->block_new ){
                dap_chain_hash_fast_t l_datum_hash;
                s_cli_parse_cmd_hash(a_argv,arg_index,a_argc,a_str_reply,"-datum", &l_datum_hash );
                l_blocks->block_new_size=dap_chain_block_datum_del_by_hash( &l_blocks->block_new, l_blocks->block_new_size, &l_datum_hash );
            }else {
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                          "Error! Can't delete datum from hash because no forming new block! Check pls you role, it must be MASTER NODE or greater");
                ret = -12;
            }
            pthread_rwlock_unlock( &PVT(l_blocks)->rwlock );
        }break;
        case SUBCMD_NEW_DATUM_ADD:{
            size_t l_datums_count=1;
            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool_new(l_chain);
            dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,
                                                           sizeof(dap_chain_datum_t*)*l_datums_count);
            if (!l_datums) {
        log_it(L_CRITICAL, "Memory allocation error");
                dap_cli_server_cmd_set_reply_text(a_str_reply,"Out of memory in s_cli_blocks");
                return -1;
            }
            size_t l_datum_size = 0;

            dap_chain_datum_t * l_datum = (dap_chain_datum_t*) dap_global_db_get_sync(l_gdb_group_mempool, l_subcmd_str_arg ,
                                                                                              &l_datum_size, NULL, NULL);
            l_datums[0] = l_datum;
            for (size_t i = 0; i < l_datums_count; i++) {
                bool l_err = dap_chain_node_mempool_process(l_chain, l_datums[i], l_subcmd_str_arg);
                if (l_err) {
                    dap_cli_server_cmd_set_reply_text(a_str_reply, "Error! Datum %s doesn't pass verifications, examine node log files",
                                                      l_subcmd_str_arg);
                    ret = -9;
                } else {
                   log_it(L_INFO, "Pass datum %s from mempool to block in the new forming round ",
                                                     l_subcmd_str_arg);
                   ret = 0;
                }
                if (l_err)
                    break;
            }
            dap_cli_server_cmd_set_reply_text(a_str_reply, "All datums processed");
            DAP_DELETE(l_gdb_group_mempool);
        } break;

        case SUBCMD_NEW_COMPLETE:{
            dap_chain_net_sync_all(l_net);
        } break;

        case SUBCMD_DROP:{
            dap_chain_net_sync_all(l_net);
        }break;
        case SUBCMD_DUMP:{
            dap_chain_block_t  * l_block;
            size_t l_block_size = 0;
            dap_chain_hash_fast_t l_block_hash={0};
			if(l_subcmd_str_arg){
					dap_chain_hash_fast_from_str( l_subcmd_str_arg, &l_block_hash); // Convert argument to hash
					l_block = (dap_chain_block_t*) dap_chain_get_atom_by_hash( l_chain, &l_block_hash, &l_block_size);
					if ( l_block){
						dap_chain_block_cache_t *l_block_cache = dap_chain_block_cs_cache_get_by_hash(l_blocks, &l_block_hash);
						if ( l_block_cache ){
							dap_string_t * l_str_tmp = dap_string_new(NULL);
							char buf[50];
							time_t l_ts_reated = (time_t) l_block->hdr.ts_created;
							// Header
							dap_string_append_printf(l_str_tmp,"Block %s:\n", l_subcmd_str_arg);
							dap_string_append_printf(l_str_tmp, "\t\t\tversion: 0x%04X\n", l_block->hdr.version);
							dap_string_append_printf(l_str_tmp,"\t\t\tcell_id: 0x%016"DAP_UINT64_FORMAT_X"\n",l_block->hdr.cell_id.uint64);
							dap_string_append_printf(l_str_tmp,"\t\t\tchain_id: 0x%016"DAP_UINT64_FORMAT_X"\n",l_block->hdr.chain_id.uint64);
							ctime_r(&l_ts_reated, buf);
							dap_string_append_printf(l_str_tmp,"\t\t\tts_created: %s\n", buf);
		
							// Dump Metadata
							dap_string_append_printf(l_str_tmp,"\tMetadata. Count: %us\n",l_block->hdr.meta_count );
							for (uint32_t i=0; i < l_block_cache->meta_count; i++){
								dap_chain_block_meta_t * l_meta = l_block_cache->meta[i];
								switch (l_meta->hdr.type) {
									case DAP_CHAIN_BLOCK_META_GENESIS:{
										dap_string_append_printf(l_str_tmp, "\t\tGENESIS\n");
									}break;
									case DAP_CHAIN_BLOCK_META_PREV:{
										s_cli_meta_hash_print(l_str_tmp, "PREV", l_meta);
									}break;
									case DAP_CHAIN_BLOCK_META_ANCHOR:{
										s_cli_meta_hash_print(l_str_tmp, "ANCHOR", l_meta);
									}break;
									case DAP_CHAIN_BLOCK_META_LINK:{
										s_cli_meta_hash_print(l_str_tmp, "LINK", l_meta);
									}break;
									case DAP_CHAIN_BLOCK_META_NONCE:{
										s_cli_meta_hex_print(l_str_tmp,"NONCE", l_meta);
									}break;
									case DAP_CHAIN_BLOCK_META_NONCE2:{
										s_cli_meta_hex_print(l_str_tmp,"NONCE2", l_meta);
									}break;
									default:{
										char * l_data_hex = DAP_NEW_Z_SIZE(char,l_meta->hdr.data_size*2+3);
										dap_bin2hex(l_data_hex, l_meta->data, l_meta->hdr.data_size);
										dap_string_append_printf(l_str_tmp, "\t\t 0x%0X: 0x%s\n", i, l_data_hex );
										DAP_DELETE(l_data_hex);
									}
								}
							}
							dap_string_append_printf(l_str_tmp,"\t\tdatums:\tcount: %zu\n",l_block_cache->datum_count);
							for (uint32_t i=0; i < l_block_cache->datum_count ; i++){
								dap_chain_datum_t * l_datum = l_block_cache->datum[i];
								size_t l_datum_size =  dap_chain_datum_size(l_datum);
								dap_string_append_printf(l_str_tmp,"\t\t\tdatum:\tdatum_size: %zu\n",l_datum_size);
								if (l_datum_size < sizeof (l_datum->header) ){
									dap_string_append_printf(l_str_tmp,"\t\t\tERROR: datum size %zu is smaller than header size %zu \n",l_datum_size,
															sizeof (l_datum->header));
									break;
								}
								time_t l_datum_ts_create = (time_t) l_datum->header.ts_create;
								// Nested datums
								dap_string_append_printf(l_str_tmp,"\t\t\t\tversion:=0x%02X\n", l_datum->header.version_id);
								const char * l_datum_type_str="UNKNOWN";
								DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_datum_type_str);
								dap_string_append_printf(l_str_tmp,"\t\t\t\ttype_id:=%s\n", l_datum_type_str);
								ctime_r(&l_datum_ts_create, buf);
								dap_string_append_printf(l_str_tmp,"\t\t\t\tts_create=%s\n", buf);
								dap_string_append_printf(l_str_tmp,"\t\t\t\tdata_size=%u\n", l_datum->header.data_size);
                                dap_chain_datum_dump(l_str_tmp, l_datum, "hex", l_net->pub.id);
							}
							// Signatures
							dap_string_append_printf(l_str_tmp,"\t\tsignatures:\tcount: %zu\n",l_block_cache->sign_count );
                            for (uint32_t i=0; i < l_block_cache->sign_count ; i++) {
								dap_sign_t * l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, i);
								size_t l_sign_size = dap_sign_get_size(l_sign);
								dap_chain_hash_fast_t l_pkey_hash;
								dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
                                char l_pkey_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                                dap_chain_hash_fast_to_str(&l_pkey_hash, l_pkey_hash_str, sizeof(l_pkey_hash_str));
								dap_string_append_printf(l_str_tmp,"\t\t\ttype:%s size: %zd pkey_hash: %s \n"
																"\t\t\t\n", dap_sign_type_to_str( l_sign->header.type ),
																		l_sign_size, l_pkey_hash_str );
							}
                            dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_tmp->str);
                            dap_string_free(l_str_tmp, true);
							ret=0;
						}
					}else {
						dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't find block %s ", l_subcmd_str_arg);
						ret=-10;
					}
			}
			else
            {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Enter block hash ");
                ret=-13;
            }
        }break;
        case SUBCMD_LIST:{
                const char * l_cert_name, *l_from_hash_name, *l_to_hash_name, *l_from_dt_name, *l_to_dt_name;
                l_cert_name = l_from_hash_name = l_to_hash_name = l_from_dt_name = l_to_dt_name = NULL;
                bool l_unspent_fl = false,l_hash_fl = false;
                size_t l_block_count = 0;
                dap_cert_t * l_cert = NULL;
                dap_pkey_t * l_pub_key = NULL;                
                dap_hash_fast_t l_from_hash;
                dap_hash_fast_t l_to_hash;

                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_hash", &l_from_hash_name);
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_hash", &l_to_hash_name);
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_dt", &l_from_dt_name);
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_dt", &l_to_dt_name);

                if(l_cert_name) {

                    l_cert = dap_cert_find_by_name( l_cert_name );
                    if( l_cert == NULL ){
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                "Can't find \"%s\" certificate", l_cert_name );
                        return -18;
                    }
                    if( l_cert->enc_key == NULL ){
                        dap_cli_server_cmd_set_reply_text(a_str_reply,
                                "Corrupted certificate \"%s\" without keys certificate", l_cert_name );
                        return -20;
                    }
                    if(l_cert) {
                        l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
                    }
                    if(dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-unspent", NULL))
                        l_unspent_fl = true;
                }
                if(l_to_hash_name){
                    dap_chain_hash_fast_from_hex_str(l_to_hash_name, &l_to_hash);
                }
                if(l_from_hash_name){
                    dap_chain_hash_fast_from_hex_str(l_from_hash_name, &l_from_hash);
                }
                if(l_from_dt_name){
                    char l_from_data_month[3] = {l_from_dt_name[2], l_from_dt_name[3], 0};
                    int l_from_time_month = atoi(l_from_data_month);
                    if (l_from_time_month < 1 || l_from_time_month > 12)
                        return -21;
                    char l_from_data_day[3] = {l_from_dt_name[4], l_from_dt_name[5], 0};
                    int l_from_time_day = atoi(l_from_data_day);
                    if (l_from_time_day < 1 || l_from_time_day > 31)
                        return -21;
                }
                if(l_to_dt_name){
                    char l_to_data_month[3] = {l_to_dt_name[2], l_to_dt_name[3], 0};
                    int l_to_time_month = atoi(l_to_data_month);
                    if (l_to_time_month < 1 || l_to_time_month > 12)
                        return -21;
                    char l_to_data_day[3] = {l_to_dt_name[4], l_to_dt_name[5], 0};
                    int l_to_time_day = atoi(l_to_data_day);
                    if (l_to_time_day < 1 || l_to_time_day > 31)
                        return -21;
                }

                time_t l_from_data = dap_time_from_str_simplified(l_from_dt_name);
                time_t l_to_data = dap_time_from_str_simplified(l_to_dt_name);

                pthread_rwlock_rdlock(&PVT(l_blocks)->rwlock);
                dap_string_t * l_str_tmp = dap_string_new(NULL);             
                for (dap_chain_block_cache_t *l_block_cache = PVT(l_blocks)->blocks; l_block_cache; l_block_cache = l_block_cache->hh.next) {
                    char l_buf[50];
                    time_t l_ts = l_block_cache->block->hdr.ts_created;
                    ctime_r(&l_ts, l_buf);
                    dap_sign_t * l_sign = NULL;
                    if(l_cert)
                    {
                        l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, 0);
                        if(!dap_pkey_compare_with_sign(l_pub_key, l_sign))
                            continue;
                        if(l_unspent_fl){
                            bool fl_found = false;
                            for (size_t i = 0; i < l_block_cache->datum_count; i++) {
                                if (l_block_cache->datum[i]->header.type_id != DAP_CHAIN_DATUM_TX)
                                    continue;
                                dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_block_cache->datum[i]->data;
                                int l_out_idx_tmp = 0;
                                if (NULL == dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, &l_out_idx_tmp))
                                    continue;
                                if (!dap_chain_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_block_cache->datum_hash + i, l_out_idx_tmp, NULL)) {
                                    fl_found = true;
                                    break;
                                }
                            }
                            if(!fl_found)
                                continue;
                        }
                    }
                    if(l_to_hash_name && dap_hash_fast_compare(&l_to_hash,&l_block_cache->block_hash))
                        break;
                    if(l_to_dt_name && (l_to_data < l_ts))
                        break;
                    if(dap_hash_fast_compare(&l_from_hash,&l_block_cache->block_hash))
                        l_hash_fl = true;
                    if((l_from_hash_name && !l_hash_fl) ||
                       (l_from_dt_name && (l_from_data > l_ts)))
                        continue;

                    dap_string_append_printf(l_str_tmp,"\t%s: ts_create=%s",
                                                 l_block_cache->block_hash_str, l_buf);
                    l_block_count++;
                }                
                if(l_cert){
                    dap_string_append_printf(l_str_tmp,"%s.%s: Have %"DAP_UINT64_FORMAT_U" blocks signed with %s certificate :\n",
                                             l_net->pub.name,l_chain->name,l_block_count,l_cert_name);
                }
                else if(l_to_hash_name || l_from_hash_name || l_from_dt_name || l_to_dt_name){
                    dap_string_append_printf(l_str_tmp,"%"DAP_UINT64_FORMAT_U" filtered blocks shown :\n",l_block_count);
                }
                dap_string_append_printf(l_str_tmp,"%s.%s: Have %"DAP_UINT64_FORMAT_U" blocks :\n",
                                         l_net->pub.name,l_chain->name,PVT(l_blocks)->blocks_count);

                pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
                dap_cli_server_cmd_set_reply_text(a_str_reply, "%s", l_str_tmp->str);
                dap_string_free(l_str_tmp, true);

        }break;
        case SUBCMD_FEE:{
            const char * str_tmp = NULL;
            const char * l_cert_name = NULL;
            const char * l_addr_str = NULL;
            const char * l_hash_out_type = NULL;
            const char * l_hash_str = NULL;

            uint256_t               l_fee_value = {};
            size_t                  l_hashes_count = 0;
            dap_list_t              *l_block_list = NULL;
            dap_chain_addr_t        *l_addr = NULL;

            //arg_index++;

            if(!dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "collect", NULL)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'block fee' requires parameter 'collect'");
                return -14;
            }
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
            if(!l_hash_out_type)
                l_hash_out_type = "hex";
            if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "invalid parameter -H, valid values: -H <hex | base58>");
                return -15;
            }

            // Private certificate
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
            // The address of the wallet to which the commission is received
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hashes", &l_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &str_tmp);

            if(!l_addr_str) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'block fee collect' requires parameter '-addr'");
                return -16;
            }
            l_addr = dap_chain_addr_from_str(l_addr_str);

            if(!l_cert_name) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'block fee collect' requires parameter '-cert'");
                return -17;
            }
            dap_cert_t * l_cert = dap_cert_find_by_name( l_cert_name );

            if( l_cert == NULL ){
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Can't find \"%s\" certificate", l_cert_name );
                return -18;
            }

            l_fee_value = dap_chain_balance_scan(str_tmp);
            if(!str_tmp||IS_ZERO_256(l_fee_value)) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'block fee collect' requires parameter '-fee' to be valid uint256");
                return -19;
            }

            if( l_cert->enc_key == NULL ){
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Corrupted certificate \"%s\" without keys certificate", l_cert_name );
                return -20;
            }

            if(!l_hash_str){
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'block fee collect' requires parameter '-hashes'");
                return -21;
            }
            l_block_list = s_block_parse_str_list(l_hash_str, &l_hashes_count,l_chain,l_cert);

            if(!l_hashes_count){
                dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Block fee collection requires at least one hash to create a transaction");
                return -22;
            }

            char * l_hash_tx = dap_chain_mempool_tx_coll_fee_create(l_cert->enc_key,l_addr,l_block_list,l_fee_value,l_hash_out_type);
            if (l_hash_tx) {
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Fee collect TX created succefully, hash=%s\n", l_hash_tx);
                ret = 0;
            }
            else
                dap_cli_server_cmd_set_reply_text(a_str_reply, "Can't create fee collect TX\n");
            ret = -24;

            DAP_DELETE(l_hash_tx);
            dap_list_free(l_block_list);
        }break;
        case SUBCMD_UNDEFINED: {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                                              "Undefined block subcommand \"%s\" ",
                                              l_subcmd_str);
            ret=-11;
        }
    }
    return ret;
}

static dap_list_t * s_block_parse_str_list(const char * a_hash_str,size_t * a_hash_size, dap_chain_t * a_chain, dap_cert_t *a_cert)
{
    dap_list_t *l_block_list = NULL;
    char * l_hashes_tmp_ptrs = NULL;
    char * l_hashes_str_dup = dap_strdup(a_hash_str);
    char *l_hashes_str = strtok_r(l_hashes_str_dup, ",", &l_hashes_tmp_ptrs);
    dap_chain_hash_fast_t   l_hash_block;
    dap_chain_block_t       *l_block;
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);

    dap_pkey_t *l_pub_key = NULL;
    if(a_cert) {
        l_pub_key = dap_pkey_from_enc_key(a_cert->enc_key);
    }
    // First we just calc items
    while(l_hashes_str) {
        l_hashes_str = strtok_r(NULL, ",", &l_hashes_tmp_ptrs);
        (*a_hash_size)++;
    }
    strcpy(l_hashes_str_dup, a_hash_str);
    l_hashes_str = strtok_r(l_hashes_str_dup, ",", &l_hashes_tmp_ptrs);

    size_t l_hashes_pos = 0;
    while(l_hashes_str) {
        l_hashes_str = dap_strstrip(l_hashes_str);
        if(dap_chain_hash_fast_from_hex_str(l_hashes_str, &l_hash_block)!=0) {
            log_it(L_WARNING,"Can't load hash %s",l_hashes_str);
            *a_hash_size = 0;
            DAP_DELETE(l_hashes_str_dup);
            return NULL;
        }
        size_t l_block_size = 0;
        l_block = (dap_chain_block_t*) dap_chain_get_atom_by_hash( a_chain, &l_hash_block, &l_block_size);
        if(!l_block)
        {
            log_it(L_WARNING,"There aren't any block by this hash");
            *a_hash_size = 0;
            DAP_DELETE(l_hashes_str_dup);
            return NULL;
        }
        dap_chain_block_cache_t *l_block_cache = dap_chain_block_cs_cache_get_by_hash(l_blocks, &l_hash_block);
        //verification of signatures of all blocks
        dap_sign_t * l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, 0);
        if(dap_pkey_compare_with_sign(l_pub_key, l_sign))
            l_block_list = dap_list_append(l_block_list, l_block_cache);
        else
             log_it(L_WARNING,"Block %s signature does not match certificate key", l_block_cache->block_hash_str);

        l_hashes_str = strtok_r(NULL, ",", &l_hashes_tmp_ptrs);
        l_hashes_pos++;
    }
    DAP_DELETE(l_hashes_str_dup);
    return l_block_list;
}

/**
 * @brief s_callback_delete
 * @details Destructor for blocks consensus chain
 * @param a_chain
 */
static void s_callback_delete(dap_chain_t * a_chain)
{
    s_callback_cs_blocks_purge(a_chain);
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    pthread_rwlock_wrlock(&PVT(l_blocks)->rwlock);
    if(l_blocks->callback_delete )
        l_blocks->callback_delete(l_blocks);
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
    pthread_rwlock_destroy(&PVT(l_blocks)->rwlock);
    pthread_rwlock_destroy(&PVT(l_blocks)->datums_rwlock);
    dap_chain_block_chunks_delete(PVT(l_blocks)->chunks);
    DAP_DEL_Z(l_blocks->_inheritor);
    DAP_DEL_Z(l_blocks->_pvt);
    log_it(L_INFO, "Block destructed");
}

static void s_callback_cs_blocks_purge(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    pthread_rwlock_wrlock(&PVT(l_blocks)->rwlock);
    dap_chain_block_cache_t *l_block = NULL, *l_block_tmp = NULL;
    HASH_ITER(hh, PVT(l_blocks)->blocks, l_block, l_block_tmp) {
        HASH_DEL(PVT(l_blocks)->blocks, l_block);
        DAP_DELETE(l_block->block);
        dap_chain_block_cache_delete(l_block);
    }
    PVT(l_blocks)->blocks_count = 0;
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
    
    dap_chain_block_datum_index_t *l_datum_index = NULL, *l_datum_index_tmp = NULL;
    pthread_rwlock_wrlock(&PVT(l_blocks)->datums_rwlock);
    HASH_ITER(hh, PVT(l_blocks)->datum_index, l_datum_index, l_datum_index_tmp) {
        HASH_DEL(PVT(l_blocks)->datum_index, l_datum_index);
        DAP_DELETE(l_datum_index);
        l_datum_index = NULL;
    }
    pthread_rwlock_unlock(&PVT(l_blocks)->datums_rwlock);

    dap_chain_block_chunks_delete(PVT(l_blocks)->chunks);
    dap_chain_cell_delete_all(a_chain);
    PVT(l_blocks)->chunks = dap_chain_block_chunks_create(l_blocks);
}

/**
 * @brief s_add_atom_to_ledger
 * @param a_blocks
 * @param a_block_cache
 * @return
 */
static int s_add_atom_datums(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_cache_t *a_block_cache)
{
    if (! a_block_cache->datum_count){
        log_it(L_WARNING,"Block %s has no datums at all, can't add anything to ledger", a_block_cache->block_hash_str);
        return 1; // No errors just empty block
    }
    int l_ret = 0;

    size_t l_block_offset = 0;
    size_t l_datum_size = 0;
    for(size_t i=0; i<a_block_cache->datum_count && l_block_offset +sizeof(a_block_cache->block->hdr) < a_block_cache->block_size ;
        i++, l_block_offset += l_datum_size ){
        dap_chain_datum_t *l_datum = a_block_cache->datum[i];
        size_t l_datum_data_size = l_datum->header.data_size;
        l_datum_size = l_datum_data_size + sizeof(l_datum->header);
        if(l_datum_size>a_block_cache->block_size- l_block_offset ){
            log_it(L_WARNING,"Corrupted block %s has strange datum on offset %zd with size %zd out of block sizee",
                   a_block_cache->block_hash_str, l_block_offset,l_datum_size );
            break;
        }
        dap_hash_fast_t *l_datum_hash = a_block_cache->datum_hash + i;
        int l_res = dap_chain_datum_add(a_blocks->chain, l_datum, l_datum_size, l_datum_hash);
        l_ret++;
        // Save datum hash -> block_hash link in hash table
        dap_chain_block_datum_index_t *l_datum_index = DAP_NEW_Z(dap_chain_block_datum_index_t);
        if (!l_datum_index) {
        log_it(L_CRITICAL, "Memory allocation error");
            return 1;
        }
        l_datum_index->ts_added = time(NULL);
        l_datum_index->block_cache = a_block_cache;
        l_datum_index->datum_hash = *l_datum_hash;
        l_datum_index->ret_code = l_res;
        l_datum_index->datum_index = i;
        pthread_rwlock_wrlock(&PVT(a_blocks)->datums_rwlock);
        HASH_ADD(hh, PVT(a_blocks)->datum_index, datum_hash, sizeof(*l_datum_hash), l_datum_index);
        pthread_rwlock_unlock(&PVT(a_blocks)->datums_rwlock);

    }
    return l_ret;
}


/**
 * @brief s_add_atom_to_blocks
 * @param a_blocks
 * @param a_block_cache
 * @return
 */
static int s_add_atom_to_blocks(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_cache_t *a_block_cache )
{
    int l_res = 0;
    //pthread_rwlock_wrlock( &PVT(a_blocks)->rwlock ); // do lock in calling context!
    l_res = s_add_atom_datums(a_blocks, a_block_cache);
    debug_if(s_debug_more, L_DEBUG, "Block %s checked, %s", a_block_cache->block_hash_str,
             l_res == (int)a_block_cache->datum_count ? "all correct" : "but ledger declined");
    // Ignore addition result for now
    HASH_ADD(hh, PVT(a_blocks)->blocks, block_hash, sizeof (a_block_cache->block_hash), a_block_cache);
    ++PVT(a_blocks)->blocks_count;
    //pthread_rwlock_unlock( &PVT(a_blocks)->rwlock ); // do unlock in calling context!
    return /* l_res */ 0;
}


/**
 * @brief s_bft_consensus_setup
 * @param a_blocks
 */
static void s_bft_consensus_setup(dap_chain_cs_blocks_t * a_blocks)
{
    bool l_was_chunks_changed = false;
    // Compare all chunks with chain's tail
    for (dap_chain_block_chunk_t *l_chunk = PVT(a_blocks)->chunks->chunks_last ; l_chunk; l_chunk=l_chunk->prev ){
        size_t l_chunk_length = HASH_COUNT(l_chunk->block_cache_hash);
        dap_chain_block_cache_t * l_block_cache_chunk_top_prev = dap_chain_block_cs_cache_get_by_hash(a_blocks,&l_chunk->block_cache_top->prev_hash);
        dap_chain_block_cache_t * l_block_cache= l_block_cache_chunk_top_prev;
        if ( l_block_cache ){ // we found prev block in main chain
            size_t l_tail_length = 0;
            // Now lets calc tail length
            for( ;l_block_cache; l_block_cache=l_block_cache->prev){
                l_tail_length++;
                if(l_tail_length>l_chunk_length)
                    break;
            }
            if(l_tail_length<l_chunk_length ){ // This generals consensus is bigger than the current one
                // Cutoff current chank from the list
                if( l_chunk->next)
                    l_chunk->next->prev = l_chunk->prev;
                if( l_chunk->prev)
                    l_chunk->prev->next = l_chunk->next;

                // Pass through all the tail and move it to chunks
                for(l_block_cache= l_block_cache_chunk_top_prev ;l_block_cache; l_block_cache=l_block_cache->prev){
                    pthread_rwlock_wrlock(& PVT(a_blocks)->rwlock);
                    if(l_block_cache->prev)
                        l_block_cache->prev->next = l_block_cache->next;
                    if(l_block_cache->next)
                        l_block_cache->next->prev = l_block_cache->prev;
                    HASH_DEL(PVT(a_blocks)->blocks,l_block_cache);
                    --PVT(a_blocks)->blocks_count;
                    pthread_rwlock_unlock(& PVT(a_blocks)->rwlock);
                    dap_chain_block_chunks_add(PVT(a_blocks)->chunks,l_block_cache);
                }
                // Pass through all the chunk and add it to main chain
                for(l_block_cache= l_chunk->block_cache_top ;l_block_cache; l_block_cache=l_block_cache->prev){
                    int l_check_res = 0;
                    if (a_blocks->callback_block_verify)
                        l_check_res = a_blocks->callback_block_verify(a_blocks, l_block_cache->block, l_block_cache->block_size);
                    if (!l_check_res)
                        l_check_res = s_add_atom_to_blocks(a_blocks, l_block_cache);
                    if ( l_check_res != 0 ){
                        log_it(L_WARNING,"Can't move block %s from chunk to main chain - data inside wasn't verified: code %d",
                                            l_block_cache->block_hash_str, l_check_res);
                        dap_chain_block_chunks_add(PVT(a_blocks)->chunks,l_block_cache);
                    }
                }
                dap_chain_block_chunk_delete(l_chunk );
                l_was_chunks_changed = true;
            }
        }

    }
    if(l_was_chunks_changed){
        dap_chain_block_chunks_sort( PVT(a_blocks)->chunks);
        log_it(L_INFO,"Recursive BFT stage additional check...");
        s_bft_consensus_setup(a_blocks);
    }
}

/**
 * @brief s_callback_atom_add
 * @details Accept new atom in blockchain
 * @param a_chain
 * @param a_atom
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_verify_res_t s_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom , size_t a_atom_size)
{
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_block_t * l_block = (dap_chain_block_t *) a_atom;
    size_t l_block_size = a_atom_size;

    dap_chain_hash_fast_t l_block_hash;
    dap_hash_fast(l_block, l_block_size, &l_block_hash);

    dap_chain_block_cache_t * l_block_cache = NULL;
    pthread_rwlock_wrlock(& PVT(l_blocks)->rwlock);
    HASH_FIND(hh, PVT(l_blocks)->blocks, &l_block_hash, sizeof(l_block_hash), l_block_cache);
    if (l_block_cache) {
        debug_if(s_debug_more, L_DEBUG, "... %s is already present", l_block_cache->block_hash_str);
        pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
        return ATOM_PASS;
    } else {
        l_block_cache = dap_chain_block_cache_new(l_blocks, &l_block_hash, l_block, l_block_size);
        if (!l_block_cache) {
            log_it(L_DEBUG, "... corrupted block");
            pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
            return ATOM_REJECT;
        }
        debug_if(s_debug_more, L_DEBUG, "... new block %s", l_block_cache->block_hash_str);
    }

    dap_chain_atom_verify_res_t ret = s_callback_atom_verify(a_chain, a_atom, a_atom_size);
    switch (ret) {
    case ATOM_ACCEPT:
        s_add_atom_to_blocks(l_blocks, l_block_cache);
        debug_if(s_debug_more, L_DEBUG, "Verified atom %p: ACCEPTED", a_atom);
        break;
    case ATOM_MOVE_TO_THRESHOLD:
        // TODO: reimplement and enable threshold for blocks
/*      {
            debug_if(s_debug_more, L_DEBUG, "Verified atom %p: THRESHOLDED", a_atom);
            break;
        }
*/
        ret = ATOM_REJECT;
    case ATOM_REJECT:
        dap_chain_block_cache_delete(l_block_cache);
        debug_if(s_debug_more, L_DEBUG, "Verified atom %p: REJECTED", a_atom);
        break;
    default:
        debug_if(s_debug_more, L_DEBUG, "Unknown verification ret code %d", ret);
        break;
    }
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
    return ret;
}

/**
 * @brief s_callback_atom_verify
 * @param a_chain
 * @param a_atom
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_verify_res_t s_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom , size_t a_atom_size)
{
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    assert(l_blocks);
    dap_chain_cs_blocks_pvt_t * l_blocks_pvt = PVT(l_blocks);
    assert(l_blocks_pvt);
    dap_chain_block_t * l_block = (dap_chain_block_t *) a_atom;
    dap_chain_hash_fast_t l_block_hash;

    if(sizeof (l_block->hdr) >= a_atom_size){
        log_it(L_WARNING,"Size of block is %zd that is equal or less then block's header size %zd",a_atom_size,sizeof (l_block->hdr));
        return  ATOM_REJECT;
    }

    // Hard accept list
    if (l_blocks_pvt->hal) {
        dap_hash_fast(l_block, a_atom_size, &l_block_hash);
        struct cs_blocks_hal_item *l_hash_found = NULL;
        HASH_FIND(hh, l_blocks_pvt->hal, &l_block_hash, sizeof(l_block_hash), l_hash_found);
        if (l_hash_found) {
            return ATOM_ACCEPT;
        }
    }

    size_t l_meta_count = 0;
    dap_chain_block_meta_t ** l_meta=  dap_chain_block_get_meta(l_block, a_atom_size, & l_meta_count);
    // Parse metadata
    bool l_is_genesis=false;
    dap_chain_hash_fast_t l_block_prev_hash = {0};
    dap_chain_hash_fast_t l_block_anchor_hash = {0};
    uint64_t l_nonce = 0;
    uint64_t l_nonce2 = 0;

    dap_chain_block_meta_extract(l_meta, l_meta_count,
                                        &l_block_prev_hash,
                                        &l_block_anchor_hash,
                                        NULL,
                                        NULL,
                                        NULL,
                                        &l_is_genesis,
                                        &l_nonce,
                                        &l_nonce2 ) ;
    DAP_DELETE(l_meta);

    // 2nd level consensus
    if(l_blocks->callback_block_verify)
        if (l_blocks->callback_block_verify(l_blocks, l_block, a_atom_size))
            return ATOM_REJECT;

    // genesis or seed mode
    if (l_is_genesis) {
        if (!l_blocks_pvt->blocks) {
            dap_hash_fast(l_block, a_atom_size, &l_block_hash);
            if (s_seed_mode)
                log_it(L_NOTICE, "Accepting new genesis block");

            else if(dap_hash_fast_compare(&l_block_hash,&l_blocks_pvt->static_genesis_block_hash)
                    &&!dap_hash_fast_is_blank(&l_block_hash))
                log_it(L_NOTICE, "Accepting static genesis block");
            else{
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = { '\0' };
                dap_hash_fast_to_str(&l_block_hash, l_hash_str, sizeof(l_hash_str));
                log_it(L_WARNING,"Cant accept genesis block: seed mode not enabled or hash mismatch with static genesis block %s in configuration", l_hash_str);
                return ATOM_REJECT;
            }
        } else {
            log_it(L_WARNING,"Cant accept genesis block: already present data in blockchain");
            return ATOM_REJECT;
        }
    } else {
        dap_chain_block_cache_t *l_bcache_last = PVT(l_blocks)->blocks ? PVT(l_blocks)->blocks->hh.tbl->tail->prev : NULL;
        l_bcache_last = l_bcache_last ? l_bcache_last->hh.next : PVT(l_blocks)->blocks;
        if (!l_bcache_last || !dap_hash_fast_compare(&l_bcache_last->block_hash, &l_block_prev_hash))
            return ATOM_MOVE_TO_THRESHOLD;
    }
    return ATOM_ACCEPT;
}

/**
 * @brief s_callback_atom_get_static_hdr_size
 * @return
 */
static size_t s_callback_atom_get_static_hdr_size(void)
{
    return sizeof (dap_chain_block_hdr_t);
}

/**
 * @brief s_callback_atom_iter_create
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t *s_callback_atom_iter_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, bool a_with_treshold)
{
    dap_chain_atom_iter_t * l_atom_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_atom_iter) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_atom_iter->chain = a_chain;
    l_atom_iter->cell_id = a_cell_id;
    l_atom_iter->with_treshold = a_with_treshold;
#ifdef WIN32
    log_it(L_DEBUG, "! %p create caller id %lu", l_atom_iter, GetThreadId(GetCurrentThread()));
#endif
    return l_atom_iter;
}

/**
 * @brief s_callback_atom_iter_create_from
 * @param a_chain
 * @param a_atom
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_iter_t* s_callback_atom_iter_create_from(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size)
{
    if (a_atom && a_atom_size){
        dap_chain_hash_fast_t l_atom_hash;
        dap_hash_fast(a_atom, a_atom_size, &l_atom_hash);
        dap_chain_atom_iter_t * l_atom_iter = s_callback_atom_iter_create(a_chain, a_chain->cells->id, 0);
        if (l_atom_iter){
            dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
            l_atom_iter->cur_item = dap_chain_block_cs_cache_get_by_hash(l_blocks, &l_atom_hash);
            l_atom_iter->cur = a_atom;
            l_atom_iter->cur_size = a_atom_size;
            return l_atom_iter;
        }else
            return NULL;
    }else
        return NULL;
}

/**
 * @brief s_callback_atom_iter_find_by_hash
 * @param a_atom_iter
 * @param a_atom_hash
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter, dap_chain_hash_fast_t * a_atom_hash,
                                                              size_t * a_atom_size)
{
    assert(a_atom_iter);
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = PVT(DAP_CHAIN_CS_BLOCKS(a_atom_iter->chain));
    dap_chain_block_cache_t * l_block_cache = NULL;
    pthread_rwlock_rdlock(&l_blocks_pvt->rwlock);
    HASH_FIND(hh, l_blocks_pvt->blocks, a_atom_hash, sizeof(*a_atom_hash), l_block_cache);
    pthread_rwlock_unlock(&l_blocks_pvt->rwlock);
    a_atom_iter->cur_item = l_block_cache;
    if (l_block_cache) {
        a_atom_iter->cur = l_block_cache->block;
        a_atom_iter->cur_size = l_block_cache->block_size;
    } else {
        a_atom_iter->cur = NULL;
        a_atom_iter->cur_size = 0;
    }
    if (a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;
    return a_atom_iter->cur;
}

/**
 * @brief s_callback_atom_iter_find_by_tx_hash
 * @param a_chain
 * @param a_atom_hash
 * @return
 */
static dap_chain_datum_t *s_callback_datum_find_by_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                        dap_chain_hash_fast_t *a_block_hash, int *a_ret_code)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_block_datum_index_t *l_datum_index = NULL;
    pthread_rwlock_rdlock(&PVT(l_cs_blocks)->datums_rwlock);
    HASH_FIND(hh, PVT(l_cs_blocks)->datum_index, a_datum_hash, sizeof (*a_datum_hash), l_datum_index);
    pthread_rwlock_unlock(&PVT(l_cs_blocks)->datums_rwlock);
    if (!l_datum_index || !l_datum_index->block_cache)
        return NULL;
    if (a_block_hash)
        *a_block_hash = l_datum_index->block_cache->block_hash;
    if (a_ret_code)
        *a_ret_code = l_datum_index->ret_code;
    return l_datum_index->block_cache->datum[l_datum_index->datum_index];
}

/**
 * @brief s_callback_block_find_by_tx_hash
 * @param a_datums
 * @param a_tx_hash
 * @return atom_ptr
 */
static dap_chain_atom_ptr_t s_callback_block_find_by_tx_hash(dap_chain_t * a_chain, dap_chain_hash_fast_t * a_tx_hash, size_t *a_block_size)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_block_datum_index_t *l_datum_index = NULL;
    pthread_rwlock_rdlock(&PVT(l_cs_blocks)->datums_rwlock);
    HASH_FIND(hh, PVT(l_cs_blocks)->datum_index, a_tx_hash, sizeof (*a_tx_hash), l_datum_index);
    pthread_rwlock_unlock(&PVT(l_cs_blocks)->datums_rwlock);
    if (!l_datum_index)
        return NULL;
    if (a_block_size)
        *a_block_size = l_datum_index->block_cache->block_size;
    return l_datum_index->block_cache->block;
}

/**
 * @brief s_callback_atom_get_datum
 * @param a_event
 * @param a_atom_size
 * @return
 */
static dap_chain_datum_t** s_callback_atom_get_datums(dap_chain_atom_ptr_t a_atom, size_t a_atom_size, size_t * a_datums_count)
{
    assert(a_datums_count);
    dap_chain_datum_t ** l_ret = dap_chain_block_get_datums((dap_chain_block_t *)a_atom, a_atom_size,a_datums_count);
    return l_ret;
}

/**
 * @brief s_callback_atom_iter_get_first
 * @param a_atom_iter
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size )
{
    if(!a_atom_iter) {
        log_it(L_CRITICAL, "Invalid argument");
        return NULL;
    }
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_atom_iter->chain);
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = l_blocks ? PVT(l_blocks) : NULL;
    assert(l_blocks_pvt);
    //pthread_rwlock_rdlock(&l_blocks_pvt->rwlock);
    a_atom_iter->cur_item       = l_blocks_pvt->blocks;
    if (a_atom_iter->cur_item) {
        a_atom_iter->cur        = l_blocks_pvt->blocks->block;
        a_atom_iter->cur_size   = l_blocks_pvt->blocks->block_size;
        a_atom_iter->cur_hash   = &l_blocks_pvt->blocks->block_hash;
    } else {
        a_atom_iter->cur        = NULL;
        a_atom_iter->cur_size   = 0;
        a_atom_iter->cur_hash   = NULL;
    }
    //pthread_rwlock_unlock(&l_blocks_pvt->rwlock);
    if (a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;

    return a_atom_iter->cur;
}

/**
 * @brief s_callback_atom_iter_get_next
 * @param a_atom_iter
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_callback_atom_iter_get_next(dap_chain_atom_iter_t * a_atom_iter,size_t *a_atom_size )
{
    assert(a_atom_iter);
    assert(a_atom_iter->cur_item);

    dap_chain_block_cache_t *l_next_item = ((dap_chain_block_cache_t*)a_atom_iter->cur_item)->hh.next;
    a_atom_iter->cur_item = l_next_item;
    if (a_atom_iter->cur_item) {
        a_atom_iter->cur        = l_next_item->block;
        a_atom_iter->cur_size   = l_next_item->block_size;
        a_atom_iter->cur_hash   = &l_next_item->block_hash;
    } else {
        a_atom_iter->cur        = NULL;
        a_atom_iter->cur_size   = 0;
        a_atom_iter->cur_hash   = NULL;
    }
    if(a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;

    return a_atom_iter->cur;
}

/**
 * @brief s_callback_atom_iter_get_links
 * @param a_atom_iter
 * @param a_links_size
 * @param a_links_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_links(dap_chain_atom_iter_t *a_atom_iter , size_t *a_links_size, size_t **a_links_size_ptr)
{
    assert(a_atom_iter);
    assert(a_links_size);
    assert(a_links_size_ptr);
    if (!a_atom_iter->cur_item) {
        return NULL;
    }
    dap_chain_block_cache_t * l_block_cache =(dap_chain_block_cache_t *) a_atom_iter->cur_item;
    if (!l_block_cache->links_hash_count) {
        return NULL;
    }
    *a_links_size_ptr = DAP_NEW_Z_SIZE(size_t, l_block_cache->links_hash_count * sizeof(size_t));
    *a_links_size = l_block_cache->links_hash_count;
    dap_chain_atom_ptr_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_atom_ptr_t, l_block_cache->links_hash_count * sizeof(dap_chain_atom_ptr_t));
    for (size_t i = 0; i < l_block_cache->links_hash_count; ++i){
        dap_chain_cs_blocks_t *l_cs_blocks = (dap_chain_cs_blocks_t *)l_block_cache->_inheritor;
        dap_chain_block_cache_t *l_link = dap_chain_block_cs_cache_get_by_hash(l_cs_blocks, &l_block_cache->links_hash[i]);
        assert(l_link);
        (*a_links_size_ptr)[i] = l_link->block_size;
        l_ret[i] = l_link->block;
    }
    return l_ret;
}

/**
 * @brief s_callback_atom_iter_get_lasts
 * @param a_atom_iter
 * @param a_links_size
 * @param a_lasts_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_lasts( dap_chain_atom_iter_t *a_atom_iter, size_t *a_links_size, size_t **a_lasts_size_ptr)
{
    if(!a_atom_iter) {
        log_it(L_CRITICAL, "Invalid argument");
        return NULL;
    }
    dap_chain_block_cache_t *l_blocks = PVT(DAP_CHAIN_CS_BLOCKS(a_atom_iter->chain))->blocks;
    dap_chain_block_cache_t *l_block_cache_last = l_blocks ? l_blocks->hh.tbl->tail->prev : NULL;
    l_block_cache_last = l_block_cache_last ? l_block_cache_last->hh.next : l_blocks;

    if (l_block_cache_last) {
        a_atom_iter->cur = l_block_cache_last->block;
        a_atom_iter->cur_size = l_block_cache_last->block_size;
        a_atom_iter->cur_hash = &l_block_cache_last->block_hash;
        if (a_lasts_size_ptr) {
            *a_lasts_size_ptr = DAP_NEW_Z(size_t);
            if (!a_lasts_size_ptr) {
                log_it(L_CRITICAL, "Memory allocation error");
                return NULL;
            }
            (*a_lasts_size_ptr)[0] = l_block_cache_last->block_size;
        }
        if (a_links_size)
            *a_links_size = 1;
        dap_chain_atom_ptr_t *l_ret = DAP_NEW_Z(dap_chain_atom_ptr_t);
        if (!l_ret) {
            log_it(L_CRITICAL, "Memory allocation error");
            if (a_lasts_size_ptr)
                DAP_DEL_Z(*a_lasts_size_ptr);
            return NULL;
        }
        l_ret[0] = l_block_cache_last->block;
        return l_ret;
    } else {
        a_atom_iter->cur = NULL;
        a_atom_iter->cur_size = 0;
        a_atom_iter->cur_hash = NULL;
        if (a_links_size)
            *a_links_size = 0;
        if (a_lasts_size_ptr)
            *a_lasts_size_ptr = NULL;
        return NULL;
    }
}

/**
 * @brief s_callback_atom_iter_delete
 * @param a_atom_iter
 */
static void s_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter)
{
#ifdef WIN32
    log_it(L_DEBUG, "! %p delete caller id %lu", a_atom_iter, GetThreadId(GetCurrentThread()));
#endif
    DAP_DELETE(a_atom_iter);
}

static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain)
{
    dap_chain_datum_iter_t *l_ret = DAP_NEW_Z(dap_chain_datum_iter_t);
    if (!l_ret) {
        log_it(L_CRITICAL, "Memory allocation error");
        return NULL;
    }
    l_ret->chain = a_chain;
    return l_ret;
}

static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter)
{
    DAP_DELETE(a_datum_iter);
}

static void s_datum_iter_fill(dap_chain_datum_iter_t *a_datum_iter, dap_chain_block_datum_index_t *a_datum_index)
{
    a_datum_iter->cur_item = a_datum_index;
    if (a_datum_index && a_datum_index->block_cache->datum) {
        a_datum_iter->cur = a_datum_index->block_cache->datum[a_datum_index->datum_index];
        a_datum_iter->cur_size = dap_chain_datum_size(a_datum_iter->cur);
        a_datum_iter->cur_hash = &a_datum_index->datum_hash;
        a_datum_iter->cur_atom_hash = &a_datum_index->block_cache->block_hash;
        a_datum_iter->ret_code = a_datum_index->ret_code;
    } else {
        a_datum_iter->cur = NULL;
        a_datum_iter->cur_hash = NULL;
        a_datum_iter->cur_atom_hash = NULL;
        a_datum_iter->cur_size = 0;
        a_datum_iter->ret_code = 0;
    }
    debug_if(a_datum_index && !a_datum_index->block_cache->datum, L_ERROR, "Chains was deleted with errors");
}

static dap_chain_datum_t *s_chain_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_CHAIN_CS_BLOCKS(a_datum_iter->chain);
    pthread_rwlock_rdlock(&PVT(l_cs_blocks)->datums_rwlock);
    dap_chain_block_datum_index_t *l_datum_index = PVT(l_cs_blocks)->datum_index;
    s_datum_iter_fill(a_datum_iter, l_datum_index);
    pthread_rwlock_unlock(&PVT(l_cs_blocks)->datums_rwlock);
    return a_datum_iter->cur;
}

static dap_chain_datum_t *s_chain_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_CHAIN_CS_BLOCKS(a_datum_iter->chain);
    pthread_rwlock_rdlock(&PVT(l_cs_blocks)->datums_rwlock);
    dap_chain_block_datum_index_t *l_datum_index = a_datum_iter->cur_item;
    if (l_datum_index)
        l_datum_index = l_datum_index->hh.next;
    s_datum_iter_fill(a_datum_iter, l_datum_index);
    pthread_rwlock_unlock(&PVT(l_cs_blocks)->datums_rwlock);
    return a_datum_iter->cur;
}


static dap_chain_block_t *s_new_block_move(dap_chain_cs_blocks_t *a_blocks, size_t *a_new_block_size)
{
    size_t l_ret_size = 0;
    dap_chain_block_t *l_ret = NULL;
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = PVT(a_blocks);
    pthread_rwlock_wrlock(&l_blocks_pvt->rwlock);
    if ( a_blocks->block_new ) {
        l_ret = a_blocks->block_new;
        l_ret_size = a_blocks->block_new_size;
        a_blocks->block_new = NULL;
        a_blocks->block_new_size = 0;
    }
    pthread_rwlock_unlock(&l_blocks_pvt->rwlock);
    if (a_new_block_size)
        *a_new_block_size = l_ret_size;
    return l_ret;
}

/**
 * @brief s_callback_datums_pool_proc
 * @param a_chain
 * @param a_datums
 * @param a_datums_size
 * @return
 */
static size_t s_callback_add_datums(dap_chain_t *a_chain, dap_chain_datum_t **a_datums, size_t a_datums_count)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = PVT(l_blocks);

    size_t l_datum_processed = 0;
    pthread_rwlock_wrlock(&l_blocks_pvt->rwlock);
    for (size_t i = 0; i < a_datums_count; ++i) {
        dap_chain_datum_t *l_datum = a_datums[i];
        size_t l_datum_size = dap_chain_datum_size(l_datum);
        if (!l_datum_size) {
            log_it(L_WARNING, "Empty datum"); /* How might it be? */
            continue;
        }
        if (l_blocks->block_new_size + l_datum_size > DAP_CHAIN_CS_BLOCKS_MAX_BLOCK_SIZE) {
            log_it(L_DEBUG, "Maximum size exeeded, %zu > %d", l_blocks->block_new_size + l_datum_size, DAP_CHAIN_CS_BLOCKS_MAX_BLOCK_SIZE);
            break;
        }
        if (!l_blocks->block_new) {
            dap_chain_block_cache_t *l_bcache_last = l_blocks_pvt->blocks ? l_blocks_pvt->blocks->hh.tbl->tail->prev : NULL;
            l_bcache_last = l_bcache_last ? l_bcache_last->hh.next : l_blocks_pvt->blocks;
            l_blocks->block_new = dap_chain_block_new(&l_bcache_last->block_hash, &l_blocks->block_new_size);
            l_blocks->block_new->hdr.cell_id.uint64 = a_chain->cells->id.uint64;
            l_blocks->block_new->hdr.chain_id.uint64 = l_blocks->chain->id.uint64;
        }

        l_blocks->block_new_size = dap_chain_block_datum_add(&l_blocks->block_new, l_blocks->block_new_size, l_datum, l_datum_size);
        l_datum_processed++;
    }
    pthread_rwlock_unlock(&l_blocks_pvt->rwlock);
    return l_datum_processed;
}

/**
 * @brief s_callback_count_atom Gets the number of blocks
 * @param a_chain Chain object
 * @return size_t
 */
static size_t s_callback_count_atom(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    size_t l_ret = 0;
    pthread_rwlock_rdlock(&PVT(l_blocks)->rwlock);
    l_ret = PVT(l_blocks)->blocks_count;
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
    return l_ret;
}

/**
 * @brief s_callback_get_atoms Gets the specified number of blocks with an offset
 * @param a_chain Chain object
 * @param a_count Number of blocks
 * @param a_page The page from which you need to pick up the set number of blocks
 * @param a_reverse Boolean value to specify the first page comes from the beginning or end of the list
 * @return List of blocks
 */
static dap_list_t *s_callback_get_atoms(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = PVT(l_blocks);
    pthread_rwlock_rdlock(&PVT(l_blocks)->rwlock);
    if (!l_blocks_pvt->blocks) {
        pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
        return NULL;
    }
    size_t l_offset = a_count * (a_page - 1);
    size_t l_count = l_blocks_pvt->blocks_count;
    if (a_page < 2)
        l_offset = 0;
    if (l_offset > l_count){
        pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
        return NULL;
    }
    dap_list_t *l_list = NULL;
    size_t l_counter = 0;
    size_t l_end = l_offset + a_count;

    if (a_reverse) {
        dap_chain_block_cache_t *l_ptr = l_blocks_pvt->blocks->hh.tbl->tail->prev;
        if (!l_ptr)
            l_ptr = l_blocks_pvt->blocks;
        else
            l_ptr = l_ptr->hh.next;
        for (dap_chain_block_cache_t *ptr = l_ptr; ptr != NULL && l_counter < l_end; ptr = ptr->hh.prev) {
            if (l_counter >= l_offset) {
                dap_chain_block_t *l_block = ptr->block;
                l_list = dap_list_append(l_list, l_block);
                l_list = dap_list_append(l_list, &ptr->block_size);
            }
            l_counter++;
        }
    } else {
        dap_chain_block_cache_t *l_ptr = l_blocks_pvt->blocks;
        if (!l_ptr)
            l_ptr = l_blocks_pvt->blocks;
        else
            l_ptr = l_ptr->hh.next;
        for (dap_chain_block_cache_t *ptr = l_ptr; ptr != NULL && l_counter < l_end; ptr = ptr->hh.next) {
            if (l_counter >= l_offset) {
                dap_chain_block_t *l_block = ptr->block;
                l_list = dap_list_append(l_list, l_block);
                l_list = dap_list_append(l_list, &ptr->block_size);
            }
            l_counter++;
        }
    }
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
    return l_list;
}
