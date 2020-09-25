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
#include "dap_common.h"

#include "dap_enc_base58.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"
#define LOG_TAG "dap_chain_cs_blocks"

typedef struct dap_chain_cs_blocks_pvt
{
    dap_chain_cs_blocks_t * blocks;

    dap_chain_block_cache_t * block_cache_first; // Mapped area start
    dap_chain_block_cache_t * block_cache_last; // Last block in mapped area


    uint64_t blocks_count;
    uint64_t difficulty;

    dap_chain_block_t * block_new;
    size_t block_new_size;
} dap_chain_cs_blocks_pvt_t;

#define PVT(a) ((dap_chain_cs_blocks_pvt_t *) a->_pvt )

static int s_cli_parse_cmd_hash(char ** a_argv, int a_arg_index, int a_argc, char **a_str_reply,const char * a_param, dap_chain_hash_fast_t * a_datum_hash);
static void s_cli_meta_hash_print(  dap_string_t * a_str_tmp, const char * a_meta_title, dap_chain_block_meta_t * a_meta);
static int s_cli_blocks(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply);

// Callbacks
static void s_callback_delete(dap_chain_t * a_chain);
// Accept new block
static dap_chain_atom_verify_res_t s_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);
//    Verify new block
static dap_chain_atom_verify_res_t s_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t);

//    Get block header size
static size_t s_callback_atom_get_static_hdr_size(void);

static dap_chain_atom_iter_t* s_callback_atom_iter_create(dap_chain_t * a_chain );
static dap_chain_atom_iter_t* s_callback_atom_iter_create_from(dap_chain_t *  ,
                                                                     dap_chain_atom_ptr_t , size_t);


static dap_chain_atom_ptr_t s_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
static dap_chain_datum_tx_t* s_callback_atom_iter_find_by_tx_hash(dap_chain_t * a_chain ,
                                                                       dap_chain_hash_fast_t * a_atom_hash);

static dap_chain_datum_t* s_callback_atom_get_datum(dap_chain_atom_ptr_t a_event, size_t a_atom_size);
//    Get blocks
static dap_chain_atom_ptr_t s_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size ); //    Get the fisrt block
static dap_chain_atom_ptr_t s_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter,size_t *a_atom_size );  //    Get the next block
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter , size_t *a_links_size,
                                                                  size_t ** a_links_size_ptr );  //    Get list of linked blocks
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_lasts( dap_chain_atom_iter_t * a_atom_iter ,size_t *a_links_size,
                                                                  size_t ** a_lasts_size_ptr );  //    Get list of linked blocks

// Delete iterator
static void s_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt block

static size_t s_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_size);

bool s_seed_mode=false;


/**
 * @brief dap_chain_cs_blocks_init
 * @return
 */
int dap_chain_cs_blocks_init()
{
    dap_chain_cs_type_add("blocks", dap_chain_cs_blocks_new );
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    dap_chain_node_cli_cmd_item_create ("block", s_cli_blocks, NULL, "Create and explore blockchains",
        "New block create, fill and complete commands:"
            "\tblock -net <chain net name> -chain <chain name> new\n"
                "\t\tCreate new block and flush memory if was smth formed before\n\n"

            "\tblock -net <chain net name> -chain <chain name> new_datum_add <datum hash>\n"
                "\t\tAdd block section from datum <datum hash> taken from the mempool\n\n"

            "\tblock -net <chain net name> -chain <chain name> new_datum_del <datum hash>\n"
                "\t\tDel block section with datum <datum hash>\n\n"

            "\tblock -net <chain net name> -chain <chain name> new_datum_list\n"
                "\t\tList block sections and show their datums hashes\n\n"

            "\tblock -net <chain net name> -chain <chain name> new_datum\n\n"
                "\t\tComplete the current new round, verify it and if everything is ok - publish new events in chain\n\n"

        "Blockchain explorer:"
            "\tblock -net <chain net name> -chain <chain name> dump <block hash>\n"
                "\t\tDump block info\n\n"

            "\tblock -net <chain net name> -chain <chain name> list [-from_hash <block hash>] [-to_hash <block hash>]"
            "\t                                                           [-from_dt <datetime>] [-to_dt <datetime>]"
                "\t\t List blocks"

                                        );
    if (dap_chain_block_cache_init() != 0){
        log_it(L_WARNING, "Can't init blocks cache");
    }
    log_it(L_NOTICE,"Initialized blocks chain type");

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
    a_chain->_inheritor = l_cs_blocks;

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
    a_chain->callback_atom_get_datum = s_callback_atom_get_datum;

    a_chain->callback_atom_iter_get_links = s_callback_atom_iter_get_links; // Get the next element from chain from the current one
    a_chain->callback_atom_iter_get_lasts = s_callback_atom_iter_get_lasts;

    a_chain->callback_atom_find_by_hash = s_callback_atom_iter_find_by_hash;
    a_chain->callback_tx_find_by_hash = s_callback_atom_iter_find_by_tx_hash;


    a_chain->callback_datums_pool_proc = s_callback_datums_pool_proc;

    dap_chain_cs_blocks_pvt_t *l_cs_blocks_pvt = DAP_NEW_Z(dap_chain_cs_blocks_pvt_t);
    l_cs_blocks->_pvt = l_cs_blocks_pvt;

    dap_chain_node_role_t l_net_role= dap_chain_net_get_role( dap_chain_net_by_id(a_chain->net_id) );

    // Datum operations callbacks
/*
    a_chain->callback_datum_iter_create = s_chain_callback_datum_iter_create; // Datum iterator create
    a_chain->callback_datum_iter_delete = s_chain_callback_datum_iter_delete; // Datum iterator delete
    a_chain->callback_datum_iter_get_first = s_chain_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_next = s_chain_callback_datum_iter_get_next; // Get the next datum from chain from the current one
*/
    return 0;
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
    dap_chain_node_cli_find_option_val(a_argv, a_arg_index, a_argc, a_param, &l_datum_hash_str);

    return dap_enc_base58_hex_to_hash(l_datum_hash_str, a_datum_hash);
}

/**
 * @brief s_cli_meta_hash_print
 * @param a_str_tmp
 * @param a_meta_title
 * @param a_meta
 */
static void s_cli_meta_hash_print(  dap_string_t * a_str_tmp, const char * a_meta_title, dap_chain_block_meta_t * a_meta)
{
    if(a_meta->hdr.size == sizeof (dap_chain_hash_fast_t) ){
        char * l_hash_str = dap_chain_hash_fast_to_str_new( (dap_chain_hash_fast_t *) a_meta->data);
        dap_string_append_printf(a_str_tmp,"\t\tPREV: \"%s\"\n", a_meta_title,l_hash_str);
        DAP_DELETE(l_hash_str);
    }else{
        char * l_data_hex = DAP_NEW_Z_SIZE(char,a_meta->hdr.size*2+3);
        dap_bin2hex(l_data_hex, a_meta->data, a_meta->hdr.size);
        dap_string_append_printf(a_str_tmp,"\t\t\%s: 0x%s\n", a_meta_title, l_data_hex );
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
    char * l_data_hex = DAP_NEW_Z_SIZE(char,a_meta->hdr.size*2+3);
    dap_bin2hex(l_data_hex, a_meta->data, a_meta->hdr.size);
    dap_string_append_printf(a_str_tmp,"\t\t\%s: 0x%s\n", a_meta_title, l_data_hex );
}

/**
 * @brief s_cli_blocks
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
static int s_cli_blocks(int a_argc, char ** a_argv, void *a_arg_func, char **a_str_reply)
{
    (void) a_arg_func;
    enum {
        SUBCMD_UNDEFINED =0,
        SUBCMD_NEW_FLUSH,
        SUBCMD_NEW_DATUM_ADD,
        SUBCMD_NEW_DATUM_DEL,
        SUBCMD_NEW_DATUM_LIST,
        SUBCMD_NEW_COMPLETE,
        SUBCMD_DUMP,
        SUBCMD_LIST,
        SUBCMD_DROP
    } l_subcmd={0};

    const char* l_subcmd_strs[]={
        [SUBCMD_NEW_FLUSH]="new",
        [SUBCMD_NEW_DATUM_ADD]="new_datum_add",
        [SUBCMD_NEW_DATUM_DEL]="new_datum_del",
        [SUBCMD_NEW_DATUM_LIST]="new_datum_del",
        [SUBCMD_NEW_COMPLETE]="new_complete",
        [SUBCMD_DUMP]="dump",
        [SUBCMD_LIST]="list",
        [SUBCMD_DROP]="drop",
        [SUBCMD_UNDEFINED]=NULL
    };
    const size_t l_subcmd_str_count=sizeof(l_subcmd_strs)/sizeof(*l_subcmd_strs)-1;
    const char* l_subcmd_str_args[l_subcmd_str_count];
    const char* l_subcmd_str_arg;
    const char* l_subcmd_str;


    int arg_index = 1;

    const char * l_net_name = NULL;
    const char * l_chain_name = NULL;

    dap_chain_t * l_chain = NULL;
    dap_chain_cs_blocks_t * l_blocks = NULL;
    dap_chain_net_t * l_net = NULL;

    // Parse default values
    if(dap_chain_node_cli_cmd_values_parse_net_chain(&arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_net) < 0)
        return -11;

    l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);

    // Parse commands
    for (size_t i=0; i<l_subcmd_str_count; i++){
        int l_opt_idx = dap_chain_node_cli_check_option(a_argv, arg_index,a_argc, l_subcmd_strs[i]);
        if( l_opt_idx >= 0 ){
            dap_chain_node_cli_find_option_val(a_argv, l_opt_idx, a_argc, l_subcmd_strs[i], &l_subcmd_str_args[i] );
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
            if ( PVT(l_blocks)->block_new )
                DAP_DELETE( PVT(l_blocks)->block_new );
            PVT(l_blocks)->block_new = dap_chain_block_new( PVT(l_blocks)->block_cache_last? &PVT(l_blocks)->block_cache_last->block_hash: NULL );
            PVT(l_blocks)->block_new_size = sizeof (PVT(l_blocks)->block_new->hdr);
        } break;

        // Add datum to the forming new block
        case SUBCMD_NEW_DATUM_LIST:{

        }break;
        case SUBCMD_NEW_DATUM_DEL:{
            if ( PVT(l_blocks)->block_new ){
                dap_chain_hash_fast_t l_datum_hash;
                s_cli_parse_cmd_hash(a_argv,arg_index,a_argc,a_str_reply,"-datum", &l_datum_hash );
                dap_chain_block_datum_del_by_hash( PVT(l_blocks)->block_new, PVT(l_blocks)->block_new_size, &l_datum_hash );
            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                          "Error! Can't delete datum from hash because no forming new block! Check pls you role, it must be MASTER NODE or greater");
                ret = -12;
            }
        }break;
        case SUBCMD_NEW_DATUM_ADD:{
            size_t l_datums_count=1;
            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
            dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,
                                                           sizeof(dap_chain_datum_t*)*l_datums_count);
            size_t l_datum_size = 0;

            dap_chain_datum_t * l_datum = (dap_chain_datum_t*) dap_chain_global_db_gr_get( l_subcmd_str_arg ,
                                                                                              &l_datum_size,
                                                               l_gdb_group_mempool);
            l_datums[0] = l_datum;
            if ( s_callback_datums_pool_proc(l_chain,l_datums,l_datums_count ) == l_datums_count ){
                for ( size_t i = 0; i <l_datums_count; i++){
                   dap_chain_hash_fast_t l_datum_hash;
                   dap_hash_fast(l_datums[i],dap_chain_datum_size(l_datums[i]),&l_datum_hash);
                   char * l_datums_datum_hash_str = dap_chain_hash_fast_to_str_new(&l_datum_hash);
                   if ( dap_chain_global_db_gr_del( dap_strdup(l_datums_datum_hash_str),l_gdb_group_mempool ) ){
                       dap_chain_node_cli_set_reply_text(a_str_reply,
                                                         "Converted datum %s from mempool to event in the new forming round ",
                                                         l_datums_datum_hash_str);
                       DAP_DELETE(l_datums_datum_hash_str);
                       ret = 0;
                   }else {
                       dap_chain_node_cli_set_reply_text(a_str_reply,
                                                         "Warning! Can't delete datum %s from mempool after conversion to event in the new forming round ",
                                                         l_datums_datum_hash_str);
                       ret = 1;
                   }
                }
            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "Warning! Can't convert datum %s from mempool to the new forming block's section  ", l_subcmd_str_arg);
                ret = -13;
            }

            DAP_DELETE(l_gdb_group_mempool);
        }break;

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
            dap_enc_base58_hex_to_hash( l_subcmd_str_arg, &l_block_hash); // Convert argument to hash
            l_block = (dap_chain_block_t*) dap_chain_get_atom_by_hash( l_chain, &l_block_hash, &l_block_size);
            if ( l_block){
                dap_chain_block_cache_t *l_block_cache = dap_chain_block_cache_get(l_block, l_block_size);
                if ( l_block_cache ){
                    dap_string_t * l_str_tmp = dap_string_new(NULL);
                    char buf[50];
                    time_t l_ts_reated = (time_t) l_block->hdr.ts_created;
                     // Header
                    dap_string_append_printf(l_str_tmp,"Block %s:\n", l_subcmd_str_arg);
                    dap_string_append_printf(l_str_tmp,"\t\t\tversion: 0x%04sX\n",l_block->hdr.version);
                    dap_string_append_printf(l_str_tmp,"\t\t\tcell_id: 0x%016llX\n",l_block->hdr.cell_id.uint64);
                    dap_string_append_printf(l_str_tmp,"\t\t\tchain_id: 0x%016llX\n",l_block->hdr.chain_id.uint64);
                    dap_string_append_printf(l_str_tmp,"\t\t\tts_created: %s\n",ctime_r(&l_ts_reated, buf) );

                    // Prepare to parse data section
                    size_t l_offset = 0;

                    // Parse Metadata
                    dap_string_append_printf(l_str_tmp,"\tMetadata. Count: %us\n",l_block->hdr.meta_count );
                    for (uint16_t i=0; i < l_block->hdr.meta_count  &&  l_offset < l_block_size-sizeof (l_block->hdr); i++){
                        dap_chain_block_meta_t * l_meta =(dap_chain_block_meta_t *) (l_block->meta_n_datum_n_sign + l_offset);
                        switch (l_meta->hdr.type) {
                            case DAP_CHAIN_BLOCK_META_GENESIS:{
                                dap_string_append_printf(l_str_tmp,"\t\tGENESIS\n");
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
                                char * l_data_hex = DAP_NEW_Z_SIZE(char,l_meta->hdr.size*2+3);
                                dap_bin2hex(l_data_hex, l_meta->data, l_meta->hdr.size);
                                dap_string_append_printf(l_str_tmp,"\t\t\0x%0X: 0x%s\n", l_data_hex );
                            }
                        }
                        l_offset += l_meta->hdr.size + sizeof (l_meta->hdr);
                    }
                    for (uint16_t i=0; i < l_block->hdr.meta_count  &&  l_offset < l_block_size-sizeof (l_block->hdr); i++){
                        dap_chain_datum_t * l_datum = (dap_chain_datum_t*) (l_block->hashes_n_datum_n_signs + l_offset);
                        size_t l_datum_size =  dap_chain_datum_size(l_datum);
                        time_t l_datum_ts_create = (time_t) l_datum->header.ts_create;

                        // Nested datums
                        dap_string_append_printf(l_str_tmp,"\t\t\t\tdatum:\tdatum_size: %u\n",l_datum_size);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tversion:=0x%02X\n", l_datum->header.version_id);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype_id:=%s\n", c_datum_type_str[l_datum->header.type_id]);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tts_create=%s\n",ctime_r( &l_datum_ts_create,buf ));
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tdata_size=%u\n", l_datum->header.data_size);
                    }
                    // Signatures
                    dap_string_append_printf(l_str_tmp,"\t\t\t\tsigns:\tcount: %us\n",l_block->hdr.sign_count);
                    l_offset += l_datum_size;
                    while (l_offset + sizeof (l_block->header) < l_event_size ){
                        dap_sign_t * l_sign =(dap_sign_t *) (l_block->hashes_n_datum_n_signs +l_offset);
                        size_t l_sign_size = dap_sign_get_size(l_sign);
                        if (l_sign_size == 0 ){
                            dap_string_append_printf(l_str_tmp,"\t\t\t\tERROR: wrong sign size 0, stop parsing headers\n");
                            break;
                        }
                        dap_chain_addr_t l_addr = {0};
                        dap_chain_hash_fast_t l_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
                        dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, l_net->pub.id);
                        char * l_addr_str = dap_chain_addr_to_str(&l_addr);
                        dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype: %s\taddr: %s"
                                                           "n", dap_sign_type_to_str( l_sign->header.type ),
                                                 l_addr_str );
                        l_offset += l_sign_size;
                        DAP_DELETE( l_addr_str);
                    }
                    dap_chain_net_dump_datum(l_str_tmp, l_datum, l_hash_out_type);

                    dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
                    dap_string_free(l_str_tmp,false);
                    ret=0;
                }
            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Can't find blocl 0x%s in the new forming round ",
                                                  l_event_hash_str);
                ret=-10;
            }
        }break;
        case SUBCMD_LIST:{
            if( (l_from_events_str == NULL) ||
                    (strcmp(l_from_events_str,"round.new") == 0) ){
                char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
                dap_string_t * l_str_tmp = dap_string_new("");
                if ( l_gdb_group_events ){
                    dap_global_db_obj_t * l_objs;
                    size_t l_objs_count = 0;
                    l_objs = dap_chain_global_db_gr_load(l_gdb_group_events,&l_objs_count);
                    dap_string_append_printf(l_str_tmp,"%s.%s: Found %u records :\n",l_net->pub.name,l_chain->name,l_objs_count);

                    for (size_t i = 0; i< l_objs_count; i++){
                        dap_chain_cs_dag_event_t * l_event = (dap_chain_cs_dag_event_t *) l_objs[i].value;
                        char buf[50];
                        time_t l_ts_create = (time_t) l_event->header.ts_created;
                        dap_string_append_printf(l_str_tmp,"\t%s: ts_create=%s",
                                                 l_objs[i].key, ctime_r( &l_ts_create,buf ) );

                    }
                    // bugs-3932
                    //DAP_DELETE( l_gdb_group_events);
                    if (l_objs && l_objs_count )
                        dap_chain_global_db_objs_delete(l_objs, l_objs_count);
                    ret = 0;
                } else {
                    dap_string_append_printf(l_str_tmp,"%s.%s: Error! No GlobalDB group!\n",l_net->pub.name,l_chain->name);
                    ret = -2;

                }
                dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
                dap_string_free(l_str_tmp,false);
            }else if (l_from_events_str && (strcmp(l_from_events_str,"events") == 0) ){
                dap_string_t * l_str_tmp = dap_string_new(NULL);
                size_t l_events_count = HASH_COUNT(PVT(l_dag)->events);
                dap_string_append_printf(l_str_tmp,"%s.%s: Have %u events :\n",
                                         l_net->pub.name,l_chain->name,l_events_count);
                dap_chain_cs_dag_event_item_t * l_event_item = NULL,*l_event_item_tmp = NULL;

                pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                HASH_ITER(hh,PVT(l_dag)->events,l_event_item, l_event_item_tmp ) {
                    char buf[50];
                    char * l_event_item_hash_str = dap_chain_hash_fast_to_str_new( &l_event_item->hash);
                    time_t l_ts_create = (time_t) l_event_item->event->header.ts_created;
                    dap_string_append_printf(l_str_tmp,"\t%s: ts_create=%s",
                                             l_event_item_hash_str, ctime_r( &l_ts_create,buf ) );
                    DAP_DELETE(l_event_item_hash_str);
                }
                pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);

                dap_chain_node_cli_set_reply_text(a_str_reply, l_str_tmp->str);
                dap_string_free(l_str_tmp,false);

            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply, "Undefined events source for listing ");
                ret=-14;

            }
        }break;

        case SUBCMD_UNDEFINED: {
            dap_chain_node_cli_set_reply_text(a_str_reply,
                                              "Undefined block subcommand \"%s\" ",
                                              l_subcmd_str);
            ret=-11;
        }
    }
    return ret;
}


/**
 * @brief s_callback_delete
 * @details Destructor for blocks consensus chain
 * @param a_chain
 */
static void s_callback_delete(dap_chain_t * a_chain)
{
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS ( a_chain );
    if(l_blocks->callback_delete )
        l_blocks->callback_delete(l_blocks);
    if(l_blocks->_inheritor)
        DAP_DELETE(l_blocks->_inheritor);
    if(l_blocks->_pvt)
        DAP_DELETE(l_blocks->_pvt);
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

}

/**
 * @brief s_callback_atom_get_static_hdr_size
 * @return
 */
static size_t s_callback_atom_get_static_hdr_size(void)
{

}

/**
 * @brief s_callback_atom_iter_create
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t* s_callback_atom_iter_create(dap_chain_t * a_chain )
{

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

}

/**
 * @brief s_callback_atom_iter_find_by_tx_hash
 * @param a_chain
 * @param a_atom_hash
 * @return
 */
static dap_chain_datum_tx_t* s_callback_atom_iter_find_by_tx_hash(dap_chain_t * a_chain, dap_chain_hash_fast_t * a_atom_hash)
{

}

/**
 * @brief s_callback_atom_get_datum
 * @param a_event
 * @param a_atom_size
 * @return
 */
static dap_chain_datum_t* s_callback_atom_get_datum(dap_chain_atom_ptr_t a_event, size_t a_atom_size)
{

}

/**
 * @brief s_callback_atom_iter_get_first
 * @param a_atom_iter
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_callback_atom_iter_get_first( dap_chain_atom_iter_t * a_atom_iter, size_t *a_atom_size )
{

}

/**
 * @brief s_callback_atom_iter_get_next
 * @param a_atom_iter
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_callback_atom_iter_get_next( dap_chain_atom_iter_t * a_atom_iter,size_t *a_atom_size )
{

}

/**
 * @brief s_callback_atom_iter_get_links
 * @param a_atom_iter
 * @param a_links_size
 * @param a_links_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter , size_t *a_links_size, size_t ** a_links_size_ptr )
{

}

/**
 * @brief s_callback_atom_iter_get_lasts
 * @param a_atom_iter
 * @param a_links_size
 * @param a_lasts_size_ptr
 * @return
 */
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_lasts( dap_chain_atom_iter_t * a_atom_iter ,size_t *a_links_size, size_t ** a_lasts_size_ptr )
{

}

/**
 * @brief s_callback_atom_iter_delete
 * @param a_atom_iter
 */
static void s_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter )
{

}

/**
 * @brief s_callback_datums_pool_proc
 * @param a_chain
 * @param a_datums
 * @param a_datums_size
 * @return
 */
static size_t s_callback_datums_pool_proc(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_size)
{

}
