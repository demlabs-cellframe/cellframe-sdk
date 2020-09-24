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

#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"
#include "dap_chain_node_cli.h"
#define LOG_TAG "dap_chain_cs_blocks"

typedef struct dap_chain_cs_blocks_pvt
{
    dap_chain_cs_blocks_t * blocks;

    dap_chain_block_cache_t * block_cache_first; // Mapped area start
    dap_chain_block_cache_t * block_cache_last; // Last block in mapped area
    uint64_t blocks_count;
    uint64_t difficulty;

} dap_chain_cs_blocks_pvt_t;

#define PVT(a) ((dap_chain_cs_blocks_pvt_t *) a->_pvt )

static int s_cli_blocks(int argc, char ** argv, void *arg_func, char **a_str_reply);

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
 * @brief s_cli_blocks
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
static int s_cli_blocks(int argc, char ** argv, void *arg_func, char **a_str_reply)
{
    (void) arg_func;
    enum {
        SUBCMD_NEW,
        SUBCMD_NEW_DATUM_ADD,
        SUBCMD_NEW_DATUM_DEL,
        SUBCMD_NEW_DATUM_LIST,
        SUBCMD_NEW_COMPLETE,
        SUBCMD_DUMP,
        SUBCMD_LIST,
        SUBCMD_UNDEFINED
    } l_subcmd={0};

    const char* l_subcmd_str[]={
        [SUBCMD_NEW]="new",
        [SUBCMD_NEW_DATUM_ADD]="new_datum_add",
        [SUBCMD_NEW_DATUM_DEL]="new_datum_del",
        [SUBCMD_NEW_DATUM_LIST]="new_datum_del",
        [SUBCMD_NEW_COMPLETE]="new_complete",
        [SUBCMD_DUMP]="dump",
        [SUBCMD_LIST]="list",
        [SUBCMD_UNDEFINED]=NULL
    };
    const size_t l_subcmd_str_count=sizeof(l_subcmd_str)/sizeof(*l_subcmd_str)-1;
    const char* l_subcmd_str_args[l_subcmd_str_count];


    int arg_index = 1;

    const char * l_net_name = NULL;
    const char * l_chain_name = NULL;


    dap_chain_t * l_chain = NULL;
    dap_chain_cs_blocks_t * l_blocks = NULL;
    dap_chain_net_t * l_net = NULL;

    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-net", &l_net_name);
    dap_chain_node_cli_find_option_val(argv, arg_index, argc, "-chain", &l_chain_name);

    for (size_t i=0; i<l_subcmd_str_count; i++){
        int l_opt_idx = dap_chain_node_cli_check_option(argv, arg_index,argc, l_subcmd_str[i]);
        if( l_opt_idx >= 0 ){
            dap_chain_node_cli_find_option_val(argv, l_opt_idx, argc, l_subcmd_str[i], &l_subcmd_str_args[i] );
            l_subcmd = i;
        }
    }

    if ( l_net_name == NULL){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Need -net <net name> param!");
        return -1;
    }
    l_net = dap_chain_net_by_name( l_net_name );
    if ( l_net == NULL ){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't find network \"%s\"",l_net_name);
        return -2;

    }

    if ( l_chain_name == NULL){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Need -chain <chain name> param!");
        return -3;
    }
    l_chain = dap_chain_net_get_chain_by_name(l_net,l_chain_name);
    if ( l_chain == NULL ){
        dap_chain_node_cli_set_reply_text(a_str_reply, "Can't find chain \"%s\" in network \"%s\"",
                                          l_chain_name, l_net_name);
        return -4;
    }
    l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);

    switch ( l_subcmd ){
        case SUBCMD_NEW:{
        } break;
        case SUBCMD_NEW_DATUM_LIST:{

        }break;
        case SUBCMD_NEW_DATUM_DEL:{

        }break;
        case SUBCMD_NEW_DATUM_ADD:{
            size_t l_datums_count=1;
            char * l_gdb_group_mempool = dap_chain_net_get_gdb_group_mempool(l_chain);
            dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,
                                                           sizeof(dap_chain_datum_t*)*l_datums_count);
            size_t l_datum_size = 0;
            dap_chain_datum_t * l_datum = (dap_chain_datum_t*) dap_chain_global_db_gr_get( l_datum_hash_hex_str ,
                                                                                              &l_datum_size,
                                                               l_gdb_group_mempool);
            l_datums[0] = l_datum;
            if ( s_chain_callback_datums_pool_proc(l_chain,l_datums,l_datums_count ) == l_datums_count ){
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
                if(!dap_strcmp(l_hash_out_type,"hex")){
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Warning! Can't convert datum %s from mempool to event in the new forming round ", l_datum_hash_hex_str);
                }
            else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                        "Warning! Can't convert datum %s from mempool to event in the new forming round ", l_datum_hash_base58_str);
            }
                ret = -12;

            }
            DAP_DELETE(l_gdb_group_mempool);
            DAP_DELETE(l_datum_hash_hex_str);
            DAP_DELETE(l_datum_hash_base58_str);
            dap_chain_net_sync_all(l_net);
        }break;
        case SUBCMD_EVENT_CANCEL:{
            char * l_gdb_group_events = DAP_CHAIN_CS_DAG(l_chain)->gdb_group_events_round_new;
            if ( dap_chain_global_db_gr_del( dap_strdup(l_event_hash_hex_str) ,l_gdb_group_events ) ){
                if(!dap_strcmp(l_hash_out_type, "hex")){
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Successfuly removed event %s from the new forming round ",
                            l_event_hash_hex_str);
                }
                else{
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                            "Successfuly removed event %s from the new forming round ",
                            l_event_hash_base58_str);
                }
                ret = 0;
            }else {
                dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                HASH_FIND(hh,PVT(l_dag)->events,&l_event_hash,sizeof(l_event_hash),l_event_item);

                if ( l_event_item ){
                    HASH_DELETE(hh, PVT(l_dag)->events, l_event_item);
                    if(!dap_strcmp(l_hash_out_type, "hex")) {
                        log_it(L_WARNING, "Dropped event %s from chains! Hope you know what are you doing!",
                                l_event_hash_hex_str);
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "Dropped event 0x%s from chains! Hope you know what are you doing! ",
                                l_event_hash_hex_str);
                    }
                    else {
                        log_it(L_WARNING, "Dropped event %s from chains! Hope you know what are you doing!",
                                l_event_hash_base58_str);
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "Dropped event 0x%s from chains! Hope you know what are you doing! ",
                                l_event_hash_base58_str);
                    }
                    dap_chain_save_all(l_chain);
                }else {
                    if(!dap_strcmp(l_hash_out_type, "hex")) {
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "Can't remove event 0x%s ",
                                l_event_hash_hex_str);
                    }
                    else {
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                "Can't remove event 0x%s ",
                                l_event_hash_base58_str);
                    }
                    ret = -1;
                }
            }
            DAP_DELETE(l_event_hash_hex_str);
            DAP_DELETE(l_event_hash_base58_str);
            DAP_DELETE( l_gdb_group_events );
            dap_chain_net_sync_gdb(l_net);
        }break;
        case SUBCMD_EVENT_DUMP:{
            dap_chain_cs_dag_event_t * l_event = NULL;
            size_t l_event_size = 0;
            if ( l_from_events_str ){
                if ( strcmp(l_from_events_str,"round.new") == 0 ){
                    const char * l_gdb_group_events = l_dag->gdb_group_events_round_new;
                    l_event = (dap_chain_cs_dag_event_t *)  dap_chain_global_db_gr_get
                                          ( l_event_hash_str ,&l_event_size,l_gdb_group_events );
                }else if ( strncmp(l_from_events_str,"round.",6) == 0){

                }else if ( strcmp(l_from_events_str,"events_lasts") == 0){
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                    pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                    HASH_FIND(hh,PVT(l_dag)->events_lasts_unlinked,&l_event_hash,sizeof(l_event_hash),l_event_item);
                    pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                    if ( l_event_item )
                        l_event = l_event_item->event;
                    else {
                        ret = -23;
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                                          "Can't find events in events_last table\n");
                        break;
                    }
                }else if ( strcmp(l_from_events_str,"events") == 0){
                    dap_chain_cs_dag_event_item_t * l_event_item = NULL;
                    pthread_rwlock_rdlock(&PVT(l_dag)->events_rwlock);
                    HASH_FIND(hh,PVT(l_dag)->events,&l_event_hash,sizeof(l_event_hash),l_event_item);
                    pthread_rwlock_unlock(&PVT(l_dag)->events_rwlock);
                    if ( l_event_item )
                        l_event = l_event_item->event;
                    else {
                        ret = -24;
                        dap_chain_node_cli_set_reply_text(a_str_reply,
                                                          "Can't find events in events table\n");
                        break;
                    }

                }else {
                    ret = -22;
                    dap_chain_node_cli_set_reply_text(a_str_reply,
                                                      "Wrong events_from option \"%s\", need one of variant: events, round.new, events_lasts, round.0x0123456789ABCDEF", l_from_events_str);
                    break;

                }
            } else {
                ret = -21;
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "No events_from option");
                break;
            }
            if ( l_event ){
                dap_string_t * l_str_tmp = dap_string_new(NULL);
                char buf[50];
                time_t l_ts_reated = (time_t) l_event->header.ts_created;
                 // Header
                dap_string_append_printf(l_str_tmp,"Event %s:\n", l_event_hash_str);
                dap_string_append_printf(l_str_tmp,"\t\t\t\tversion: 0x%04sX\n",l_event->header.version);
                dap_string_append_printf(l_str_tmp,"\t\t\t\tcell_id: 0x%016llX\n",l_event->header.cell_id.uint64);
                dap_string_append_printf(l_str_tmp,"\t\t\t\tchain_id: 0x%016llX\n",l_event->header.chain_id.uint64);
                dap_string_append_printf(l_str_tmp,"\t\t\t\tts_created: %s\n",ctime_r(&l_ts_reated, buf) );

                // Hash links
                dap_string_append_printf(l_str_tmp,"\t\t\t\thashes:\tcount: %us\n",l_event->header.hash_count);
                for (uint16_t i=0; i < l_event->header.hash_count; i++){
                    dap_chain_hash_fast_t * l_hash = (dap_chain_hash_fast_t *) (l_event->hashes_n_datum_n_signs +
                            i*sizeof (dap_chain_hash_fast_t));
                    char * l_hash_str = dap_chain_hash_fast_to_str_new(l_hash);
                    dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\thash: %s\n",l_hash_str);
                    DAP_DELETE(l_hash_str);
                }
                size_t l_offset =  l_event->header.hash_count*sizeof (dap_chain_hash_fast_t);
                dap_chain_datum_t * l_datum = (dap_chain_datum_t*) (l_event->hashes_n_datum_n_signs + l_offset);
                size_t l_datum_size =  dap_chain_datum_size(l_datum);
                time_t l_datum_ts_create = (time_t) l_datum->header.ts_create;

                // Nested datum
                dap_string_append_printf(l_str_tmp,"\t\t\t\tdatum:\tdatum_size: %u\n",l_datum_size);
                dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tversion:=0x%02X\n", l_datum->header.version_id);
                dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\ttype_id:=%s\n", c_datum_type_str[l_datum->header.type_id]);
                dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tts_create=%s\n",ctime_r( &l_datum_ts_create,buf ));
                dap_string_append_printf(l_str_tmp,"\t\t\t\t\t\tdata_size=%u\n", l_datum->header.data_size);

                // Signatures
                dap_string_append_printf(l_str_tmp,"\t\t\t\tsigns:\tcount: %us\n",l_event->header.signs_count);
                l_offset += l_datum_size;
                while (l_offset + sizeof (l_event->header) < l_event_size ){
                    dap_sign_t * l_sign =(dap_sign_t *) (l_event->hashes_n_datum_n_signs +l_offset);
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
            }else {
                dap_chain_node_cli_set_reply_text(a_str_reply,
                                                  "Can't find event 0x%s in the new forming round ",
                                                  l_event_hash_str);
                ret=-10;
            }
        }break;
        case SUBCMD_EVENT_LIST:{
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
                                              "Undefined event subcommand \"%s\" ",
                                              l_event_cmd_str);
            ret=-11;
        }
    }
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
