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
#include "dap_chain.h"
#include "dap_chain_srv.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_block.h"
#include "dap_chain_block_cache.h"
#include "dap_cli_server.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_decree.h"
#include "dap_chain_net.h"
#include "dap_chain_mempool.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_datum.h"
#include "dap_enc_base58.h"
#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "dap_chain_cs_blocks"

#ifndef DAP_CHAIN_BLOCKS_TEST
#define DAP_FORK_MAX_DEPTH_DEFAULT 10
#else
#define DAP_FORK_MAX_DEPTH_DEFAULT 5
#endif


typedef struct dap_chain_block_datum_index {
    dap_chain_hash_fast_t datum_hash;
    int ret_code;
    time_t ts_added;
    dap_chain_block_cache_t *block_cache;
    size_t datum_index;
    char token_ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_srv_uid_t service_uid;
    dap_chain_tx_tag_action_type_t action;
    UT_hash_handle hh;
} dap_chain_block_datum_index_t;

struct cs_blocks_hal_item {
    dap_chain_hash_fast_t hash;
    UT_hash_handle hh;
};

typedef struct dap_chain_cs_blocks_pvt {
    // Parent link
    dap_chain_cs_blocks_t *cs_blocks;

    // All the blocks are here
    dap_chain_block_cache_t *blocks;
    dap_chain_block_cache_t *blocks_num;
    _Atomic uint64_t blocks_count;

    // Brnches and forks
    size_t forked_br_cnt;
    dap_chain_block_forked_branch_t **forked_branches; // list of lists with atoms in side branches
    pthread_rwlock_t forked_branches_rwlock;

    // Datum search in blocks
    dap_chain_block_datum_index_t *datum_index;
    pthread_rwlock_t datums_rwlock;
     _Atomic uint64_t tx_count;

    dap_chain_hash_fast_t genesis_block_hash;
    dap_chain_hash_fast_t static_genesis_block_hash;

    bool is_celled;

    pthread_rwlock_t rwlock;
    struct cs_blocks_hal_item *hal;
    // Number of blocks for one block confirmation
    uint64_t block_confirm_cnt;
} dap_chain_cs_blocks_pvt_t;

typedef struct dap_chain_block_fork_resolved_notificator{
    dap_chain_cs_blocks_callback_fork_resolved_t callback;
    void *arg;
} dap_chain_block_fork_resolved_notificator_t;

#define PVT(a) ((dap_chain_cs_blocks_pvt_t *)(a)->_pvt )

#define print_rdlock(blocks) log_it(L_DEBUG, "Try to rdlock, %s, %d, thread_id=%u", __FUNCTION__, __LINE__, dap_gettid());\
        pthread_rwlock_rdlock(& PVT(blocks)->rwlock);\
        log_it(L_DEBUG, "Locked rdlock, %s, %d, thread_id=%u", __FUNCTION__, __LINE__, dap_gettid());

#define print_wrlock(blocks) log_it(L_DEBUG, "Try to wrlock, %s, %d, thread_id=%u", __FUNCTION__, __LINE__, dap_gettid());\
        pthread_rwlock_wrlock(& PVT(blocks)->rwlock);\
        log_it(L_DEBUG, "Locked wrlock, %s, %d, thread_id=%u", __FUNCTION__, __LINE__, dap_gettid());

#define print_unlock(blocks) log_it(L_DEBUG, "Try to unlock, %s, %d, thread_id=%u", __FUNCTION__, __LINE__, dap_gettid());\
        pthread_rwlock_unlock(& PVT(blocks)->rwlock);\
        log_it(L_DEBUG, "Unlocked rwqlock, %s, %d, thread_id=%u", __FUNCTION__, __LINE__, dap_gettid());

static int s_cli_parse_cmd_hash(char ** a_argv, int a_arg_index, int a_argc, void **a_str_reply,const char * a_param, dap_chain_hash_fast_t * a_datum_hash);
static void s_cli_meta_hash_print(  json_object* a_json_obj_out, const char * a_meta_title, dap_chain_block_meta_t * a_meta, const char *a_hash_out_type);
static int s_cli_blocks(int a_argc, char ** a_argv, void **a_str_reply);

// Setup BFT consensus and select the longest chunk
static void s_bft_consensus_setup(dap_chain_cs_blocks_t * a_blocks);

static bool s_chain_find_atom(dap_chain_block_cache_t* a_blocks, dap_chain_hash_fast_t* a_atom_hash);

// Callbacks
static int s_callback_delete(dap_chain_t * a_chain);
// Accept new block
static dap_chain_atom_verify_res_t s_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t, dap_hash_fast_t * a_atom_hash, bool a_atom_new);
//    Verify new block
static dap_chain_atom_verify_res_t s_callback_atom_verify(dap_chain_t * a_chain, dap_chain_atom_ptr_t , size_t, dap_hash_fast_t * a_atom_hash);

//    Get block header size
static size_t s_callback_atom_get_static_hdr_size(void);

static dap_chain_atom_iter_t *s_callback_atom_iter_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from);
static dap_chain_atom_ptr_t s_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter ,
                                                                       dap_chain_hash_fast_t * a_atom_hash, size_t * a_atom_size);
static json_object *s_callback_atom_dump_json(json_object **a_arr_out, dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom_ptr, size_t a_atom_size, const char *a_hash_out_type);
static dap_chain_atom_ptr_t s_callback_atom_iter_get_by_num(dap_chain_atom_iter_t *a_atom_iter, uint64_t a_atom_num);
static dap_chain_datum_t *s_callback_datum_find_by_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash,
                                                        dap_chain_hash_fast_t *a_block_hash, int *a_ret_code);

static dap_chain_atom_ptr_t s_callback_block_find_by_tx_hash(dap_chain_t * a_chain, dap_chain_hash_fast_t * a_tx_hash, size_t *a_block_size);

static dap_chain_datum_t** s_callback_atom_get_datums(dap_chain_atom_ptr_t a_atom, size_t a_atom_size, size_t * a_datums_count);
static dap_time_t s_chain_callback_atom_get_timestamp(dap_chain_atom_ptr_t a_atom) { return ((dap_chain_block_t *)a_atom)->hdr.ts_created; }
static uint256_t s_callback_calc_reward(dap_chain_t *a_chain, dap_hash_fast_t *a_block_hash, dap_pkey_t *a_block_sign_pkey);
static int s_fee_verificator_callback(dap_ledger_t * a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond, bool a_owner);
static int s_fee_stack_verificator_callback(dap_ledger_t * a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t *a_tx_in_hash, dap_chain_tx_out_cond_t *a_cond, bool a_owner);
//    Get blocks
static dap_chain_atom_ptr_t s_callback_atom_iter_get(dap_chain_atom_iter_t *a_atom_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size);
static dap_chain_atom_ptr_t *s_callback_atom_iter_get_links( dap_chain_atom_iter_t * a_atom_iter , size_t *a_links_size,
                                                                  size_t ** a_links_size_ptr );  //    Get list of linked blocks
//Get list of hashes
static dap_list_t *s_block_parse_str_list(char *a_hash_str, size_t * a_hash_size, dap_chain_t * a_chain);

// Delete iterator
static void s_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter );                  //    Get the fisrt block

// Datum ops
static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain);
static void s_chain_callback_datum_iter_delete(dap_chain_datum_iter_t *a_datum_iter);
static dap_chain_datum_t *s_chain_callback_datum_iter_get_first(dap_chain_datum_iter_t *a_datum_iter); // Get the fisrt datum from blocks
static dap_chain_datum_t *s_chain_callback_datum_iter_get_last(dap_chain_datum_iter_t *a_datum_iter); // Get the last datum from blocks
static dap_chain_datum_t *s_chain_callback_datum_iter_get_next(dap_chain_datum_iter_t *a_datum_iter); // Get the next datum from blocks
static dap_chain_datum_t *s_chain_callback_datum_iter_get_prev(dap_chain_datum_iter_t *a_datum_iter); // Get the prev datum from blocks

static size_t s_callback_add_datums(dap_chain_t * a_chain, dap_chain_datum_t ** a_datums, size_t a_datums_count);

static int s_callback_cs_blocks_purge(dap_chain_t *a_chain);

static dap_chain_block_t *s_new_block_move(dap_chain_cs_blocks_t *a_blocks, size_t *a_new_block_size);

//Work with atoms
static uint64_t s_callback_count_atom(dap_chain_t *a_chain);
static dap_list_t *s_callback_get_atoms(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);
// Get TXs callbacks
static uint64_t s_callback_count_txs(dap_chain_t *a_chain);
static dap_list_t *s_callback_get_txs(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse);
static int s_chain_cs_blocks_new(dap_chain_t * a_chain, dap_config_t * a_chain_config);

static bool s_seed_mode = false;
static bool s_debug_more = false;

static dap_list_t *s_fork_resolved_notificators = NULL;

/**
 * @brief dap_chain_cs_blocks_init
 * @return
 */
int dap_chain_cs_blocks_init()
{
    dap_chain_cs_class_callbacks_t l_callbacks = { .callback_init = s_chain_cs_blocks_new,
                                                   .callback_delete = s_callback_delete,
                                                   .callback_purge = s_callback_cs_blocks_purge };
    dap_chain_cs_class_add("blocks", l_callbacks);

    dap_chain_block_init();
    s_seed_mode = dap_config_get_item_bool_default(g_config,"general","seed_mode",false);
    s_debug_more = dap_config_get_item_bool_default(g_config, "blocks", "debug_more", false);
    dap_cli_server_cmd_add ("block", s_cli_blocks, "Create and explore blockchains", dap_chain_node_cli_cmd_id_from_str("block"),
        "New block create, fill and complete commands:\n"
            "block -net <net_name> [-chain <chain_name>] new\n"
                "\t\tCreate new block and flush memory if was smth formed before\n\n"

            "block -net <net_name> [-chain <chain_name>] new_datum_add <datum_hash>\n"
                "\t\tAdd block section from datum <datum hash> taken from the mempool\n\n"

            "block -net <net_name> [-chain <chain_name>] new_datum_del <datum_hash>\n"
                "\t\tDel block section with datum <datum hash>\n\n"

            "block -net <net_name> [-chain <chain_name>] new_datum_list\n"
                "\t\tList block sections and show their datums hashes\n\n"

            "block -net <net_name> [-chain <chain_name>] new_datum\n\n"
                "\t\tComplete the current new round, verify it and if everything is ok - publish new blocks in chain\n\n"

        "Blockchain explorer:\n"
            "block -net <net_name> [-chain <chain_name>] [-brief] dump {-hash <block_hash> | -num <block_number>}\n"
                "\t\tDump block info\n\n"

            "block -net <net_name> [-chain <chain_name>] list [{signed | first_signed}] [-limit] [-offset] [-head]"
            " [-from_hash <block_hash>] [-to_hash <block_hash>] [-from_date <YYMMDD>] [-to_date <YYMMDD>]"
            " [{-cert <signing_cert_name> | -pkey_hash <signing_cert_pkey_hash>}] [-unspent]\n"
                "\t\t List blocks\n\n"

            "block -net <net_name> [-chain <chain_name>] count\n"
                "\t\t Show count block\n\n"

            "block -net <net_name> -chain <chain_name> last\n\n"
                "\t\tShow last block in chain\n\n"

            "block -net <net_name> -chain <chain_name> find -datum <datum_hash>\n\n"
                "\t\tSearches and shows blocks that contains specify datum\n\n"

        "Commission collect:\n"
            "block -net <net_name> [-chain <chain_name>] fee collect"
            " -cert <priv_cert_name> -addr <addr> -hashes <hashes_list> -fee <value> {-before_hardfork}\n"
                "\t\t Take delegated part of commission\n\n"
                "\t\t {-before_hardfork} collect fees from blocks before hardfork\n\n"

        "Reward for block signs:\n"
            "block -net <net_name> [-chain <chain_name>] reward set"
            " -poa_cert <poa_cert_name> -value <value>\n"
                "\t\t Set base reward for sign for one block at one minute\n\n"

            "block -net <net_name> [-chain <chain_name>] reward show\n"
                "\t\t Show base reward for sign for one block at one minute\n\n"

            "block -net <net_name> [-chain <chain_name>] reward collect"
            " -cert <priv_cert_name> -addr <addr> -hashes <hashes_list> -fee <value> {-before_hardfork}\n"
                "\t\t Take delegated part of reward\n\n"
                "\t\t {-before_hardfork} collect rewards from blocks before hardfork\n\n"

        "Rewards and fees autocollect status:\n"
            "block -net <net_name> [-chain <chain_name>] autocollect status\n"
                "\t\t Show rewards and fees automatic collecting status (enabled or not)."
                    " Show prepared blocks for collecting rewards and fees if status is enabled\n\n"

        "Rewards and fees autocollect renew:\n"
            "block -net <net_name> [-chain <chain_name>] autocollect renew\n"
            " -cert <priv_cert_name> -addr <addr>\n"
                "\t\t Update reward and fees block table."
                    " Automatic collection of commission in case of triggering of the setting\n\n"
        
        "Hint:\n"
        "\texample coins amount syntax (only natural) 1.0 123.4567\n"
        "\texample datoshi amount syntax (only integer) 1 20 0.4321e+4\n\n"
        
                                        );
    if( dap_chain_block_cache_init() ) {
        log_it(L_WARNING, "Can't init blocks cache");
        return -1;
    }
    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, s_fee_verificator_callback, NULL, NULL, NULL, NULL, NULL);
    log_it(L_NOTICE ,"Initialized blocks(m) chain type");

    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE_STACK, s_fee_stack_verificator_callback, NULL, NULL, NULL, NULL, NULL);
    log_it(L_NOTICE ,"Initialized blocks(m) chain type verificator for fee stack subtype");

    return 0;
}

/**
 * @brief dap_chain_cs_blocks_deinit
 */
void dap_chain_cs_blocks_deinit()
{
    dap_chain_block_cache_deinit();
}

static int s_chain_cs_blocks_new(dap_chain_t *a_chain, dap_config_t *a_chain_config)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_cs_blocks_t, -1);
    a_chain->_inheritor = l_cs_blocks;
    l_cs_blocks->chain = a_chain;

    // Atom element callbacks
    a_chain->callback_atom_add = s_callback_atom_add ;  // Accept new element in chain
    a_chain->callback_atom_verify = s_callback_atom_verify ;  // Verify new element in chain
    a_chain->callback_atom_get_hdr_static_size = s_callback_atom_get_static_hdr_size; // Get block hdr size

    a_chain->callback_atom_iter_create = s_callback_atom_iter_create;
    a_chain->callback_atom_iter_delete = s_callback_atom_iter_delete;
    a_chain->callback_atom_iter_get = s_callback_atom_iter_get; // Linear pass through

    a_chain->callback_atom_iter_get_links = s_callback_atom_iter_get_links;

    // Datum operations callbacks
    a_chain->callback_datum_iter_create = s_chain_callback_datum_iter_create; // Datum iterator create
    a_chain->callback_datum_iter_delete = s_chain_callback_datum_iter_delete; // Datum iterator delete
    a_chain->callback_datum_iter_get_first = s_chain_callback_datum_iter_get_first; // Get the fisrt datum from chain
    a_chain->callback_datum_iter_get_last = s_chain_callback_datum_iter_get_last; // Get the last datum from chain
    a_chain->callback_datum_iter_get_next = s_chain_callback_datum_iter_get_next; // Get the next datum from chain from the current one
    a_chain->callback_datum_iter_get_prev = s_chain_callback_datum_iter_get_prev; // Get the next datum from chain from the current one

    a_chain->callback_atom_get_datums = s_callback_atom_get_datums;
    a_chain->callback_atom_get_timestamp = s_chain_callback_atom_get_timestamp;

    a_chain->callback_atom_find_by_hash = s_callback_atom_iter_find_by_hash;
    a_chain->callback_atom_dump_json = s_callback_atom_dump_json;
    a_chain->callback_atom_get_by_num = s_callback_atom_iter_get_by_num;
    a_chain->callback_datum_find_by_hash = s_callback_datum_find_by_hash;
//    a_chain->callback_atom_dump_json =

    a_chain->callback_block_find_by_tx_hash = s_callback_block_find_by_tx_hash;
    a_chain->callback_calc_reward = s_callback_calc_reward;

    a_chain->callback_add_datums = s_callback_add_datums;

    a_chain->callback_count_atom = s_callback_count_atom;
    a_chain->callback_get_atoms = s_callback_get_atoms;
    a_chain->callback_count_tx = s_callback_count_txs;
    a_chain->callback_get_txs = s_callback_get_txs;


    l_cs_blocks->callback_new_block_move = s_new_block_move;

    dap_chain_cs_blocks_pvt_t *l_cs_blocks_pvt = DAP_NEW_Z(dap_chain_cs_blocks_pvt_t);
    if (!l_cs_blocks_pvt) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }
    l_cs_blocks->_pvt = l_cs_blocks_pvt;
    pthread_rwlock_init(&l_cs_blocks_pvt->rwlock,NULL);
    pthread_rwlock_init(&l_cs_blocks_pvt->datums_rwlock, NULL);
    pthread_rwlock_init(&l_cs_blocks_pvt->forked_branches_rwlock, NULL);

    
    l_cs_blocks_pvt->block_confirm_cnt = dap_config_get_item_uint64_default(a_chain_config,"blocks","blocks_for_confirmation",DAP_FORK_MAX_DEPTH_DEFAULT);
    const char * l_genesis_blocks_hash_str = dap_config_get_item_str_default(a_chain_config,"blocks","genesis_block",NULL);
    if ( l_genesis_blocks_hash_str ){
        int lhr;
        if ( (lhr= dap_chain_hash_fast_from_str(l_genesis_blocks_hash_str,&l_cs_blocks_pvt->genesis_block_hash) )!= 0 ){
            log_it( L_ERROR, "Can't read hash from genesis_block \"%s\", ret code %d ", l_genesis_blocks_hash_str, lhr);
        }
    }
    l_cs_blocks_pvt->is_celled = dap_config_get_item_bool_default(a_chain_config, "blocks", "is_celled", false);
    const char * l_static_genesis_blocks_hash_str = dap_config_get_item_str_default(a_chain_config,"blocks","static_genesis_block",NULL);
    if ( l_static_genesis_blocks_hash_str ){
        int lhr;
        if ( (lhr= dap_chain_hash_fast_from_str(l_static_genesis_blocks_hash_str,&l_cs_blocks_pvt->static_genesis_block_hash) )!= 0 ){
            log_it( L_ERROR, "Can't read hash from static_genesis_block \"%s\", ret code %d ", l_static_genesis_blocks_hash_str, lhr);
        }
    }

    uint16_t l_list_len = 0;
    const char **l_hard_accept_list = dap_config_get_array_str(a_chain_config, "blocks", "hard_accept_list", &l_list_len);
    log_it(L_MSG, "HAL for blocks contains %d whitelisted events", l_list_len);
    for (uint16_t i = 0; i < l_list_len; i++) {
        struct cs_blocks_hal_item *l_hal_item = DAP_NEW_Z(struct cs_blocks_hal_item);
        if (!l_hal_item){
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
 * @brief dap_chain_block_cache_get_by_hash
 * @param a_blocks
 * @param a_block_hash
 * @return
 */
dap_chain_block_cache_t * dap_chain_block_cache_get_by_hash(dap_chain_cs_blocks_t * a_blocks,  dap_chain_hash_fast_t *a_block_hash)
{
    dap_chain_block_cache_t * l_ret = NULL;
    int err = pthread_rwlock_rdlock(& PVT(a_blocks)->rwlock);
    assert(!err);
    HASH_FIND(hh, PVT(a_blocks)->blocks,a_block_hash, sizeof (*a_block_hash), l_ret );
    pthread_rwlock_unlock(& PVT(a_blocks)->rwlock);
    return l_ret;
}

/**
 * @brief dap_chain_block_cache_get_by_number
 * @param a_blocks
 * @param a_block_number
 * @return
 */
dap_chain_block_cache_t * dap_chain_block_cache_get_by_number(dap_chain_cs_blocks_t * a_blocks,  uint64_t a_block_number)
{
    dap_chain_block_cache_t * l_ret = NULL;
    int err = pthread_rwlock_rdlock(& PVT(a_blocks)->rwlock);
    assert(!err);
    HASH_FIND_BYHASHVALUE(hh2, PVT(a_blocks)->blocks_num, &a_block_number, sizeof (a_block_number), a_block_number, l_ret);
    pthread_rwlock_unlock(& PVT(a_blocks)->rwlock);
    return l_ret;
}

int dap_chain_block_add_fork_notificator(dap_chain_cs_blocks_callback_fork_resolved_t a_callback, void *a_arg)
{
    if (!a_callback)
        return -100;

    dap_chain_block_fork_resolved_notificator_t *l_notificator = DAP_NEW_Z(dap_chain_block_fork_resolved_notificator_t);
    if (!l_notificator) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return -1;
    }

    l_notificator->arg = a_arg;
    l_notificator->callback = a_callback;

    s_fork_resolved_notificators = dap_list_append(s_fork_resolved_notificators, l_notificator);

    return 0;
}

static char *s_blocks_decree_set_reward(dap_chain_net_t *a_net, dap_chain_t *a_chain, uint256_t a_value, dap_cert_t *a_cert)
{
    dap_return_val_if_fail(a_net && a_cert && a_cert->enc_key &&
                           a_cert->enc_key->priv_key_data && a_cert->enc_key->priv_key_data_size, NULL);
    dap_chain_t *l_chain_anchor = a_chain ? a_chain : dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if (!l_chain_anchor) {
        log_it(L_ERROR, "Can't find chain with anchor support");
        return NULL;
    }
    dap_chain_t *l_chain_decree = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if (!l_chain_decree) {
        log_it(L_ERROR, "Can't find chain with decree support");
        return NULL;
    }
    // Create decree
    size_t l_tsd_total_size = sizeof(dap_tsd_t) + sizeof(uint256_t);
    size_t l_decree_size = sizeof(dap_chain_datum_decree_t) + l_tsd_total_size;
    dap_chain_datum_decree_t *l_decree = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_datum_decree_t, l_decree_size, NULL);
    // Fill the header
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    l_decree->header.common_decree_params.chain_id = l_chain_anchor->id;
    l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(a_net);
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD;
    l_decree->header.data_size = l_tsd_total_size;
    // Fill a TSD section
    dap_tsd_t *l_tsd = (dap_tsd_t *)l_decree->data_n_signs;
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE;
    l_tsd->size = sizeof(uint256_t);
    *(uint256_t*)(l_tsd->data) = a_value;
    // Sign it
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_decree, l_decree_size);
    if (!l_sign) {
        log_it(L_ERROR, "Decree signing failed");
        DAP_DELETE(l_decree);
        return NULL;
    }
    log_it(L_NOTICE, "<-- Signed with '%s'", a_cert->name);
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_decree_size += l_sign_size;
    l_decree->header.signs_size = l_sign_size;
    dap_chain_datum_decree_t *l_decree_rl = DAP_REALLOC_RET_VAL_IF_FAIL(l_decree, l_decree_size, NULL, l_decree, l_sign);
    l_decree = l_decree_rl;
    memcpy(l_decree->data_n_signs + l_tsd_total_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);

    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, l_decree, l_decree_size);
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain_decree, "hex");
    DAP_DELETE(l_datum);
    DAP_DEL_Z(l_decree);
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
static int s_cli_parse_cmd_hash(char ** a_argv, int a_arg_index, int a_argc, void **a_str_reply,const char * a_param,
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
 * @param a_hash_out_type
 */
static void s_cli_meta_hash_print(json_object* a_json_obj_out, const char *a_meta_title, dap_chain_block_meta_t *a_meta, const char *a_hash_out_type)
{
    if (a_meta->hdr.data_size == sizeof (dap_chain_hash_fast_t)) {
        const char *l_hash_str = !dap_strcmp(a_hash_out_type, "base58") ?
                dap_enc_base58_encode_hash_to_str_static((dap_chain_hash_fast_t*)a_meta->data) :
                dap_chain_hash_fast_to_str_static((dap_chain_hash_fast_t*)a_meta->data);
        json_object_object_add(a_json_obj_out, a_meta_title, json_object_new_string(l_hash_str));
//        if (dap_strcmp(a_hash_out_type, "base58")) {
//            const char *l_hash_str = dap_enc_base58_encode_hash_to_str_static(a_meta->data);
            //
//        } else {
//            char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
//            dap_chain_hash_fast_to_str((dap_chain_hash_fast_t *) a_meta->data, l_hash_str, sizeof(l_hash_str));
//        }
    } else
        json_object_object_add(a_json_obj_out, a_meta_title, json_object_new_string("Error, hash size is incorrect"));
}

/**
 * @brief s_cli_meta_hex_print
 * @param a_str_tmp
 * @param a_meta_title
 * @param a_meta
 */
static void s_cli_meta_hex_print(json_object* a_json_obj_out, const char * a_meta_title, dap_chain_block_meta_t * a_meta)
{
    char l_str[a_meta->hdr.data_size * 2 + 3];
    strcpy(l_str, "0x");
    dap_bin2hex(l_str + 2, a_meta->data, a_meta->hdr.data_size);
    json_object_object_add(a_json_obj_out, a_meta_title, json_object_new_string(l_str));
}

static void s_print_autocollect_table(dap_chain_net_t *a_net, json_object *a_json_obj_out, const char *a_table_name)
{
    size_t l_objs_count = 0;
    char *l_group = dap_strcmp(a_table_name, "Fees") ? dap_chain_cs_blocks_get_reward_group(a_net->pub.name)
                                                     : dap_chain_cs_blocks_get_fee_group(a_net->pub.name);
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(l_group, &l_objs_count);
    DAP_DELETE(l_group);
    uint256_t l_total_value = uint256_0;
    json_object* json_arr_out = json_object_new_array();
    for (size_t i = 0; i < l_objs_count; i++) {
        json_object* json_obj_t = json_object_new_object();
        dap_global_db_obj_t *l_obj_cur = l_objs + i;
        uint256_t l_cur_value = *(uint256_t*)l_obj_cur->value;
        const char *l_value_str; dap_uint256_to_char(l_cur_value, &l_value_str);
        json_object_object_add(json_obj_t, "obj_key", json_object_new_string(l_obj_cur->key));
        json_object_object_add(json_obj_t, "obj_val", json_object_new_string(l_value_str));
        json_object_array_add(json_arr_out, json_obj_t);
        SUM_256_256(l_total_value, l_cur_value, &l_total_value);
    }
    char *l_val = dap_strdup_printf("Autocollect tables content for === %s ===", a_table_name);
    json_object_object_add(a_json_obj_out, l_val, json_arr_out);
    DAP_DEL_Z(l_val);
    if (l_objs_count) {
        dap_global_db_objs_delete(l_objs, l_objs_count);
        uint256_t l_collect_fee = dap_chain_esbocs_get_fee(a_net->pub.id);
        SUM_256_256(l_collect_fee, a_net->pub.fee_value, &l_collect_fee);
        uint256_t l_collect_tax = {}, l_collect_value = {};
        if (compare256(l_total_value, l_collect_fee) == 1) {
            SUBTRACT_256_256(l_total_value, l_collect_fee, &l_collect_value);
            dap_pkey_t *l_my_sign_pkey = dap_chain_esbocs_get_sign_pkey(a_net->pub.id);
            dap_hash_t l_my_sign_pkey_hash;
            dap_hash_fast(l_my_sign_pkey->pkey, l_my_sign_pkey->header.size, &l_my_sign_pkey_hash);
            dap_chain_net_srv_stake_item_t *l_key_item = dap_chain_net_srv_stake_check_pkey_hash(a_net->pub.id, &l_my_sign_pkey_hash);
            if (l_key_item && !IS_ZERO_256(l_key_item->sovereign_tax) &&
                    !dap_chain_addr_is_blank(&l_key_item->sovereign_addr)) {
                MULT_256_COIN(l_collect_value, l_key_item->sovereign_tax, &l_collect_tax);
                SUBTRACT_256_256(l_collect_value, l_collect_tax, &l_collect_value);
            }
        }
        char *l_total_str = dap_chain_balance_coins_print(l_total_value);
        char *l_profit_str = dap_chain_balance_coins_print(l_collect_value);
        char *l_tax_str = dap_chain_balance_coins_print(l_collect_tax);
        char *l_fee_str = dap_chain_balance_coins_print(l_collect_fee);
        l_val = dap_strdup_printf("Total prepared value: %s %s, where profit is %s, tax is %s, fee is %s\n",
                                 l_total_str, a_net->pub.native_ticker, l_profit_str, l_tax_str, l_fee_str);
        DAP_DEL_MULTY(l_total_str, l_profit_str, l_tax_str, l_fee_str);
    }
    char *l_key = dap_strdup_printf("%s status", a_table_name);
    json_object_object_add(a_json_obj_out, l_key, json_object_new_string(l_val ? l_val : "Empty"));
    DAP_DEL_MULTY(l_key, l_val);
}

static int block_list_sort_by_date(const void *a, const void *b, bool a_forward)
{
    struct json_object *obj_a = (struct json_object*)a,
                       *obj_b = (struct json_object*)b;

    struct json_object *timestamp_a = json_object_object_get(obj_a, "timestamp"), 
                       *timestamp_b = json_object_object_get(obj_b, "timestamp");
    int l_fwd = a_forward ? 1 : -1;
    return timestamp_a > timestamp_b ? a_forward : timestamp_a < timestamp_b ? -a_forward : 0;
}

static int blocks_sort_fwd(const void *a, const void *b) {
    return block_list_sort_by_date(a, b, true);
}

static int blocks_sort_rev(const void *a, const void *b) {
    return block_list_sort_by_date(a, b, false);
}

/**
 * @brief s_cli_blocks
 * @param argc
 * @param argv
 * @param arg_func
 * @param a_str_reply
 * @return
 */
static int s_cli_blocks(int a_argc, char ** a_argv, void **a_str_reply)
{
    json_object **a_json_arr_reply = (json_object **)a_str_reply;
    //char ** a_str_reply = (char **) reply;    
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
        SUBCMD_DROP,
        SUBCMD_REWARD,
        SUBCMD_AUTOCOLLECT,
        SUBCMD_COUNT,
        SUBCMD_LAST,
        SUBCMD_FIND
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
        [SUBCMD_REWARD] = "reward",
        [SUBCMD_AUTOCOLLECT] = "autocollect",
        [SUBCMD_COUNT] = "count",
        [SUBCMD_LAST] = "last",
        [SUBCMD_FIND] = "find",
        [SUBCMD_UNDEFINED]=NULL
    };
    const size_t l_subcmd_str_count=sizeof(l_subcmd_strs)/sizeof(*l_subcmd_strs);
    const char* l_subcmd_str_args[l_subcmd_str_count];
	for(size_t i=0;i<l_subcmd_str_count;i++)
        l_subcmd_str_args[i]=NULL;
    const char* l_subcmd_str_arg = NULL, *l_subcmd_str = NULL;

    int arg_index = 1;

    dap_chain_t * l_chain = NULL;
    dap_chain_cs_blocks_t * l_blocks = NULL;
    dap_chain_net_t * l_net = NULL;

    // Parse default values
    if (dap_chain_node_cli_cmd_values_parse_net_chain_for_json(*a_json_arr_reply, &arg_index, a_argc, a_argv, &l_chain, &l_net, CHAIN_TYPE_TX))
        return -DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;

    const char *l_chain_type = dap_chain_get_cs_type(l_chain);

    if (!strstr(l_chain_type, "block_") && strcmp(l_chain_type, "esbocs")){
        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CHAIN_TYPE_ERR, "Type of chain %s is not block. This chain with type %s is not supported by this command",
                        l_chain->name, l_chain_type);
        return DAP_CHAIN_NODE_CLI_COM_BLOCK_CHAIN_TYPE_ERR;
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
    int ret = 0;
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
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_DATUM_DEL_ERR, "Error! Can't delete datum from hash because no forming new block! Check pls you role, it must be MASTER NODE or greater");
                ret = DAP_CHAIN_NODE_CLI_COM_BLOCK_DATUM_DEL_ERR;
            }
            pthread_rwlock_unlock( &PVT(l_blocks)->rwlock );
        }break;
        case SUBCMD_NEW_DATUM_ADD:{
            size_t l_datums_count=1;
            char * l_gdb_group_mempool = dap_chain_mempool_group_new(l_chain);
            dap_chain_datum_t ** l_datums = DAP_NEW_Z_SIZE(dap_chain_datum_t*,
                                                           sizeof(dap_chain_datum_t*)*l_datums_count);
            if (!l_datums) {
                log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_MEMORY_ERR, "Out of memory in s_cli_blocks");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_MEMORY_ERR;
            }
            size_t l_datum_size = 0;

            dap_chain_datum_t * l_datum = (dap_chain_datum_t*) dap_global_db_get_sync(l_gdb_group_mempool, l_subcmd_str_arg ,
                                                                                              &l_datum_size, NULL, NULL);
            l_datums[0] = l_datum;
            for (size_t i = 0; i < l_datums_count; i++) {
                if ( dap_chain_node_mempool_process(l_chain, l_datums[i], l_subcmd_str_arg, NULL) ) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_VERIF_ERR, "Error! Datum %s doesn't pass verifications, examine node log files",
                                                      l_subcmd_str_arg);
                    DAP_DEL_MULTY(l_datum, l_datums, l_gdb_group_mempool);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_VERIF_ERR;
                }
                log_it(L_INFO, "Pass datum %s from mempool to block in the new forming round ",
                               l_subcmd_str_arg);
            }
            json_object* json_obj_out = json_object_new_string("All datums processed");
            json_object_array_add(*a_json_arr_reply, json_obj_out);
            ret = DAP_CHAIN_NODE_CLI_COM_BLOCK_OK;
            DAP_DEL_MULTY(l_datum, l_datums, l_gdb_group_mempool);
        } break;

        case SUBCMD_NEW_COMPLETE:{
            // TODO
        } break;

        case SUBCMD_DROP:{
            // TODO
        }break;

        case SUBCMD_DUMP:{
            const char *l_hash_out_type = NULL;
            const char *l_hash_str = NULL;
            const char *l_num_str = NULL;
            dap_chain_hash_fast_t l_block_hash={0};
            bool l_brief = (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "-brief") != -1) ? true : false;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
            if(!l_hash_out_type)
                l_hash_out_type = "hex";
            if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }           
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hash", &l_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-num", &l_num_str);
            if (!l_hash_str && !l_num_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR, "Enter block hash or block number");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR;
            }

            dap_chain_hash_fast_from_str(l_hash_str, &l_block_hash);
            dap_chain_block_cache_t *l_block_cache = NULL;
            if (l_hash_str)
                l_block_cache = dap_chain_block_cache_get_by_hash(l_blocks, &l_block_hash);
            else {
                uint16_t num = 0;
                dap_digit_from_string(l_num_str, &num, sizeof(uint16_t));
                if (!num && dap_strcmp(l_num_str, "0")) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR, "Invalid block number %s", l_num_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR;
                }
                l_block_cache = dap_chain_block_cache_get_by_number(l_blocks, num);
            }
            if (!l_block_cache) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_FIND_ERR, "Can't find block %s ", l_hash_str);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_FIND_ERR;
            }
            dap_chain_block_t *l_block = l_block_cache->block;

            char l_time_buf[DAP_TIME_STR_SIZE], l_hexbuf[32] = { '\0' };
            // Header
            json_object* json_obj_inf = json_object_new_object();

            json_object_object_add(json_obj_inf, "block_number", json_object_new_uint64(l_block_cache->block_number));
            json_object_object_add(json_obj_inf, "hash", json_object_new_string(l_block_cache->block_hash_str));
            snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%04X",l_block->hdr.version);
            
            json_object_object_add(json_obj_inf, "version", json_object_new_string(l_hexbuf));
            snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%016"DAP_UINT64_FORMAT_X"",l_block->hdr.cell_id.uint64);
            json_object_object_add(json_obj_inf, "cell_id", json_object_new_string(l_hexbuf));
            snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%016"DAP_UINT64_FORMAT_X"",l_block->hdr.chain_id.uint64);
            json_object_object_add(json_obj_inf, "chain_id", json_object_new_string(l_hexbuf));
            dap_time_to_str_rfc822(l_time_buf, DAP_TIME_STR_SIZE, l_block->hdr.ts_created);
            json_object_object_add(json_obj_inf, "ts_created", json_object_new_string(l_time_buf));

            // Dump Metadata
            size_t l_offset = 0;
            json_object_object_add(json_obj_inf, "metadata_count", json_object_new_int(l_block->hdr.meta_count));
            json_object* json_arr_meta_out = json_object_new_array();
            json_object_array_add(*a_json_arr_reply, json_obj_inf);
            for (uint32_t i=0; i < l_block->hdr.meta_count; i++) {
                json_object* json_obj_meta = json_object_new_object();
                dap_chain_block_meta_t *l_meta = (dap_chain_block_meta_t *)(l_block->meta_n_datum_n_sign + l_offset);
                switch (l_meta->hdr.type) {
                case DAP_CHAIN_BLOCK_META_GENESIS:
                    json_object_object_add(json_obj_meta, "GENESIS", json_object_new_string("GENESIS"));
                    break;
                case DAP_CHAIN_BLOCK_META_PREV:
                    s_cli_meta_hash_print(json_obj_meta,"PREV", l_meta, l_hash_out_type);
                    break;
                case DAP_CHAIN_BLOCK_META_ANCHOR:
                    s_cli_meta_hash_print(json_obj_meta, "ANCHOR", l_meta, l_hash_out_type);
                    break;
                case DAP_CHAIN_BLOCK_META_LINK:
                    s_cli_meta_hash_print(json_obj_meta, "LINK", l_meta, l_hash_out_type);
                    break;
                case DAP_CHAIN_BLOCK_META_NONCE:
                    s_cli_meta_hex_print(json_obj_meta, "NONCE", l_meta);
                    break;
                case DAP_CHAIN_BLOCK_META_NONCE2:
                    s_cli_meta_hex_print(json_obj_meta, "NONCE2", l_meta);
                    break;
                default: {
                    snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%0X", i);
                    json_object_object_add(json_obj_meta, "#", json_object_new_string(l_hexbuf));
                    int l_len = l_meta->hdr.data_size * 2 + 5;
                    char *l_data_hex = DAP_NEW_STACK_SIZE(char, l_len);
                    strcpy(l_data_hex, "0x");
                    dap_bin2hex(l_data_hex + 2, l_meta->data, l_meta->hdr.data_size);
                    json_object_object_add(json_obj_meta, "data_hex", json_object_new_string(l_data_hex)); }
                }
                json_object_array_add(json_arr_meta_out, json_obj_meta);
                l_offset += sizeof(l_meta->hdr) + l_meta->hdr.data_size;
            }
            json_object_array_add(*a_json_arr_reply, json_arr_meta_out);
            json_object* json_obj_datum = json_object_new_object();
            json_object_object_add(json_obj_datum, "datums_count", json_object_new_uint64(l_block_cache->datum_count));
            json_object_array_add(*a_json_arr_reply, json_obj_datum);
            json_object* json_arr_datum_out = json_object_new_array();
            for (uint32_t i=0; i < l_block_cache->datum_count ; i++){
                json_object* json_obj_tx = json_object_new_object();
                dap_chain_datum_t * l_datum = l_block_cache->datum[i];
                size_t l_datum_size =  dap_chain_datum_size(l_datum);
                if (l_brief){
                    const char *l_hash_str = dap_strcmp(l_hash_out_type, "hex")
                            ? dap_enc_base58_encode_hash_to_str_static(&l_block_cache->datum_hash[i])
                            : dap_chain_hash_fast_to_str_static(&l_block_cache->datum_hash[i]);
                    json_object_object_add(json_obj_tx, "num",json_object_new_uint64(i));
                    json_object_object_add(json_obj_tx, "hash",json_object_new_string(l_hash_str));
                } else {
                    json_object_object_add(json_obj_tx, "datum size ",json_object_new_uint64(l_datum_size));
                    if (l_datum_size < sizeof (l_datum->header) ){
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_DATUM_SIZE_ERR, "ERROR: datum size %zu is smaller than header size %zu \n",l_datum_size,
                                                sizeof (l_datum->header));
                        break;
                    }
                    // Nested datums
                    snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%02X",l_datum->header.version_id);
                    json_object_object_add(json_obj_tx, "version",json_object_new_string(l_hexbuf));
                    const char * l_datum_type_str = "UNKNOWN";
                    DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_datum_type_str);
                    json_object_object_add(json_obj_tx, "type_id",json_object_new_string(l_datum_type_str));
                    dap_time_to_str_rfc822(l_time_buf, DAP_TIME_STR_SIZE, l_datum->header.ts_create);
                    json_object_object_add(json_obj_tx, "ts_create",json_object_new_string(l_time_buf));
                    json_object_object_add(json_obj_tx, "data_size",json_object_new_int(l_datum->header.data_size));
                    dap_chain_datum_dump_json(*a_json_arr_reply, json_obj_tx,l_datum,l_hash_out_type,l_net->pub.id, true);
                }
                json_object_array_add(json_arr_datum_out, json_obj_tx);
            }
            // Signatures
            json_object_array_add(*a_json_arr_reply, json_arr_datum_out);
            // Signatures
            json_object* json_obj_sig = json_object_new_object();
            json_object_object_add(json_obj_sig, "signatures_count", json_object_new_uint64(l_block_cache->sign_count));
            json_object_array_add(*a_json_arr_reply, json_obj_sig);
            json_object* json_arr_sign_out = json_object_new_array();
            for (uint32_t i=0; i < l_block_cache->sign_count ; i++) {
                json_object* json_obj_sign = json_object_new_object();
                dap_sign_t * l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, i);
                size_t l_sign_size = dap_sign_get_size(l_sign);
                dap_chain_hash_fast_t l_pkey_hash;
                dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
                const char *l_hash_str = !dap_strcmp(l_hash_out_type, "base58") ?
                        dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash) :
                        dap_chain_hash_fast_to_str_static(&l_pkey_hash);
                json_object_object_add(json_obj_sign, "type",json_object_new_string(dap_sign_type_to_str( l_sign->header.type )));
                json_object_object_add(json_obj_sign, "size",json_object_new_uint64(l_sign_size));
                json_object_object_add(json_obj_sign, "pkey_hash",json_object_new_string(l_hash_str));
                json_object_array_add(json_arr_sign_out, json_obj_sign);
            }
            json_object_array_add(*a_json_arr_reply, json_arr_sign_out);
        } break;

        case SUBCMD_LIST:{
            const char *l_cert_name = NULL, *l_from_hash_str = NULL, *l_to_hash_str = NULL, *l_head_str = NULL,
                        *l_from_date_str = NULL, *l_to_date_str = NULL, *l_pkey_hash_str = NULL, *l_limit_str = NULL, *l_offset_str = NULL;
            bool l_unspent_flag = false, l_first_signed_flag = false, l_signed_flag = false, l_hash_flag = false;
            dap_pkey_t * l_pub_key = NULL;
            dap_hash_fast_t l_from_hash = {}, l_to_hash = {}, l_pkey_hash = {};
            dap_time_t l_from_time = 0, l_to_time = 0;
            l_signed_flag = dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "signed") > 0;
            l_first_signed_flag = dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "first_signed") > 0;
            l_unspent_flag = dap_cli_server_cmd_check_option(a_argv, 1, a_argc, "-unspent") > 0;
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-pkey_hash", &l_pkey_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_hash", &l_from_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_hash", &l_to_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-from_date", &l_from_date_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-to_date", &l_to_date_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-limit", &l_limit_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-offset", &l_offset_str);
            bool l_head = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-head", &l_head_str) ? true : false;
            size_t l_offset = l_offset_str ? strtoul(l_offset_str, NULL, 10) : 0;
            size_t l_limit = l_limit_str ? strtoul(l_limit_str, NULL, 10) : 0;

            if (l_signed_flag && l_first_signed_flag) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Choose only one option from 'singed' and 'first_signed'");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }
            if ((l_signed_flag || l_first_signed_flag) && !l_cert_name && !l_pkey_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Option from '%s' requires parameter '-cert' or 'pkey_hash'",
                                                                l_first_signed_flag ? "first_signed" : "signed");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }
            if (l_cert_name) {
                dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
                if (!l_cert) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR, "Can't find \"%s\" certificate", l_cert_name);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR;
                }
                l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
                if (!l_pub_key) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PUB_KEY_ERR, "Corrupted certificate \"%s\" have no public key data", l_cert_name);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PUB_KEY_ERR;
                }
            } else if (l_pkey_hash_str) {
                if (dap_chain_hash_fast_from_str(l_pkey_hash_str, &l_pkey_hash)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR, "Can't convert \"%s\" to hash", l_pkey_hash_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR;
                }
            }
            if (l_unspent_flag && l_signed_flag && !l_pkey_hash_str)
                dap_hash_fast(l_pub_key->pkey, l_pub_key->header.size, &l_pkey_hash);
            if ((l_cert_name || l_pkey_hash_str) && !l_signed_flag && !l_first_signed_flag)
                l_first_signed_flag = true;

            if (l_from_hash_str) {
                if (dap_chain_hash_fast_from_str(l_from_hash_str, &l_from_hash)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR, "Can't convert \"%s\" to hash", l_from_hash_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR;
                }
            }
            if (l_to_hash_str) {
                if (dap_chain_hash_fast_from_str(l_to_hash_str, &l_to_hash)) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR, "Can't convert \"%s\" to hash", l_to_hash_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR;
                }
            }

            if (l_from_date_str) {
                l_from_time = dap_time_from_str_simplified(l_from_date_str);
                if (!l_from_time) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR, "Can't convert \"%s\" to date", l_from_date_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR;
                }
            }
            if (l_to_date_str) {
                l_to_time = dap_time_from_str_simplified(l_to_date_str);
                if (!l_to_time) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR, "Can't convert \"%s\" to date", l_to_date_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR;
                }
                struct tm *l_localtime = localtime((time_t *)&l_to_time);
                l_localtime->tm_mday += 1;  // + 1 day to end date, got it inclusive
                l_to_time = mktime(l_localtime);
            }

            pthread_rwlock_rdlock(&PVT(l_blocks)->rwlock);
            json_object* json_arr_bl_cache_out = json_object_new_array();
            size_t l_start_arr = 0;
            size_t l_arr_end = 0;
            dap_chain_set_offset_limit_json(json_arr_bl_cache_out, &l_start_arr, &l_arr_end, l_limit, l_offset, PVT(l_blocks)->blocks_count, false);
            
            size_t i_tmp = 0;
            dap_chain_block_cache_t *l_block_cache = PVT(l_blocks)->blocks;
            if (!l_head) {                
                l_block_cache = HASH_LAST(l_block_cache);
                dap_time_t temp = l_from_time;
                l_from_time = l_to_time;
                l_to_time = temp;
            }             
            for ( ; l_block_cache; l_block_cache = l_head ? l_block_cache->hh.next : l_block_cache->hh.prev) {
                dap_time_t l_ts = l_block_cache->block->hdr.ts_created;
                if (l_head) {
                    if (l_from_time && l_ts < l_from_time)
                        continue;
                    if (l_to_time && l_ts >= l_to_time)
                        break;
                } else {
                    if (l_from_time && l_ts > l_from_time)
                        continue;
                    if (l_to_time && l_ts <= l_to_time)
                        break;
                }
                if (l_from_hash_str && !l_hash_flag) {
                   if (!dap_hash_fast_compare(&l_from_hash, &l_block_cache->block_hash))
                       continue;
                   l_hash_flag = true;
                }
                if (l_first_signed_flag) {
                    dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, 0);
                    if (!l_pub_key) {
                        dap_hash_fast_t l_sign_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                        if (!dap_hash_fast_compare(&l_pkey_hash, &l_sign_pkey_hash))
                            continue;
                    } else if (!dap_pkey_compare_with_sign(l_pub_key, l_sign))
                        continue;
                    if (l_unspent_flag) {
                        bool l_found = false;
                        for (size_t i = 0; i < l_block_cache->datum_count; i++) {
                            if (l_block_cache->datum[i]->header.type_id != DAP_CHAIN_DATUM_TX)
                                continue;
                            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_block_cache->datum[i]->data;
                            int l_out_idx_tmp = 0;
                            if (NULL == dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, &l_out_idx_tmp))
                                continue;
                            if (!dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_block_cache->datum_hash + i, l_out_idx_tmp, NULL)) {
                                l_found = true;
                                break;
                            }
                        }
                        if (!l_found)
                            continue;
                    }
                } else if (l_signed_flag) {
                    if (l_unspent_flag && l_ts < DAP_REWARD_INIT_TIMESTAMP)
                        continue;
                    if (!l_pub_key) {
                        bool l_found = false;
                        // TODO optimize performance by precalculated sign hashes in block cache
                        for (size_t i = 0; i < l_block_cache->sign_count ; i++) {
                            dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, i);
                            dap_hash_fast_t l_sign_pkey_hash;
                            dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                            if (dap_hash_fast_compare(&l_pkey_hash, &l_sign_pkey_hash)) {
                                l_found = true;
                                break;
                            }
                        }
                        if (!l_found)
                            continue;
                    } else if (!dap_chain_block_sign_match_pkey(l_block_cache->block, l_block_cache->block_size, l_pub_key))
                        continue;
                    if (l_unspent_flag) {
                        if (dap_ledger_is_used_reward(l_net->pub.ledger, &l_block_cache->block_hash, &l_pkey_hash))
                            continue;
                    }
                }
                if (i_tmp < l_start_arr || i_tmp >= l_arr_end) {
                    i_tmp++;
                    continue;
                }
                i_tmp++;
                char l_buf[DAP_TIME_STR_SIZE];
                dap_time_to_str_rfc822(l_buf, DAP_TIME_STR_SIZE, l_ts);
                json_object* json_obj_bl_cache = json_object_new_object();
                json_object_object_add(json_obj_bl_cache, "block_number",json_object_new_uint64(l_block_cache->block_number));
                json_object_object_add(json_obj_bl_cache, "hash",json_object_new_string(l_block_cache->block_hash_str));
                json_object_object_add(json_obj_bl_cache, "timestamp", json_object_new_uint64(l_ts));
                json_object_object_add(json_obj_bl_cache, "ts_create",json_object_new_string(l_buf));
                json_object_array_add(json_arr_bl_cache_out, json_obj_bl_cache);
                if (l_to_hash_str && dap_hash_fast_compare(&l_to_hash, &l_block_cache->block_hash))
                    break;
            }
            pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
            //sort by time
            json_object_array_sort(json_arr_bl_cache_out, l_head ? blocks_sort_fwd : blocks_sort_rev);
            // Remove the timestamp and change block num
            size_t l_length = json_object_array_length(json_arr_bl_cache_out);
            for (size_t i = 0; i < l_length; i++) {
                struct json_object *obj = json_object_array_get_idx(json_arr_bl_cache_out, i);
                json_object_object_del(obj, "timestamp");
                if (json_object_object_get_ex(obj, "block", NULL)) 
                    json_object_object_add(obj, "block", json_object_new_uint64(i));
            }
            json_object_array_add(*a_json_arr_reply, json_arr_bl_cache_out);

            char *l_filtered_criteria = "none";
            json_object* json_obj_out = json_object_new_object();
            if (l_cert_name || l_pkey_hash_str || l_from_hash_str || l_to_hash_str || l_from_date_str || l_to_date_str)
                l_filtered_criteria = " filtered according to the specified criteria";
            char *l_key = dap_strdup_printf("%s.%s with filter - %s, have blocks",l_net->pub.name,l_chain->name,l_filtered_criteria);
            json_object_object_add(json_obj_out, l_key, json_object_new_uint64(i_tmp));
            DAP_DELETE(l_key);
            json_object_array_add(*a_json_arr_reply,json_obj_out);
        } break;
        case SUBCMD_LAST: {
            json_object* json_obj_out = json_object_new_object();
            dap_chain_block_cache_t *l_last_block = HASH_LAST(PVT(l_blocks)->blocks);
            char l_buf[DAP_TIME_STR_SIZE];
            if (l_last_block)
                dap_time_to_str_rfc822(l_buf, DAP_TIME_STR_SIZE, l_last_block->ts_created);
            json_object_object_add(json_obj_out, "last_block_num", json_object_new_uint64(l_last_block ? l_last_block->block_number : 0));
            json_object_object_add(json_obj_out, "last_block_hash", json_object_new_string(l_last_block ? l_last_block->block_hash_str : "empty"));
            json_object_object_add(json_obj_out, "ts_created", json_object_new_string(l_last_block ? l_buf : "never"));

            char *l_key = dap_strdup_printf("%s.%s has blocks", l_net->pub.name, l_chain->name);
            json_object_object_add(json_obj_out, l_key, json_object_new_uint64(PVT(l_blocks)->blocks_count));
            DAP_DELETE(l_key);
            json_object_array_add(*a_json_arr_reply, json_obj_out);
        } break;
        case SUBCMD_FIND: {
            const char* l_datum_hash_str = NULL;
            json_object* json_obj_out = json_object_new_object();
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-datum", &l_datum_hash_str);
            if (!l_datum_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'event find' requires parameter '-datum'");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }
            dap_hash_fast_t l_datum_hash = {};
            int ret_code = 0;
            int l_atoms_cnt = 0;
            dap_chain_hash_fast_from_str(l_datum_hash_str, &l_datum_hash);
            pthread_rwlock_rdlock(&PVT(l_blocks)->datums_rwlock);
            dap_chain_block_cache_t *l_curr_block = PVT(l_blocks)->blocks;
            json_object* json_arr_bl_cache_out = json_object_new_array();
            for (;l_curr_block;l_curr_block = l_curr_block->hh.next){
                for (size_t i = 0; i < l_curr_block->datum_count; i++){
                    if (dap_hash_fast_compare(&l_datum_hash, &l_curr_block->datum_hash[i])){
                        json_object_array_add(json_arr_bl_cache_out, json_object_new_string(dap_hash_fast_to_str_static(&l_curr_block->block_hash)));
                        l_atoms_cnt++;
                        continue;
                    }
                }
            }
            pthread_rwlock_unlock(&PVT(l_blocks)->datums_rwlock);
            json_object_object_add(json_obj_out, "blocks", json_arr_bl_cache_out);
            json_object_object_add(json_obj_out, "total",json_object_new_int(l_atoms_cnt));
            json_object_array_add(*a_json_arr_reply, json_obj_out);
        } break;
        case SUBCMD_COUNT: {
            json_object* json_obj_out = json_object_new_object();
            char *l_key = dap_strdup_printf("%s.%s has blocks - ", l_net->pub.name,l_chain->name);
            json_object_object_add(json_obj_out, l_key, json_object_new_uint64(PVT(l_blocks)->blocks_count));
            DAP_DELETE(l_key);
            json_object_array_add(*a_json_arr_reply, json_obj_out);

        } break;

        case SUBCMD_FEE:
        case SUBCMD_REWARD: {
            const char * l_fee_value_str = NULL;
            const char * l_cert_name = NULL;
            const char * l_addr_str = NULL;
            const char * l_hash_out_type = NULL;
            const char * l_hash_str = NULL;

            uint256_t               l_fee_value = {};
            size_t                  l_hashes_count = 0;
            dap_list_t              *l_block_list = NULL;
            dap_chain_addr_t        *l_addr = NULL;

            if (l_subcmd == SUBCMD_FEE) {
                if (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "collect") == -1) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block fee' requires subcommand 'collect'");
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                }
            } else { // l_sumcmd == SUBCMD_REWARD
                if (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "set") >= 0) {
                    const char *l_value_str = NULL;
                    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-poa_cert", &l_cert_name);
                    if(!l_cert_name) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block reward set' requires parameter '-poa_cert'");
                        return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                    }
                    dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
                    if (!l_cert) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR, "Can't find \"%s\" certificate", l_cert_name);
                        return DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR;
                    }
                    if (!l_cert->enc_key || !l_cert->enc_key->priv_key_data || !l_cert->enc_key->priv_key_data_size) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PVT_KEY_ERR, "Certificate \"%s\" doesn't contains private key", l_cert_name);
                        return DAP_CHAIN_NODE_CLI_COM_BLOCK_PVT_KEY_ERR;
                    }

                    dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-value", &l_value_str);
                    uint256_t l_value = dap_chain_balance_scan(l_value_str);
                    if (!l_value_str || IS_ZERO_256(l_value)) {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block reward set' requires parameter '-value' to be valid 256-bit unsigned integer");
                        return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                    }
                    char *l_decree_hash_str = s_blocks_decree_set_reward(l_net, l_chain, l_value, l_cert);
                    if (l_decree_hash_str) {
                        json_object* json_obj_out = json_object_new_object();
                        char *l_val = dap_strdup_printf("Decree with hash %s created to set basic block sign reward", l_decree_hash_str);
                        DAP_DELETE(l_decree_hash_str);
                        json_object_object_add(json_obj_out, "status", json_object_new_string(l_val));
                        DAP_DELETE(l_val);
                        json_object_array_add(*a_json_arr_reply, json_obj_out);
                    } else {
                        dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_SIGN_ERR, "Basic block sign reward setting failed. Examine log file for details");
                        return DAP_CHAIN_NODE_CLI_COM_BLOCK_SIGN_ERR;
                    }
                    break;
                } else if (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "show") >= 0) {
                    uint256_t l_cur_reward = dap_chain_net_get_reward(l_net, UINT64_MAX);
                    const char *l_reward_str; dap_uint256_to_char(l_cur_reward, &l_reward_str);
                    json_object* json_obj_out = json_object_new_object();
                    char *l_val = dap_strdup_printf("Current base block reward is %s\n", l_reward_str);
                    json_object_object_add(json_obj_out, "status", json_object_new_string(l_val));
                    DAP_DELETE(l_val);
                    json_object_array_add(*a_json_arr_reply, json_obj_out);
                    break;
                } else if (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "collect") == -1) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block reward' requires subcommands 'set' or 'show' or 'collect'");
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                }
            }

            // Fee or reward collect handler
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-H", &l_hash_out_type);
            if(!l_hash_out_type)
                l_hash_out_type = "hex";
            if(dap_strcmp(l_hash_out_type,"hex") && dap_strcmp(l_hash_out_type,"base58")) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "invalid parameter -H, valid values: -H <hex | base58>");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }

            // Private certificate
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
            // The address of the wallet to which the commission is received
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-hashes", &l_hash_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-fee", &l_fee_value_str);
            dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-before_hardfork", &l_fee_value_str);
            int l_before_hardfork = dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-before_hardfork", NULL);

            if (!l_addr_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block %s collect' requires parameter '-addr'", l_subcmd_str);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }
            l_addr = dap_chain_addr_from_str(l_addr_str);
            if(!l_cert_name) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block %s collect' requires parameter '-cert'", l_subcmd_str);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }
            dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
            if (!l_cert) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR, "Can't find \"%s\" certificate", l_cert_name);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR;
            }
            if (!l_cert->enc_key || !l_cert->enc_key->priv_key_data || !l_cert->enc_key->priv_key_data_size) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR,
                                        "Certificate \"%s\" doesn't contains private key", l_cert_name);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR;
            }
            if (!l_fee_value_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block %s collect' requires parameter '-fee'", l_subcmd_str);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }
            l_fee_value = dap_chain_balance_scan(l_fee_value_str);
            if (!l_fee_value_str || IS_ZERO_256(l_fee_value)) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block %s collect' requires parameter '-fee' to be valid uint256", l_subcmd_str);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }

            if (!l_hash_str) {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR, "Command 'block fee collect' requires parameter '-hashes'");
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
            }

            char *l_hash_tx = NULL;
            if (l_before_hardfork == 0) {
                // NOTE: This call will modify source string
                l_block_list = s_block_parse_str_list((char *)l_hash_str, &l_hashes_count, l_chain);            
                if (!l_block_list || !l_hashes_count) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR,
                                                "Block fee collection requires at least one hash to create a transaction");
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR;
                }
                char *l_hash_tx = l_subcmd == SUBCMD_FEE
                    ? dap_chain_mempool_tx_coll_fee_create(l_blocks, l_cert->enc_key, l_addr, l_block_list, l_fee_value, l_hash_out_type)
                    : dap_chain_mempool_tx_reward_create(l_blocks, l_cert->enc_key, l_addr, l_block_list, l_fee_value, l_hash_out_type);
            } else {
                char *l_hash_tx = dap_chain_mempool_tx_coll_fee_stack_create(l_blocks, l_cert->enc_key, l_addr, l_fee_value, l_hash_out_type);
            }
            
            if (l_hash_tx) {
                json_object* json_obj_out = json_object_new_object();
                char *l_val = dap_strdup_printf("TX for %s collection created successfully, hash = %s\n", l_subcmd_str, l_hash_tx);
                DAP_DELETE(l_hash_tx);
                json_object_object_add(json_obj_out, "status", json_object_new_string(l_val ? l_val : "(null)"));
                DAP_DELETE(l_val);
                json_object_array_add(*a_json_arr_reply, json_obj_out);
            } else {
                dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR,
                                            "Can't create %s collect TX\n", l_subcmd_str);
                return DAP_CHAIN_NODE_CLI_COM_BLOCK_HASH_ERR;
            }
            dap_list_free_full(l_block_list, NULL);
        }break;

        case SUBCMD_AUTOCOLLECT: {
            const char *l_cert_name = NULL, *l_addr_str = NULL;
            dap_hash_fast_t l_pkey_hash = {};
            size_t l_block_count = 0;
            if (dap_cli_server_cmd_check_option(a_argv, arg_index,a_argc, "renew") > 0) {
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-cert", &l_cert_name);
                if(!l_cert_name) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR,
                                            "Command 'block autocollect renew' requires parameter '-cert'", l_subcmd_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                }
                dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
                if (!l_cert) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR,
                                            "Can't find \"%s\" certificate", l_cert_name);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_CERT_ERR;
                }
                dap_pkey_t *l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
                if (!l_pub_key) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PUB_KEY_ERR,
                                            "Corrupted certificate \"%s\" have no public key data", l_cert_name);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PUB_KEY_ERR;
                }
                dap_cli_server_cmd_find_option_val(a_argv, arg_index, a_argc, "-addr", &l_addr_str);
                if (!l_addr_str) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR,
                                            "Command 'block autocollect renew' requires parameter '-addr'", l_subcmd_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                }
                dap_chain_addr_t *l_addr = dap_chain_addr_from_str(l_addr_str);
                if (!l_addr) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_CONVERT_ERR,
                                            "Can't convert sring %s to wallet address", l_addr_str);
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                }
                if (l_addr->net_id.uint64 != l_net->pub.id.uint64) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_NET_ERR,
                                            "Wallet address should be from the collecting network");
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_NET_ERR;
                }
                dap_chain_esbocs_block_collect_t l_block_collect_params = (dap_chain_esbocs_block_collect_t){
                        .collecting_level = dap_chain_esbocs_get_collecting_level(l_chain),
                        .minimum_fee = dap_chain_esbocs_get_fee(l_chain->net_id),
                        .chain = l_chain,
                        .blocks_sign_key = l_cert->enc_key,
                        .block_sign_pkey = l_pub_key,
                        .collecting_addr = l_addr
                };
                //Clear gdb
                char *l_group_fee = dap_chain_cs_blocks_get_fee_group(l_net->pub.name);
                dap_global_db_erase_table_sync(l_group_fee);
                DAP_DELETE(l_group_fee);
                char *l_group_reward = dap_chain_cs_blocks_get_reward_group(l_net->pub.name);
                dap_global_db_erase_table_sync(l_group_reward);
                DAP_DELETE(l_group_reward);

                json_object* json_arr_bl_out = json_object_new_array();

                for (dap_chain_block_cache_t *l_block_cache = PVT(l_blocks)->blocks; l_block_cache; l_block_cache = l_block_cache->hh.next) {
                    dap_time_t l_ts = l_block_cache->block->hdr.ts_created;
                    dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, 0);
                    if (!l_pub_key) {
                        dap_hash_fast_t l_sign_pkey_hash;
                        dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                        if (!dap_hash_fast_compare(&l_pkey_hash, &l_sign_pkey_hash))
                            continue;
                    } else if (!dap_pkey_compare_with_sign(l_pub_key, l_sign))
                        continue;
                    for (size_t i = 0; i < l_block_cache->datum_count; i++) {
                        if (l_block_cache->datum[i]->header.type_id != DAP_CHAIN_DATUM_TX)
                            continue;
                        dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_block_cache->datum[i]->data;
                        int l_out_idx_tmp = 0;
                        if (NULL == dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, &l_out_idx_tmp))
                            continue;
                        if (!dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_block_cache->datum_hash + i, l_out_idx_tmp, NULL)) {
                            dap_chain_esbocs_add_block_collect(l_block_cache, &l_block_collect_params, DAP_CHAIN_BLOCK_COLLECT_FEES);
                            char l_buf[DAP_TIME_STR_SIZE];
                            json_object* json_obj_bl = json_object_new_object();
                            dap_time_to_str_rfc822(l_buf, DAP_TIME_STR_SIZE, l_ts);
                            char *l_val = dap_strdup_printf("fee - \t%s: ts_create=%s", l_block_cache->block_hash_str, l_buf);
                            json_object_object_add(json_obj_bl, "block", json_object_new_string(l_val));
                            DAP_DELETE(l_val);
                            json_object_array_add(json_arr_bl_out, json_obj_bl);
                            l_block_count++;
                            break;
                        }
                    } 
                    if (l_ts < DAP_REWARD_INIT_TIMESTAMP)
                            continue;
                    
                    if (!l_pub_key) {
                        bool l_found = false;
                        for (size_t i = 0; i < l_block_cache->sign_count ; i++) {
                            dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, i);
                            dap_hash_fast_t l_sign_pkey_hash;
                            dap_sign_get_pkey_hash(l_sign, &l_sign_pkey_hash);
                            if (dap_hash_fast_compare(&l_pkey_hash, &l_sign_pkey_hash)) {
                                l_found = true;
                                break;
                            }
                        }
                        if(!l_found)
                            continue;
                    } else if (!dap_chain_block_sign_match_pkey(l_block_cache->block, l_block_cache->block_size, l_pub_key))
                        continue;
                    if (dap_ledger_is_used_reward(l_net->pub.ledger, &l_block_cache->block_hash, &l_pkey_hash))
                        continue;
                    dap_chain_esbocs_add_block_collect(l_block_cache, &l_block_collect_params, DAP_CHAIN_BLOCK_COLLECT_REWARDS);
                    char l_buf[DAP_TIME_STR_SIZE];
                    json_object* json_obj_bl = json_object_new_object();
                    dap_time_to_str_rfc822(l_buf, DAP_TIME_STR_SIZE, l_ts);
                    char *l_val = dap_strdup_printf("rewards - \t%s: ts_create=%s\n", l_block_cache->block_hash_str, l_buf);
                    json_object_object_add(json_obj_bl, "block", json_object_new_string(l_val));
                    DAP_DELETE(l_val);
                    json_object_array_add(json_arr_bl_out, json_obj_bl);
                    l_block_count++;
                }
                json_object_array_add(*a_json_arr_reply, json_arr_bl_out);
                json_object* json_obj_out = json_object_new_object();
                char *l_val = dap_strdup_printf("%s.%s: Have %"DAP_UINT64_FORMAT_U" blocks\n",
                                     l_net->pub.name, l_chain->name, l_block_count);
                json_object_object_add(json_obj_out, "status", json_object_new_string(l_val));
                DAP_DELETE(l_val);
                json_object_array_add(*a_json_arr_reply, json_obj_out);
            } else {
                if (dap_cli_server_cmd_check_option(a_argv, arg_index, a_argc, "status") == -1) {
                    dap_json_rpc_error_add(*a_json_arr_reply, DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR,
                                            "Command 'block autocollect' requires subcommand 'status'");
                    return DAP_CHAIN_NODE_CLI_COM_BLOCK_PARAM_ERR;
                }
                json_object* json_obj_out = json_object_new_object();
                json_object_array_add(*a_json_arr_reply, json_obj_out);
                bool l_status = dap_chain_esbocs_get_autocollect_status(l_net->pub.id);
                char *l_val = dap_strdup_printf("for network %s is %s\n", l_net->pub.name,
                                                l_status ? "active" : "inactive cause of the network config or consensus starting problems");
                json_object_object_add(json_obj_out, "autocollect_status", json_object_new_string(l_val));
                DAP_DELETE(l_val);
                if (!l_status)
                    break;
                s_print_autocollect_table(l_net, json_obj_out, "Fees");
                s_print_autocollect_table(l_net, json_obj_out, "Rewards");
            }            
        } break;

        case SUBCMD_UNDEFINED:
        default: {
            json_object* json_obj_out = json_object_new_object();
            char *l_val = dap_strdup_printf("Undefined block subcommand \"%s\" ", l_subcmd_str);
            json_object_object_add(json_obj_out, "status", json_object_new_string(l_val));
            DAP_DELETE(l_val);
            json_object_array_add(*a_json_arr_reply, json_obj_out);
            ret = DAP_CHAIN_NODE_CLI_COM_BLOCK_UNKNOWN;

        } break;
    }
    return ret;
}

static dap_list_t *s_block_parse_str_list(char *a_hash_str, size_t *a_hash_size, dap_chain_t *a_chain)
{
    dap_list_t *l_block_list = NULL;
    dap_chain_hash_fast_t l_hash_block;
    char *l_hashes_tmp_ptrs = NULL;
    char *l_hashes_str = strtok_r(a_hash_str, ",", &l_hashes_tmp_ptrs);
    size_t l_hashes_pos = 0;
    while (l_hashes_str) {
        l_hashes_str = dap_strstrip(l_hashes_str);
        if (!l_hashes_str || dap_chain_hash_fast_from_str(l_hashes_str, &l_hash_block)) {
            log_it(L_WARNING, "Can't convert string %s to hash", l_hashes_str ? l_hashes_str : "(null)");
            l_hashes_pos = 0;
            break;
        }
        dap_chain_block_t *l_block = (dap_chain_block_t *)dap_chain_get_atom_by_hash(a_chain, &l_hash_block, NULL);
        if (!l_block) {
            log_it(L_WARNING, "There is no block pointed by hash %s", l_hashes_str);
            l_hashes_pos = 0;
            break;
        }
        dap_hash_fast_t *l_block_hash_new = DAP_DUP(&l_hash_block);
        if (!l_block_hash_new) {
            log_it(L_CRITICAL, "Memory allocaton error");
            l_hashes_pos = 0;
            break;
        }
        l_block_list = dap_list_append(l_block_list, l_block_hash_new);
        l_hashes_str = strtok_r(NULL, ",", &l_hashes_tmp_ptrs);
        l_hashes_pos++;
    }
    if (a_hash_size)
        *a_hash_size = l_hashes_pos;
    if (!l_hashes_pos && l_block_list) {
        dap_list_free_full(l_block_list, NULL);
        l_block_list = NULL;
    }
    return l_block_list;
}

/**
 * @brief s_callback_delete
 * @details Destructor for blocks consensus chain
 * @param a_chain
 */
static int s_callback_delete(dap_chain_t * a_chain)
{
    s_callback_cs_blocks_purge(a_chain);
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    int err = pthread_rwlock_wrlock(&PVT(l_blocks)->rwlock);
    assert(!err);
    if (l_blocks->callback_delete)
        l_blocks->callback_delete(l_blocks);
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
    pthread_rwlock_destroy(&PVT(l_blocks)->rwlock);
    pthread_rwlock_destroy(&PVT(l_blocks)->datums_rwlock);
    pthread_rwlock_destroy(&PVT(l_blocks)->forked_branches_rwlock);
    DAP_DEL_Z(l_blocks->_inheritor);
    DAP_DEL_Z(l_blocks->_pvt);
    log_it(L_INFO, "Block destructed");
    return 0;
}

static int s_callback_cs_blocks_purge(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);

    pthread_rwlock_wrlock(&PVT(l_blocks)->forked_branches_rwlock);
    for (size_t i = 0; i < PVT(l_blocks)->forked_br_cnt; i++){
        dap_chain_block_forked_branch_atoms_table_t *l_atom_tmp, *l_atom;
        HASH_ITER(hh, PVT(l_blocks)->forked_branches[i]->forked_branch_atoms, l_atom, l_atom_tmp) {
            HASH_DEL(PVT(l_blocks)->forked_branches[i]->forked_branch_atoms, l_atom);
            l_atom = NULL;
        }
        DAP_DEL_Z(PVT(l_blocks)->forked_branches[i]);
    }
    DAP_DEL_Z(PVT(l_blocks)->forked_branches);
    pthread_rwlock_unlock(&PVT(l_blocks)->forked_branches_rwlock);

    int err = pthread_rwlock_wrlock(&PVT(l_blocks)->rwlock);
    assert(!err);
    dap_chain_block_cache_t *l_block = NULL, *l_block_tmp = NULL;
    HASH_ITER(hh, PVT(l_blocks)->blocks, l_block, l_block_tmp) {
        HASH_DEL(PVT(l_blocks)->blocks, l_block);
        if (!a_chain->is_mapped)
            DAP_DELETE(l_block->block);
        dap_chain_block_cache_delete(l_block);
    }
    PVT(l_blocks)->blocks_count = 0;
    HASH_CLEAR(hh2, PVT(l_blocks)->blocks_num);
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
    
    dap_chain_block_datum_index_t *l_datum_index = NULL, *l_datum_index_tmp = NULL;
    pthread_rwlock_wrlock(&PVT(l_blocks)->datums_rwlock);
    HASH_ITER(hh, PVT(l_blocks)->datum_index, l_datum_index, l_datum_index_tmp) {
        HASH_DEL(PVT(l_blocks)->datum_index, l_datum_index);
        DAP_DELETE(l_datum_index);
        l_datum_index = NULL;
    }
    pthread_rwlock_unlock(&PVT(l_blocks)->datums_rwlock);
    return 0;
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
    for (size_t i = 0;
            i < a_block_cache->datum_count && l_block_offset + sizeof(a_block_cache->block->hdr) < a_block_cache->block_size;
            i++, l_block_offset += l_datum_size) {
        dap_chain_datum_t *l_datum = a_block_cache->datum[i];
        size_t l_datum_data_size = l_datum->header.data_size;
        l_datum_size = l_datum_data_size + sizeof(l_datum->header);
        if(l_datum_size>a_block_cache->block_size- l_block_offset ){
            log_it(L_WARNING, "Corrupted block %s has strange datum on offset %zd with size %zd out of block size",
                   a_block_cache->block_hash_str, l_block_offset,l_datum_size );
            break;
        }
        dap_hash_fast_t *l_datum_hash = a_block_cache->datum_hash + i;
        dap_ledger_datum_iter_data_t l_datum_index_data = { .token_ticker = "0", .action = DAP_CHAIN_TX_TAG_ACTION_UNKNOWN , .uid.uint64 = 0 };
        bool is_hardfork_related_block = a_block_cache->generation && a_block_cache->generation == a_blocks->chain->generation;
        int l_res = dap_chain_datum_add(a_blocks->chain, l_datum, l_datum_size, l_datum_hash, &l_datum_index_data);
        if (l_datum->header.type_id != DAP_CHAIN_DATUM_TX || l_res != DAP_LEDGER_CHECK_ALREADY_CACHED) { // If this is any datum other than a already cached transaction
            l_ret++;
            if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX)
                PVT(a_blocks)->tx_count++;  
            // Save datum hash -> block_hash link in hash table
            dap_chain_block_datum_index_t *l_datum_index = DAP_NEW_Z(dap_chain_block_datum_index_t);
            if (!l_datum_index) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
                return 1;
            }
            l_datum_index->ts_added = time(NULL);
            l_datum_index->block_cache = a_block_cache;
            l_datum_index->datum_hash = *l_datum_hash;
            l_datum_index->ret_code = l_res;
            l_datum_index->datum_index = i;
            l_datum_index->action = l_datum_index_data.action;
            l_datum_index->service_uid = l_datum_index_data.uid;
            dap_strncpy(l_datum_index->token_ticker, l_datum_index_data.token_ticker, DAP_CHAIN_TICKER_SIZE_MAX);
            pthread_rwlock_wrlock(&PVT(a_blocks)->datums_rwlock);
            HASH_ADD(hh, PVT(a_blocks)->datum_index, datum_hash, sizeof(*l_datum_hash), l_datum_index);
            pthread_rwlock_unlock(&PVT(a_blocks)->datums_rwlock);
            dap_chain_datum_notify(a_blocks->chain, a_block_cache->block->hdr.cell_id, l_datum_hash, &l_datum_index->block_cache->block_hash,
                                   (byte_t*)l_datum, l_datum_size, l_res, l_datum_index_data.action, l_datum_index_data.uid);
        }
    }
    debug_if(s_debug_more, L_DEBUG, "Block %s checked, %s", a_block_cache->block_hash_str,
             l_ret == (int)a_block_cache->datum_count ? "all correct" : "there are rejected datums");
    return l_ret;
}


static int s_delete_atom_datums(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_cache_t *a_block_cache)
{
    if (! a_block_cache->datum_count){
        log_it(L_WARNING,"Block %s has no datums at all, can't remove anything from ledger", a_block_cache->block_hash_str);
        return 1; // No errors just empty block
    }
    int l_ret = 0;

    size_t l_block_offset = 0;
    size_t l_datum_size = 0;
    for(size_t i=0; i<a_block_cache->datum_count && l_block_offset +sizeof(a_block_cache->block->hdr) < a_block_cache->block_size;
            i++, l_block_offset += l_datum_size){
        dap_hash_fast_t *l_datum_hash = a_block_cache->datum_hash + i;
        dap_chain_datum_t *l_datum = a_block_cache->datum[i];
        dap_chain_block_datum_index_t *l_datum_index = NULL;
        size_t l_datum_data_size = l_datum->header.data_size;
        l_datum_size = l_datum_data_size + sizeof(l_datum->header);
        HASH_FIND(hh, PVT(a_blocks)->datum_index, l_datum_hash, sizeof(dap_hash_fast_t), l_datum_index);
        if (l_datum_index){
            if (l_datum_index->ret_code >= 0)
                dap_chain_datum_remove(a_blocks->chain, l_datum, l_datum_size, l_datum_hash);
            l_ret++;
            HASH_DEL(PVT(a_blocks)->datum_index, l_datum_index);
            // notify datum removed
            dap_chain_datum_removed_notify(a_blocks->chain, a_block_cache->block->hdr.cell_id, l_datum_hash, l_datum);
        }
    }
    debug_if(s_debug_more, L_DEBUG, "Block %s checked, %s", a_block_cache->block_hash_str,
             l_ret == (int)a_block_cache->datum_count ? "all correct" : "there are rejected datums");
    return l_ret;
}

static bool s_select_longest_branch(dap_chain_cs_blocks_t * a_blocks, dap_chain_block_cache_t * a_bcache, uint64_t a_main_branch_length)
{
    dap_chain_cs_blocks_t * l_blocks = a_blocks;
    if (!a_blocks){
        log_it(L_ERROR,"a_blocks is NULL");
        return false;
    }

    if (!a_bcache){
        log_it(L_ERROR,"a_bcache is NULL");
        return false;
    }

    if (!a_bcache->forked_branches){
        log_it(L_ERROR,"This block is not a forked.");
        return false;
    }

    // Find longest forked branch 
    dap_list_t *l_branch = a_bcache->forked_branches;
    dap_chain_block_forked_branch_t *l_longest_branch_cache_ptr = l_branch ? (dap_chain_block_forked_branch_t*)l_branch->data : NULL;
    uint64_t l_longest_branch_length = a_main_branch_length;
    while (l_branch){
        uint64_t l_branch_length = (((dap_chain_block_forked_branch_t*)l_branch->data)->forked_branch_atoms)->hh.tbl->num_items;
        if (l_branch_length > l_longest_branch_length){
            l_longest_branch_length = l_branch_length;
            l_longest_branch_cache_ptr = (dap_chain_block_forked_branch_t*)l_branch->data;
        }
        l_branch = l_branch->next;
    }

    if (a_main_branch_length < l_longest_branch_length){
        dap_list_t *l_reverted_blocks_list= NULL;
        uint64_t l_reverted_blocks_cnt = 0;
        uint64_t l_main_blocks_cnt = 0;

        log_it(L_INFO,"Found new longest branch. Start switching.");
        // Switch branches
        dap_chain_block_forked_branch_atoms_table_t *l_new_forked_branch = NULL;
        // First we must save all atoms from main branch into new forked branch
        unsigned l_curr_index;
        dap_chain_block_cache_t *l_atom = NULL;
        for (l_atom = a_bcache->hh.next, l_curr_index = 0; 
            a_main_branch_length > l_curr_index && l_atom; l_curr_index++){
                dap_chain_block_forked_branch_atoms_table_t *l_new_item = DAP_NEW_Z(dap_chain_block_forked_branch_atoms_table_t);
                l_new_item->block_cache = l_atom;
                l_new_item->block_hash = l_atom->block_hash;
                HASH_ADD(hh, l_new_forked_branch, block_hash, sizeof(dap_hash_fast_t), l_new_item);
                l_reverted_blocks_cnt++;
                dap_hash_fast_t *l_reverted_block_hash = DAP_DUP_SIZE(&l_atom->block_hash, sizeof(l_atom->block_hash));
                l_reverted_blocks_list = dap_list_prepend(l_reverted_blocks_list, l_reverted_block_hash);
                l_atom = l_atom->hh.next;
        }
        // Next we must to remove all blocks from main branch and delete all datums in this atoms from storages
        unsigned l_new_forked_branch_len = HASH_COUNT(l_new_forked_branch);
        for (l_curr_index = 0; l_curr_index < l_new_forked_branch_len; ++l_curr_index) {
            dap_chain_block_cache_t *l_curr_atom = HASH_LAST(PVT(l_blocks)->blocks);
            s_delete_atom_datums(l_blocks, l_curr_atom);
            --PVT(l_blocks)->blocks_count;
            HASH_DEL(PVT(l_blocks)->blocks, l_curr_atom);
            HASH_DELETE(hh2, PVT(l_blocks)->blocks_num, l_curr_atom);
            dap_time_t l_prev_block_timestamp = l_curr_atom->hh.prev ? ((dap_chain_block_cache_t *)l_curr_atom->hh.prev)->block->hdr.ts_created : 0;
            dap_chain_atom_remove_notify(a_blocks->chain, l_curr_atom->block->hdr.cell_id, l_prev_block_timestamp);
        }

        // Next we add all atoms from new main branch into blockchain 
        // and their datums into storages and remove old HT with former forked atoms
        dap_chain_block_forked_branch_atoms_table_t *new_main_branch = l_longest_branch_cache_ptr->forked_branch_atoms,
                                                    *l_temp = NULL, *l_item = NULL;

        HASH_ITER(hh, new_main_branch, l_item, l_temp) {
            dap_chain_block_cache_t *l_curr_atom = l_item->block_cache;
            ++PVT(l_blocks)->blocks_count;
            HASH_ADD(hh, PVT(l_blocks)->blocks, block_hash, sizeof(l_curr_atom->block_hash), l_curr_atom);
            HASH_ADD_BYHASHVALUE(hh2, PVT(l_blocks)->blocks_num, block_number, sizeof(l_curr_atom->block_number), l_curr_atom->block_number, l_curr_atom);
            debug_if(s_debug_more, L_DEBUG, "Verified atom %p: ACCEPTED", l_curr_atom);
            s_add_atom_datums(l_blocks, l_curr_atom);
            dap_chain_atom_notify(a_blocks->chain, l_curr_atom->block->hdr.cell_id, &l_curr_atom->block_hash, (byte_t*)l_curr_atom->block, l_curr_atom->block_size, l_curr_atom->block->hdr.ts_created);
            HASH_DEL(new_main_branch, l_item);
            l_main_blocks_cnt++;
        }
        // Notify about branch switching
        for (dap_list_t *l_temp = s_fork_resolved_notificators; l_temp; l_temp = l_temp->next){
            dap_chain_block_fork_resolved_notificator_t *l_notificator = (dap_chain_block_fork_resolved_notificator_t*)l_temp->data;
            l_notificator->callback(l_blocks->chain, a_bcache->block_hash, l_reverted_blocks_list, l_reverted_blocks_cnt, l_main_blocks_cnt, l_notificator->arg);
        }

        dap_list_free_full(l_reverted_blocks_list, NULL);
        // Next we save pointer to new forked branch (former main branch) instead of it
        l_longest_branch_cache_ptr->forked_branch_atoms = l_new_forked_branch;
        return true;
    }
    return false;
}

/**
 * @brief s_callback_atom_add
 * @details Accept new atom in blockchain
 * @param a_chain
 * @param a_atom
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_verify_res_t s_callback_atom_add(dap_chain_t * a_chain, dap_chain_atom_ptr_t a_atom , size_t a_atom_size, dap_hash_fast_t *a_atom_hash, bool a_atom_new)
{
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_block_t * l_block = (dap_chain_block_t *) a_atom;

    dap_chain_hash_fast_t l_block_hash = *a_atom_hash;

    dap_chain_block_cache_t * l_block_cache = NULL;

    dap_chain_atom_verify_res_t ret = s_callback_atom_verify(a_chain, a_atom, a_atom_size, &l_block_hash);
    dap_hash_t *l_prev_hash_meta_data = (dap_hash_t *)dap_chain_block_meta_get(l_block, a_atom_size, DAP_CHAIN_BLOCK_META_PREV);
    dap_hash_t l_block_prev_hash = l_prev_hash_meta_data ? *l_prev_hash_meta_data : (dap_hash_t){};

    switch (ret) {
    case ATOM_ACCEPT:{
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
#ifndef DAP_CHAIN_BLOCKS_TEST
        assert(l_net);
        if ( !dap_chain_net_get_load_mode(l_net) ) {
            int l_err = dap_chain_atom_save(a_chain, l_block->hdr.cell_id, a_atom, a_atom_size, a_atom_new ? &l_block_hash : NULL, (char**)&l_block);
            if (l_err) {
                log_it(L_ERROR, "Can't save atom to file, code %d", l_err);
                return ATOM_REJECT;
            }
        }
#endif
        if (!( l_block_cache = dap_chain_block_cache_new(&l_block_hash, l_block, a_atom_size, PVT(l_blocks)->blocks_count + 1, !a_chain->is_mapped) )) {
            log_it(L_ERROR, "Block %s is corrupted!", l_block_cache->block_hash_str);
            return dap_chain_net_get_load_mode(l_net) ? ATOM_CORRUPTED : ATOM_REJECT;
        }
        debug_if(s_debug_more, L_DEBUG, "... new block %s", l_block_cache->block_hash_str);

        int err = pthread_rwlock_wrlock(&PVT(l_blocks)->rwlock);
        assert(!err);
        if (!l_block_cache->is_genesis) {
            dap_chain_block_cache_t *l_last_block = HASH_LAST(PVT(l_blocks)->blocks);
            if (l_last_block && dap_hash_fast_compare(&l_last_block->block_hash, &l_block_prev_hash)){
                ++PVT(l_blocks)->blocks_count;
                HASH_ADD(hh, PVT(l_blocks)->blocks, block_hash, sizeof(l_block_cache->block_hash), l_block_cache);
                HASH_ADD_BYHASHVALUE(hh2, PVT(l_blocks)->blocks_num, block_number, sizeof(l_block_cache->block_number), l_block_cache->block_number, l_block_cache);
                debug_if(s_debug_more, L_DEBUG, "Verified atom %p: ACCEPTED", a_atom);
                s_add_atom_datums(l_blocks, l_block_cache);
                dap_chain_atom_notify(a_chain, l_block->hdr.cell_id, &l_block_cache->block_hash, (byte_t*)l_block, a_atom_size, l_block->hdr.ts_created);
                dap_chain_atom_add_from_threshold(a_chain);
                pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);

                dap_chain_block_cache_t *l_bcache_last = HASH_LAST(PVT(l_blocks)->blocks);
                // Send it to notificator listeners
#ifndef DAP_CHAIN_BLOCKS_TEST
                if (!dap_chain_net_get_load_mode(l_net)) {
#endif
                    dap_list_t *l_iter;
                    DL_FOREACH(a_chain->atom_confirmed_notifiers, l_iter) {
                        dap_chain_atom_confirmed_notifier_t *l_notifier = (dap_chain_atom_confirmed_notifier_t*)l_iter->data;
                        dap_chain_block_cache_t *l_tmp = l_bcache_last;
                        int l_checked_atoms_cnt = l_notifier->block_notify_cnt != 0 ? l_notifier->block_notify_cnt : PVT(l_blocks)->block_confirm_cnt;
                        for (; l_tmp && l_checked_atoms_cnt; l_tmp = l_tmp->hh.prev, l_checked_atoms_cnt--);
                        if (l_checked_atoms_cnt == 0 && l_tmp) {
                            l_notifier->callback(l_notifier->arg, a_chain, a_chain->active_cell_id, &l_tmp->block_hash, (void*)l_tmp->block, l_tmp->block_size, l_tmp->block->hdr.ts_created);
#ifndef DAP_CHAIN_BLOCKS_TEST
                            for (size_t i = 0; i < l_tmp->datum_count; i++)
                                dap_ledger_tx_clear_colour(l_net->pub.ledger, l_tmp->datum_hash + i);
#endif
                        }
                    }    
#ifndef DAP_CHAIN_BLOCKS_TEST
                }
#endif
                return ATOM_ACCEPT;
            }
            for (size_t i = 0; i < PVT(l_blocks)->forked_br_cnt; i++){
                dap_chain_block_forked_branch_t *l_cur_branch = PVT(l_blocks)->forked_branches[i];
                dap_chain_block_forked_branch_atoms_table_t *l_last = HASH_LAST(l_cur_branch->forked_branch_atoms);
                if(!l_last){
                    continue;
                }

                if (dap_hash_fast_compare(&l_last->block_hash, &l_block_prev_hash)){
                    dap_chain_block_forked_branch_atoms_table_t *l_new_item = DAP_NEW_Z(dap_chain_block_forked_branch_atoms_table_t);
                    l_new_item->block_cache = l_block_cache;
                    l_new_item->block_hash = l_block_cache->block_hash;
                    l_block_cache->block_number = l_last->block_cache->block_number + 1;
                    HASH_ADD(hh, l_cur_branch->forked_branch_atoms, block_hash, sizeof(dap_hash_fast_t), l_new_item);
                    uint64_t l_main_branch_length = PVT(l_blocks)->blocks_count - l_cur_branch->connected_block->block_number;
                    if ( s_select_longest_branch(l_blocks, l_cur_branch->connected_block, l_main_branch_length) ) {
                        dap_chain_block_cache_t *l_bcache_last = HASH_LAST(PVT(l_blocks)->blocks);
                        // Send it to notificator listeners
#ifndef DAP_CHAIN_BLOCKS_TEST
                        if (!dap_chain_net_get_load_mode( dap_chain_net_by_id(a_chain->net_id))){
#endif
                            dap_list_t *l_iter;
                            DL_FOREACH(a_chain->atom_confirmed_notifiers, l_iter) {
                                dap_chain_atom_confirmed_notifier_t *l_notifier = (dap_chain_atom_confirmed_notifier_t*)l_iter->data;
                                dap_chain_block_cache_t *l_tmp = l_bcache_last;
                                int l_checked_atoms_cnt = l_notifier->block_notify_cnt != 0 ? l_notifier->block_notify_cnt : PVT(l_blocks)->block_confirm_cnt;
                                for (; l_tmp && l_checked_atoms_cnt; l_tmp = l_tmp->hh.prev, l_checked_atoms_cnt--);
                                if (l_checked_atoms_cnt == 0 && l_tmp)
                                    l_notifier->callback(l_notifier->arg, a_chain, a_chain->active_cell_id, &l_tmp->block_hash, (void*)l_tmp->block, l_tmp->block_size, l_tmp->block->hdr.ts_created);
                            }    
#ifndef DAP_CHAIN_BLOCKS_TEST
                        }
#endif
                    }
                    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
                    debug_if(s_debug_more, L_DEBUG, "Verified atom %p: ACCEPTED to a forked branch.", a_atom);
                    return ATOM_FORK;
                }
            }

        } else { // Block is genesis

            uint8_t *l_generation_meta = dap_chain_block_meta_get(l_block, a_atom_size, DAP_CHAIN_BLOCK_META_GENERATION);
            uint16_t l_generation = l_generation_meta ? *(uint16_t *)l_generation_meta : 0;
            if (l_generation && a_chain->generation < l_generation) {
                pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
                dap_hash_fast_t *l_hardfork_decree_hash = (dap_hash_fast_t *)dap_chain_block_meta_get(l_block, a_atom_size, DAP_CHAIN_BLOCK_META_LINK);
                if (!l_hardfork_decree_hash) {
                    log_it(L_ERROR, "Can't find hardfork decree hash in candidate block meta");
                    return ATOM_REJECT;
                }
                a_chain->generation++;
                dap_ledger_anchor_purge(l_net->pub.ledger, a_chain->id);
                dap_ledger_tx_purge(l_net->pub.ledger, false);
                dap_chain_srv_purge_all(a_chain->net_id);
                dap_chain_purge(a_chain);
                l_net->pub.ledger->is_hardfork_state = true;
                if (dap_chain_net_srv_stake_hardfork_data_import(a_chain->net_id, l_hardfork_decree_hash)) { // True import
                    log_it(L_ERROR, "Can't accept hardfork genesis block %s: error in hardfork data restoring", dap_hash_fast_to_str_static(a_atom_hash));
                    return ATOM_REJECT;
                }
                pthread_rwlock_wrlock(&PVT(l_blocks)->rwlock);
            }
            HASH_ADD(hh, PVT(l_blocks)->blocks, block_hash, sizeof(l_block_cache->block_hash), l_block_cache);
            HASH_ADD_BYHASHVALUE(hh2, PVT(l_blocks)->blocks_num, block_number, sizeof(l_block_cache->block_number), l_block_cache->block_number, l_block_cache);
            ++PVT(l_blocks)->blocks_count;
            debug_if(s_debug_more, L_DEBUG, "Verified genesis atom %p: ACCEPTED", a_atom);
            s_add_atom_datums(l_blocks, l_block_cache);
            dap_chain_atom_notify(a_chain, l_block->hdr.cell_id, &l_block_cache->block_hash, (byte_t*)l_block, a_atom_size, l_block->hdr.ts_created);
            dap_chain_atom_add_from_threshold(a_chain);
            pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
            return ret;
        }

        DAP_DELETE(l_block_cache);
        pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
        debug_if(s_debug_more, L_DEBUG, "Verified atom %p: REJECTED", a_atom);
        return ATOM_REJECT;
    }
    case ATOM_MOVE_TO_THRESHOLD:
        // TODO: reimplement and enable threshold for blocks
/*      {
            debug_if(s_debug_more, L_DEBUG, "Verified atom %p: THRESHOLDED", a_atom);
            break;
        }
*/
        ret = ATOM_REJECT;
    case ATOM_REJECT:
        debug_if(s_debug_more, L_DEBUG, "Verified atom %p with hash %s: REJECTED", a_atom, dap_chain_hash_fast_to_str_static(&l_block_hash));
        break;
    case ATOM_FORK:{
#ifndef DAP_CHAIN_BLOCKS_TEST
        if ( !dap_chain_net_get_load_mode( dap_chain_net_by_id(a_chain->net_id)) ) {
            int l_err = dap_chain_atom_save(a_chain, l_block->hdr.cell_id, a_atom, a_atom_size, a_atom_new ? &l_block_hash : NULL, (char**)&l_block);
            dap_return_val_if_pass_err(l_err, ATOM_REJECT, "Can't save atom to file, code %d", l_err);
            ret = ATOM_FORK;
        }
#endif
        l_block_cache = dap_chain_block_cache_new(&l_block_hash, l_block, a_atom_size, PVT(l_blocks)->blocks_count + 1, !a_chain->is_mapped);
        if (!l_block_cache) {
            log_it(L_DEBUG, "%s", "... corrupted block");
            return ATOM_REJECT;
        }
        debug_if(s_debug_more, L_DEBUG, "... new block %s", l_block_cache->block_hash_str);
        dap_chain_block_cache_t *l_prev_bcache = NULL, *l_tmp = NULL;
        int err = pthread_rwlock_wrlock(&PVT(l_blocks)->rwlock);
        assert(!err);
        log_it(L_INFO, "New fork. Previous block hash %s, current block hash %s", dap_chain_hash_fast_to_str_static(&l_block_prev_hash),
                                                                                    l_block_cache->block_hash_str);
        HASH_FIND(hh, PVT(l_blocks)->blocks, &l_block_prev_hash, sizeof(dap_hash_fast_t), l_prev_bcache);
        if (l_prev_bcache){
            dap_chain_block_forked_branch_atoms_table_t *l_new_item = DAP_NEW_Z(dap_chain_block_forked_branch_atoms_table_t);
            l_new_item->block_cache = l_block_cache;
            l_new_item->block_hash = l_block_cache->block_hash;
            l_block_cache->block_number = l_prev_bcache->block_number + 1;

            dap_chain_block_forked_branch_t *forked_branch = DAP_NEW_Z(dap_chain_block_forked_branch_t);
            forked_branch->connected_block = l_prev_bcache;
            HASH_ADD(hh, forked_branch->forked_branch_atoms, block_hash, sizeof(dap_hash_fast_t), l_new_item);
            
            PVT(l_blocks)->forked_br_cnt++;
            PVT(l_blocks)->forked_branches = DAP_REALLOC_COUNT(PVT(l_blocks)->forked_branches, PVT(l_blocks)->forked_br_cnt);
            PVT(l_blocks)->forked_branches[PVT(l_blocks)->forked_br_cnt-1] = forked_branch;

            l_prev_bcache->forked_branches = dap_list_append(l_prev_bcache->forked_branches, PVT(l_blocks)->forked_branches[PVT(l_blocks)->forked_br_cnt-1]);
            pthread_rwlock_unlock(& PVT(l_blocks)->rwlock);
            debug_if(s_debug_more, L_DEBUG, "Fork is made successfuly.");
            return ATOM_FORK;
        }

        DAP_DELETE(l_block_cache);
        pthread_rwlock_unlock(& PVT(l_blocks)->rwlock);
        return ATOM_REJECT;
    }
    case ATOM_PASS:
        debug_if(s_debug_more, L_DEBUG, "... %s is already present", dap_chain_hash_fast_to_str_static(&l_block_hash));
        break;
    case ATOM_CORRUPTED:
        debug_if(s_debug_more, L_DEBUG, "... atom is corrupted.%s", dap_chain_net_get_load_mode(dap_chain_net_by_id(a_chain->net_id))
            ? " The file will be truncated!" : "");
    default:
        debug_if(s_debug_more, L_DEBUG, "Unknown verification ret code %d", ret);
        break;
    }
    return ret;
}

/**
 * @brief s_callback_atom_verify
 * @param a_chain
 * @param a_atom
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_verify_res_t s_callback_atom_verify(dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom, size_t a_atom_size, dap_chain_hash_fast_t *a_atom_hash)
{
    dap_return_val_if_fail(a_chain && a_atom && a_atom_size && a_atom_hash, ATOM_REJECT);
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    bool l_load_mode = l_net ? dap_chain_net_get_load_mode(l_net) : false;
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    assert(l_blocks);
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = PVT(l_blocks);
    assert(l_blocks_pvt);
    dap_chain_block_t * l_block = (dap_chain_block_t *)a_atom;
    dap_chain_hash_fast_t l_block_hash = *a_atom_hash;

    if (sizeof(l_block->hdr) >= a_atom_size) {
        log_it(L_WARNING, "Block %s size %zd <= block header size %zd",
                                dap_hash_fast_to_str_static(a_atom_hash), a_atom_size, sizeof(l_block->hdr));
        return l_load_mode ? ATOM_CORRUPTED : ATOM_REJECT;
    }
    size_t l_offset = dap_chain_block_get_sign_offset(l_block, a_atom_size);
    if (!l_offset) {
        log_it(L_WARNING, "Block %s with size %zu parsing error", dap_hash_fast_to_str_static(a_atom_hash), a_atom_size);
        return l_load_mode ? ATOM_CORRUPTED : ATOM_REJECT;
    }
    if ((l_block->hdr.version >= 2 || /* Old bug, crutch for it */ l_block->hdr.meta_n_datum_n_signs_size != l_offset) &&
            l_block->hdr.meta_n_datum_n_signs_size + sizeof(l_block->hdr) != a_atom_size) {
        // Hard accept list
        struct cs_blocks_hal_item *l_hash_found = NULL;
        HASH_FIND(hh, l_blocks_pvt->hal, &l_block_hash, sizeof(l_block_hash), l_hash_found);
        if (!l_hash_found) {
            log_it(L_WARNING, "Incorrect size %zu of block %s, expected %zu", l_block->hdr.meta_n_datum_n_signs_size + sizeof(l_block->hdr),
                                                                    dap_hash_fast_to_str_static(a_atom_hash), a_atom_size);
            return l_load_mode ? ATOM_CORRUPTED : ATOM_REJECT;
        }
    }
    while (sizeof(l_block->hdr) + l_offset + sizeof(dap_sign_t) < a_atom_size) {
        dap_sign_t *l_sign = (dap_sign_t *)((byte_t *)a_atom + sizeof(l_block->hdr) + l_offset);
        size_t l_sign_size = dap_sign_get_size(l_sign);
        if (l_offset + l_sign_size <= l_offset)
            break;
        l_offset += l_sign_size;
    }
    if (l_offset + sizeof(l_block->hdr) != a_atom_size) {
        // Hard accept list
        struct cs_blocks_hal_item *l_hash_found = NULL;
        HASH_FIND(hh, l_blocks_pvt->hal, &l_block_hash, sizeof(l_block_hash), l_hash_found);
        if (!l_hash_found) {
            log_it(L_WARNING, "Incorrect size %zu of block %s, expected %zu", l_offset + sizeof(l_block->hdr),
                                                                    dap_hash_fast_to_str_static(a_atom_hash), a_atom_size);
            return l_load_mode ? ATOM_CORRUPTED : ATOM_REJECT;
        }
    }

    if (!l_block->hdr.ts_created || l_block->hdr.ts_created > dap_time_now() + 600) {
        log_it(L_WARNING, "Incorrect block %s timestamp", dap_hash_fast_to_str_static(a_atom_hash));
        return ATOM_REJECT;
    }

    int ret = ATOM_MOVE_TO_THRESHOLD;
// Parse metadata
    bool l_is_genesis = dap_chain_block_meta_get(l_block, a_atom_size, DAP_CHAIN_BLOCK_META_GENESIS);
    uint8_t *l_generation_meta = dap_chain_block_meta_get(l_block, a_atom_size, DAP_CHAIN_BLOCK_META_GENERATION);
    uint16_t l_generation = l_generation_meta ? *(uint16_t *)l_generation_meta : 0;
    // genesis or seed mode
    if (l_is_genesis) {
#ifndef DAP_CHAIN_BLOCKS_TEST
        if (!a_chain->generation && !l_generation) {
            if (s_seed_mode)
                log_it(L_NOTICE, "Accepting new genesis block %s", dap_hash_fast_to_str_static(a_atom_hash));
            else if (dap_hash_fast_compare(&l_block_hash, &PVT(l_blocks)->static_genesis_block_hash)
                    && !dap_hash_fast_is_blank(&l_block_hash))
                log_it(L_NOTICE, "Accepting static genesis block %s", dap_hash_fast_to_str_static(a_atom_hash));
            else {
                char l_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
                dap_hash_fast_to_str(&PVT(l_blocks)->static_genesis_block_hash, l_hash_str, sizeof(l_hash_str));
                log_it(L_WARNING, "Can't accept genesis block %s: seed mode not enabled or hash mismatch with static genesis block %s in configuration",
                                    dap_hash_fast_to_str_static(a_atom_hash), l_hash_str);
                return ATOM_REJECT;
            }
        } else {
            if (a_chain->generation >= l_generation) {
                log_it(L_ERROR, "Can't accept %s genesis block %s: generation #%hu is too old", l_generation ? "hardfork" : "static",
                                                dap_hash_fast_to_str_static(a_atom_hash), l_generation);
                return ATOM_REJECT;
            }
            if (dap_chain_generation_banned(a_chain, l_generation)) {
                log_it(L_ERROR, "Can't accept hardfork genesis block %s: generation #%hu is banned", dap_hash_fast_to_str_static(a_atom_hash), l_generation);
                return ATOM_REJECT;
            }
            log_it(L_NOTICE, "Accepting hardfork genesis block %s and restore data", dap_hash_fast_to_str_static(a_atom_hash));
            dap_hash_fast_t *l_hardfork_decree_hash = (dap_hash_fast_t *)dap_chain_block_meta_get(l_block, a_atom_size, DAP_CHAIN_BLOCK_META_LINK);
            if (!l_hardfork_decree_hash) {
                log_it(L_ERROR, "Can't find hardfork decree hash in candidate block meta");
                return ATOM_REJECT;
            }
            if (dap_chain_net_srv_stake_switch_table(a_chain->net_id, true)) { // to Sandbox
                log_it(L_ERROR, "Can't accept hardfork genesis block %s: error in switching to sandbox table", dap_hash_fast_to_str_static(a_atom_hash));
                return ATOM_REJECT;
            }
            if (dap_chain_net_srv_stake_hardfork_data_import(a_chain->net_id, l_hardfork_decree_hash)) { // Sandbox
                log_it(L_ERROR, "Can't accept hardfork genesis block %s: error in hardfork data restoring", dap_hash_fast_to_str_static(a_atom_hash));
                return ATOM_REJECT;
            }
        }

#else
        PVT(l_blocks)->genesis_block_hash = *a_atom_hash;
#endif
        ret = ATOM_ACCEPT;
    } else {
        dap_hash_t *l_prev_hash_meta_data = (dap_hash_t *)dap_chain_block_meta_get(l_block, a_atom_size, DAP_CHAIN_BLOCK_META_PREV);
        if (!l_prev_hash_meta_data) {
            log_it(L_WARNING, "Block %s isn't a genesis one but not contains previous block hash in metadata", dap_hash_fast_to_str_static(a_atom_hash));
            return ATOM_REJECT;
        }
        dap_hash_t l_block_prev_hash = *l_prev_hash_meta_data;
        if (s_debug_more) {
            char l_prev_block_hash_str[DAP_HASH_FAST_STR_SIZE];
            dap_hash_fast_to_str(&l_block_prev_hash, l_prev_block_hash_str, DAP_HASH_FAST_STR_SIZE);
            log_it(L_DEBUG, "Verify new block with hash %s. Previous block hash is %s", dap_hash_fast_to_str_static(a_atom_hash), l_prev_block_hash_str);
        }
        dap_chain_block_cache_t *l_bcache_last = HASH_LAST(PVT(l_blocks)->blocks);
        if (l_bcache_last && dap_hash_fast_compare(&l_bcache_last->block_hash, &l_block_prev_hash))
            ret = ATOM_ACCEPT;
        else { // search block and previous block in forked branch
            int err = pthread_rwlock_rdlock(&PVT(l_blocks)->rwlock);
            assert(!err);
            for (size_t i = 0; i < PVT(l_blocks)->forked_br_cnt; i++) {
                dap_chain_block_forked_branch_t *l_cur_branch = PVT(l_blocks)->forked_branches[i];
                dap_chain_block_forked_branch_atoms_table_t *l_item = NULL;
                // Check block already present in forked branch
                HASH_FIND(hh, l_cur_branch->forked_branch_atoms, &l_block_hash, sizeof(dap_hash_fast_t), l_item);
                if (l_item) {
                    debug_if(s_debug_more,L_DEBUG,"%s","Block already exist in forked branch.");
                    ret = ATOM_PASS;
                    break;
                }
                l_item = NULL;
                // Find previous block is last block in current branch
                HASH_FIND(hh, l_cur_branch->forked_branch_atoms, &l_block_prev_hash, sizeof(dap_hash_fast_t), l_item);
                if (!l_item)
                    continue;
                if (l_item->hh.next) {
                    debug_if(s_debug_more,L_DEBUG,"%s","Found previous block in forked branch. Can't add block into branch because previous block is not last in the branch.");
                    ret = ATOM_PASS;
                    break;
                } else {
                    debug_if(s_debug_more,L_DEBUG,"%s","Accept block to a forked branch.");
                    ret = ATOM_ACCEPT;
                    break;
                }
            }
            if (ret == ATOM_MOVE_TO_THRESHOLD) {
                // search block and previous block in main branch
                unsigned l_checked_atoms_cnt = PVT(l_blocks)->block_confirm_cnt;
                for (dap_chain_block_cache_t *l_tmp = l_bcache_last; l_tmp && l_checked_atoms_cnt; l_tmp = l_tmp->hh.prev, l_checked_atoms_cnt--){
                    if(dap_hash_fast_compare(&l_tmp->block_hash, &l_block_hash)){
                        debug_if(s_debug_more,L_DEBUG,"%s","Block is already exist in main branch.");
                        ret = ATOM_PASS;
                        break;
                    }

                    if (dap_hash_fast_compare(&l_tmp->block_hash, &l_block_prev_hash)) {
                        if (l_tmp->hh.next) {
                            debug_if(s_debug_more,L_DEBUG,"%s","New fork!");
                            ret = ATOM_FORK;
                            break;
                        }
                        debug_if(s_debug_more,L_DEBUG,"%s","Accept block to a main branch.");
                        ret = ATOM_ACCEPT;
                        break;
                    }
                }
            }
            pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
        }
    }

    if (ret == ATOM_ACCEPT || (!l_generation && ret == ATOM_FORK)) {
        // 2nd level consensus
        if (l_blocks->callback_block_verify && l_blocks->callback_block_verify(l_blocks, l_block, a_atom_hash, /* Old bug, crutch for it */ a_atom_size)) {
            // Hard accept list
            struct cs_blocks_hal_item *l_hash_found = NULL;
            HASH_FIND(hh, l_blocks_pvt->hal, &l_block_hash, sizeof(l_block_hash), l_hash_found);
            if (!l_hash_found) {
                log_it(L_WARNING, "Block %s rejected by block verificator", dap_hash_fast_to_str_static(a_atom_hash));
                ret = ATOM_REJECT;
            }
        }
    } else if (ret == ATOM_MOVE_TO_THRESHOLD) {
        debug_if(s_debug_more,L_DEBUG,"%s","Can't find valid previous block in chain or forked branches.");
        ret = ATOM_REJECT;
    }
    if (l_is_genesis && l_generation && a_chain->generation < l_generation &&
            dap_chain_net_srv_stake_switch_table(a_chain->net_id, false)) {  // return to main
        log_it(L_CRITICAL, "Can't accept hardfork genesis block %s: error in switching to main table", dap_hash_fast_to_str_static(a_atom_hash));
        ret = ATOM_REJECT;
    }
    return ret;
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
 * @brief s_callback_atom_iter_find_by_hash
 * @param a_atom_iter
 * @param a_atom_hash
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_callback_atom_iter_find_by_hash(dap_chain_atom_iter_t * a_atom_iter, dap_chain_hash_fast_t *a_atom_hash,
                                                              size_t * a_atom_size)
{
    assert(a_atom_iter);
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_atom_iter->chain);
    dap_chain_block_cache_t *l_block_cache = dap_chain_block_cache_get_by_hash(l_blocks, a_atom_hash);
    a_atom_iter->cur_item = l_block_cache;
    if (l_block_cache) {
        a_atom_iter->cur        = l_block_cache->block;
        a_atom_iter->cur_size   = l_block_cache->block_size;
        a_atom_iter->cur_hash   = &l_block_cache->block_hash;
        a_atom_iter->cur_num    = l_block_cache->block_number;
    } else
        *a_atom_iter = (dap_chain_atom_iter_t) { .chain = a_atom_iter->chain,
                                                 .cell_id = a_atom_iter->cell_id };
    if (a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;
    return a_atom_iter->cur;
}

static dap_chain_atom_ptr_t s_callback_atom_iter_get_by_num(dap_chain_atom_iter_t *a_atom_iter, uint64_t a_atom_num)
{
    assert(a_atom_iter);
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_atom_iter->chain);
    dap_chain_block_cache_t *l_block_cache = NULL;
    int err = pthread_rwlock_rdlock(&PVT(l_blocks)->rwlock);
    assert(!err);
    for (l_block_cache = PVT(l_blocks)->blocks; l_block_cache; l_block_cache = l_block_cache->hh.next)
        if (l_block_cache->block_number == a_atom_num)
            break;
    a_atom_iter->cur_item = l_block_cache;
    if (l_block_cache) {
        a_atom_iter->cur        = l_block_cache->block;
        a_atom_iter->cur_size   = l_block_cache->block_size;
        a_atom_iter->cur_hash   = &l_block_cache->block_hash;
        a_atom_iter->cur_num    = l_block_cache->block_number;
    } else
        *a_atom_iter = (dap_chain_atom_iter_t) { .chain = a_atom_iter->chain,
                                                 .cell_id = a_atom_iter->cell_id };
    pthread_rwlock_unlock(&PVT(l_blocks)->rwlock);
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

static json_object *s_callback_atom_dump_json(json_object **a_arr_out, dap_chain_t *a_chain, dap_chain_atom_ptr_t a_atom_ptr, size_t a_atom_size, const char *a_hash_out_type) {
   dap_chain_block_t *l_block = (dap_chain_block_t *) a_atom_ptr;
    json_object *l_obj_ret = json_object_new_object();
    char l_time_buf[DAP_TIME_STR_SIZE], l_hexbuf[32] = { '\0' };
    snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%04X", l_block->hdr.version);

    json_object_object_add(l_obj_ret, "version", json_object_new_string(l_hexbuf));
    snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%016"DAP_UINT64_FORMAT_X"", l_block->hdr.cell_id.uint64);
    json_object_object_add(l_obj_ret, "cell_id", json_object_new_string(l_hexbuf));
    snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%016"DAP_UINT64_FORMAT_X"", l_block->hdr.chain_id.uint64);
    json_object_object_add(l_obj_ret, "chain_id", json_object_new_string(l_hexbuf));
    dap_time_to_str_rfc822(l_time_buf, DAP_TIME_STR_SIZE, l_block->hdr.ts_created);
    json_object_object_add(l_obj_ret, "ts_created", json_object_new_string(l_time_buf));

    // Dump Metadata
    size_t l_offset = 0;
    json_object *l_jobj_metadata = json_object_new_array();
    for (uint32_t i = 0; i < l_block->hdr.meta_count; i++) {
        json_object *json_obj_meta = json_object_new_object();
        dap_chain_block_meta_t *l_meta = (dap_chain_block_meta_t *) (l_block->meta_n_datum_n_sign + l_offset);
        switch (l_meta->hdr.type) {
            case DAP_CHAIN_BLOCK_META_GENESIS:
                json_object_object_add(json_obj_meta, "GENESIS", json_object_new_string("GENESIS"));
                break;
            case DAP_CHAIN_BLOCK_META_PREV:
                s_cli_meta_hash_print(json_obj_meta, "PREV", l_meta, a_hash_out_type);
                break;
            case DAP_CHAIN_BLOCK_META_ANCHOR:
                s_cli_meta_hash_print(json_obj_meta, "ANCHOR", l_meta, a_hash_out_type);
                break;
            case DAP_CHAIN_BLOCK_META_LINK:
                s_cli_meta_hash_print(json_obj_meta, "LINK", l_meta, a_hash_out_type);
                break;
            case DAP_CHAIN_BLOCK_META_NONCE:
                s_cli_meta_hex_print(json_obj_meta, "NONCE", l_meta);
                break;
            case DAP_CHAIN_BLOCK_META_NONCE2:
                s_cli_meta_hex_print(json_obj_meta, "NONCE2", l_meta);
                break;
            default: {
                snprintf(l_hexbuf, sizeof(l_hexbuf), "0x%0X", i);
                json_object_object_add(json_obj_meta, "#", json_object_new_string(l_hexbuf));
                int l_len = l_meta->hdr.data_size * 2 + 5;
                char *l_data_hex = DAP_NEW_STACK_SIZE(char, l_len);
                strcpy(l_data_hex, "0x");
                dap_bin2hex(l_data_hex + 2, l_meta->data, l_meta->hdr.data_size);
                json_object_object_add(json_obj_meta, "data_hex", json_object_new_string(l_data_hex));
            }
        }
        json_object_array_add(l_jobj_metadata, json_obj_meta);
        l_offset += sizeof(l_meta->hdr) + l_meta->hdr.data_size;
    }
    json_object_object_add(l_obj_ret, "metadata", l_jobj_metadata);
    json_object *l_jobj_datums = json_object_new_array();
    for (uint16_t i = 0; i < l_block->hdr.datum_count; i++) {
        dap_chain_datum_t *l_datum = (dap_chain_datum_t*)(l_block->meta_n_datum_n_sign + l_offset);
        json_object *l_jobj_datum = json_object_new_object();
        size_t l_datum_size =  dap_chain_datum_size(l_datum);
        json_object_object_add(l_jobj_datum, "datum_size",json_object_new_uint64(l_datum_size));
        if (l_datum_size < sizeof (l_datum->header) ){
            dap_json_rpc_error_add(*a_arr_out, DAP_CHAIN_NODE_CLI_COM_BLOCK_DATUM_SIZE_ERR, "ERROR: datum size %zu is smaller than header size %zu",l_datum_size,
                                    sizeof (l_datum->header));
            break;
        }
        // Nested datums
        snprintf(l_hexbuf, sizeof(l_hexbuf),"0x%02X",l_datum->header.version_id);
        json_object_object_add(l_jobj_datum, "version",json_object_new_string(l_hexbuf));
        const char * l_datum_type_str = "UNKNOWN";
        DAP_DATUM_TYPE_STR(l_datum->header.type_id, l_datum_type_str);
        json_object_object_add(l_jobj_datum, "type_id",json_object_new_string(l_datum_type_str));
        dap_time_to_str_rfc822(l_time_buf, DAP_TIME_STR_SIZE, l_datum->header.ts_create);
        json_object_object_add(l_jobj_datum, "ts_create",json_object_new_string(l_time_buf));
        json_object_object_add(l_jobj_datum, "data_size",json_object_new_int(l_datum->header.data_size));
        dap_chain_datum_dump_json(*a_arr_out, l_jobj_datum,l_datum, a_hash_out_type, a_chain->net_id, true);
        json_object_array_add(l_jobj_datums, l_jobj_datum);
        l_offset += l_datum_size;
    }
    json_object_object_add(l_obj_ret, "datums", l_jobj_datums);
    json_object *l_jobj_signatures = json_object_new_array();
    size_t l_block_signs = dap_chain_block_get_signs_count(l_block, a_atom_size);
    for (uint32_t i = 0; i < l_block_signs; i++) {
        json_object* json_obj_sign = json_object_new_object();
        dap_sign_t * l_sign = dap_chain_block_sign_get(l_block, dap_chain_block_get_size(l_block), i);
        size_t l_sign_size = dap_sign_get_size(l_sign);
        dap_chain_hash_fast_t l_pkey_hash;
        dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
        const char *l_hash_str = !dap_strcmp(a_hash_out_type, "base58") ?
                dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash) :
                dap_chain_hash_fast_to_str_static(&l_pkey_hash);
        json_object_object_add(json_obj_sign, "type",json_object_new_string(dap_sign_type_to_str( l_sign->header.type )));
        json_object_object_add(json_obj_sign, "size",json_object_new_uint64(l_sign_size));
        json_object_object_add(json_obj_sign, "pkey_hash",json_object_new_string(l_hash_str));
        json_object_array_add(l_jobj_signatures, json_obj_sign);
    }
    json_object_object_add(l_obj_ret, "signatures", l_jobj_signatures);
    return l_obj_ret;
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
 * @brief s_callback_atom_iter_create
 * @param a_chain
 * @return
 */
static dap_chain_atom_iter_t *s_callback_atom_iter_create(dap_chain_t *a_chain, dap_chain_cell_id_t a_cell_id, dap_hash_fast_t *a_hash_from)
{
    dap_chain_atom_iter_t * l_atom_iter = DAP_NEW_Z(dap_chain_atom_iter_t);
    if (!l_atom_iter) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_atom_iter->chain = a_chain;
    l_atom_iter->cell_id = a_cell_id;
    if (a_hash_from)
        s_callback_atom_iter_find_by_hash(l_atom_iter, a_hash_from, NULL);
    return l_atom_iter;
}

/**
 * @brief s_callback_atom_iter_get
 * @param a_atom_iter
 * @param a_operation
 * @param a_atom_size
 * @return
 */
static dap_chain_atom_ptr_t s_callback_atom_iter_get(dap_chain_atom_iter_t *a_atom_iter, dap_chain_iter_op_t a_operation, size_t *a_atom_size)
{
    dap_return_val_if_fail(a_atom_iter, NULL);
    dap_chain_cs_blocks_t * l_blocks = DAP_CHAIN_CS_BLOCKS(a_atom_iter->chain);
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = l_blocks ? PVT(l_blocks) : NULL;
    dap_chain_atom_ptr_t l_ret = NULL;
    if (!l_blocks_pvt) {
        log_it(L_ERROR, "l_blocks_pvt is NULL");
        return NULL;
    }
    int err = pthread_rwlock_rdlock(&l_blocks_pvt->rwlock);
    assert(!err);
    switch (a_operation) {
    case DAP_CHAIN_ITER_OP_FIRST:
        a_atom_iter->cur_item = l_blocks_pvt->blocks;
        break;
    case DAP_CHAIN_ITER_OP_LAST:
        a_atom_iter->cur_item = HASH_LAST(l_blocks_pvt->blocks);
        break;
    case DAP_CHAIN_ITER_OP_NEXT:
        if (a_atom_iter->cur_item)
            a_atom_iter->cur_item = ((dap_chain_block_cache_t *)a_atom_iter->cur_item)->hh.next;
        break;
    case DAP_CHAIN_ITER_OP_PREV:
        if (a_atom_iter->cur_item)
            a_atom_iter->cur_item = ((dap_chain_block_cache_t *)a_atom_iter->cur_item)->hh.prev;
        break;
    }
    if (a_atom_iter->cur_item) {
        dap_chain_block_cache_t *l_item = a_atom_iter->cur_item;
        a_atom_iter->cur        = l_item->block;
        a_atom_iter->cur_size   = l_item->block_size;
        a_atom_iter->cur_hash   = &l_item->block_hash;
        a_atom_iter->cur_num    = l_item->block_number;
        a_atom_iter->cur_ts     = l_item->ts_created;
    } else 
        *a_atom_iter = (dap_chain_atom_iter_t) { .chain = a_atom_iter->chain,
                                                 .cell_id = a_atom_iter->cell_id };
    pthread_rwlock_unlock(&l_blocks_pvt->rwlock);
    if (a_atom_size)
        *a_atom_size = a_atom_iter->cur_size;

    return a_atom_iter->cur;
}

/**
 * @brief s_callback_atom_iter_delete
 * @param a_atom_iter
 */
static void s_callback_atom_iter_delete(dap_chain_atom_iter_t * a_atom_iter)
{
    DAP_DELETE(a_atom_iter);
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
    dap_return_val_if_fail(a_atom_iter, NULL);
    assert(a_links_size);
    assert(a_links_size_ptr);
    if (!a_atom_iter->cur_item) {
        return NULL;
    }
    dap_chain_block_cache_t * l_block_cache =(dap_chain_block_cache_t *) a_atom_iter->cur_item;
    if (!l_block_cache->links_hash_count) {
        return NULL;
    }
    *a_links_size_ptr = DAP_NEW_Z_COUNT_RET_VAL_IF_FAIL(size_t, l_block_cache->links_hash_count, NULL);
    *a_links_size = l_block_cache->links_hash_count;
    dap_chain_atom_ptr_t *l_ret = DAP_NEW_Z_SIZE(dap_chain_atom_ptr_t, l_block_cache->links_hash_count * sizeof(dap_chain_atom_ptr_t));
    for (size_t i = 0; i < l_block_cache->links_hash_count; ++i){
        dap_chain_cs_blocks_t *l_cs_blocks = DAP_CHAIN_CS_BLOCKS(a_atom_iter->chain);
        dap_chain_block_cache_t *l_link = dap_chain_block_cache_get_by_hash(l_cs_blocks, &l_block_cache->links_hash[i]);
        assert(l_link);
        if (!l_link) {
            DAP_DEL_Z(a_links_size_ptr);
            DAP_DEL_Z(l_ret);
            return NULL;
        }
        (*a_links_size_ptr)[i] = l_link->block_size;
        l_ret[i] = l_link->block;
    }
    return l_ret;
}

static dap_chain_datum_iter_t *s_chain_callback_datum_iter_create(dap_chain_t *a_chain)
{
    dap_chain_datum_iter_t *l_ret = DAP_NEW_Z(dap_chain_datum_iter_t);
    if (!l_ret) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
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
        a_datum_iter->action = a_datum_index->action;
        a_datum_iter->uid = a_datum_index->service_uid;    
        a_datum_iter->token_ticker = dap_strcmp(a_datum_index->token_ticker, "") ? a_datum_index->token_ticker : NULL;
    } else {
        a_datum_iter->cur = NULL;
        a_datum_iter->cur_hash = NULL;
        a_datum_iter->cur_atom_hash = NULL;
        a_datum_iter->cur_size = 0;
        a_datum_iter->ret_code = 0;
        a_datum_iter->token_ticker = NULL;
        a_datum_iter->action = 0;
        a_datum_iter->uid.uint64 = 0;
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

static dap_chain_datum_t *s_chain_callback_datum_iter_get_last(dap_chain_datum_iter_t *a_datum_iter)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_CHAIN_CS_BLOCKS(a_datum_iter->chain);
    pthread_rwlock_rdlock(&PVT(l_cs_blocks)->datums_rwlock);
    //dap_chain_block_datum_index_t *l_datum_index = PVT(l_cs_blocks)->datum_index;
    dap_chain_block_datum_index_t *l_datum_index = HASH_LAST(PVT(l_cs_blocks)->datum_index);    
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

static dap_chain_datum_t *s_chain_callback_datum_iter_get_prev(dap_chain_datum_iter_t *a_datum_iter)
{
    dap_chain_cs_blocks_t * l_cs_blocks = DAP_CHAIN_CS_BLOCKS(a_datum_iter->chain);
    pthread_rwlock_rdlock(&PVT(l_cs_blocks)->datums_rwlock);
    dap_chain_block_datum_index_t *l_datum_index = a_datum_iter->cur_item;
    if (l_datum_index)
        l_datum_index = l_datum_index->hh.prev;
    s_datum_iter_fill(a_datum_iter, l_datum_index);
    pthread_rwlock_unlock(&PVT(l_cs_blocks)->datums_rwlock);
    return a_datum_iter->cur;
}


static dap_chain_block_t *s_new_block_move(dap_chain_cs_blocks_t *a_blocks, size_t *a_new_block_size)
{
    size_t l_ret_size = 0;
    dap_chain_block_t *l_ret = NULL;
    dap_chain_cs_blocks_pvt_t *l_blocks_pvt = PVT(a_blocks);
    int err = pthread_rwlock_wrlock(&l_blocks_pvt->rwlock);
    assert(!err);
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
    // dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);

    size_t l_datum_processed = 0;
    int err = pthread_rwlock_wrlock(&l_blocks_pvt->rwlock);
    assert(!err);
#ifdef DAP_TPS_TEST
    log_it(L_TPS, "Start tps %zu datums add", a_datums_count);
#endif
    for (size_t i = 0; i < a_datums_count; ++i) {
        dap_chain_datum_t *l_datum = a_datums[i];
        size_t l_datum_size = dap_chain_datum_size(l_datum);
        if (!l_datum_size) {
            log_it(L_WARNING, "Empty datum"); /* How might it be? */
            continue;
        }
        if (l_blocks->block_new_size + l_datum_size > DAP_CHAIN_CANDIDATE_MAX_SIZE) {
            log_it(L_DEBUG, "Maximum size exeeded, %zu > %d", l_blocks->block_new_size + l_datum_size, DAP_CHAIN_CANDIDATE_MAX_SIZE);
            break;
        }
        if (!l_blocks->block_new) {
            dap_chain_block_cache_t *l_bcache_last = HASH_LAST(l_blocks_pvt->blocks);
            if (a_chain->hardfork_data && l_bcache_last->block->hdr.cell_id.uint64 != c_dap_chain_cell_id_hardfork.uint64)
                l_bcache_last = NULL;       // Workaround until separate cells storages will be realized
            l_blocks->block_new = dap_chain_block_new(l_bcache_last ? &l_bcache_last->block_hash : NULL, &l_blocks->block_new_size);
            l_blocks->block_new->hdr.cell_id = a_chain->hardfork_data ? c_dap_chain_cell_id_hardfork : c_dap_chain_cell_id_null;
            l_blocks->block_new->hdr.chain_id.uint64 = l_blocks->chain->id.uint64;
        }
        l_blocks->block_new_size = dap_chain_block_datum_add(&l_blocks->block_new, l_blocks->block_new_size, l_datum, l_datum_size);
        l_datum_processed++;
    }
#ifdef DAP_TPS_TEST
    log_it(L_TPS, "Finish tps %zu datums add", a_datums_count);
#endif
    pthread_rwlock_unlock(&l_blocks_pvt->rwlock);
    return l_datum_processed;
}

/**
 * @brief s_callback_count_atom Gets the number of blocks
 * @param a_chain Chain object
 * @return size_t
 */
static uint64_t s_callback_count_atom(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    assert(l_blocks && l_blocks->chain == a_chain);
    uint64_t l_ret = 0;
    l_ret = PVT(l_blocks)->blocks_count;
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
    int err = pthread_rwlock_rdlock(&PVT(l_blocks)->rwlock);
    assert(!err);
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

static const dap_time_t s_block_timediff_unit_size = 60;

static uint256_t s_callback_calc_reward(dap_chain_t *a_chain, dap_hash_fast_t *a_block_hash, dap_pkey_t *a_block_sign_pkey)
{
    uint256_t l_ret = uint256_0;
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_block_cache_t *l_block_cache = NULL;
    HASH_FIND(hh, PVT(l_blocks)->blocks, a_block_hash, sizeof(*a_block_hash), l_block_cache);
    if (!l_block_cache)
        return l_ret;
    const dap_chain_block_t *l_block = l_block_cache->block;
    size_t l_block_size = l_block_cache->block_size;
    if (!dap_chain_block_sign_match_pkey(l_block, l_block_size, a_block_sign_pkey))
        return l_ret;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    if (!l_net) {
        log_it(L_ERROR, "Invalid chain object");
        return l_ret;
    }
    dap_time_t l_block_time = l_block->hdr.ts_created;
    if (l_block_time < DAP_REWARD_INIT_TIMESTAMP) {
        log_it(L_WARNING, "Reward is not set for this block");
        return l_ret;
    }
    l_ret = dap_chain_net_get_reward(l_net, l_block_cache->block_number);
    size_t l_signs_count = l_block_cache->sign_count;
    if (l_block_cache->is_genesis) {
        DIV_256(l_ret, GET_256_FROM_64(l_signs_count), &l_ret);
        return l_ret;
    }
    dap_hash_fast_t l_prev_block_hash = l_block_cache->prev_hash;
    l_block_cache = NULL;
    HASH_FIND(hh, PVT(l_blocks)->blocks, &l_prev_block_hash, sizeof(l_prev_block_hash), l_block_cache);
    if (!l_block_cache) {
        log_it(L_ERROR, "l_block_cache is NULL");
        return l_ret;
    }
    l_block = l_block_cache->block;
    if (!l_block) {
        log_it(L_ERROR, "l_block is NULL");
        return l_ret;
    }
    assert(l_block);
    dap_time_t l_cur_time = dap_max(l_block->hdr.ts_created, DAP_REWARD_INIT_TIMESTAMP);
    if ( l_block_time > l_cur_time ) {
        dap_time_t l_time_diff = l_block_time - l_cur_time;
        if (MULT_256_256(l_ret, GET_256_FROM_64(l_time_diff), &l_ret))
            return log_it(L_ERROR, "Integer overflow while multiplication execution to calculate final reward"), uint256_0;
    }
    DIV_256(l_ret, GET_256_FROM_64(s_block_timediff_unit_size * l_signs_count), &l_ret);
    return l_ret;
}

/**
 * @brief s_fee_verificator_callback
 * @param a_ledger
 * @param a_tx_out_hash
 * @param a_cond
 * @param a_tx_in
 * @param a_owner
 * @return
 */
static int s_fee_verificator_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t UNUSED_ARG *a_tx_in_hash,
                                      dap_chain_tx_out_cond_t UNUSED_ARG *a_cond, bool a_owner)
{
    dap_chain_net_t *l_net = a_ledger->net;
    assert(l_net);
    dap_chain_t *l_chain;
    DL_FOREACH(l_net->pub.chains, l_chain) {
        if (!l_chain->callback_block_find_by_tx_hash)
            continue;
        dap_chain_tx_in_cond_t *l_tx_in_cond = (dap_chain_tx_in_cond_t*)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_IN_COND, NULL);
        if (!l_tx_in_cond)
            return -1;
        if (dap_hash_fast_is_blank(&l_tx_in_cond->header.tx_prev_hash))
            return -2;
        size_t l_block_size = 0;
        dap_chain_block_t *l_block = (dap_chain_block_t *)l_chain->callback_block_find_by_tx_hash(
                                                    l_chain, &l_tx_in_cond->header.tx_prev_hash, &l_block_size);
        if (!l_block)
            continue;
        dap_sign_t *l_sign_block = dap_chain_block_sign_get(l_block, l_block_size, 0);
        if (!l_sign_block)
            return -3;

        // TX sign is already verified, just compare pkeys
        dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)dap_chain_datum_tx_item_get(a_tx_in, NULL, NULL, TX_ITEM_TYPE_SIG, NULL);
        dap_sign_t *l_sign_tx = dap_chain_datum_tx_item_sig_get_sign(l_tx_sig);
        return dap_sign_compare_pkeys(l_sign_block, l_sign_tx) ? 0 : -5;
    }
    return -4;
}


static int s_fee_stack_verificator_callback(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx_in, dap_hash_fast_t UNUSED_ARG *a_tx_in_hash,
                                      dap_chain_tx_out_cond_t UNUSED_ARG *a_cond, bool a_owner)
{
    return a_owner ? 0 : -1;
}



static uint64_t s_callback_count_txs(dap_chain_t *a_chain)
{
    return PVT(DAP_CHAIN_CS_BLOCKS(a_chain))->tx_count;
}


static dap_list_t *s_callback_get_txs(dap_chain_t *a_chain, size_t a_count, size_t a_page, bool a_reverse)
{
    UNUSED(a_reverse); // TODO
    size_t l_count = s_callback_count_txs(a_chain);
    size_t l_offset = a_count * a_page;
    if (l_offset > l_count)
        return NULL;
    if (a_page < 2)
        l_offset = 0;
    dap_list_t *l_list = NULL;
    size_t l_counter = 0;
    size_t l_end = l_offset + a_count;
    for (dap_chain_block_datum_index_t *it = PVT(DAP_CHAIN_CS_BLOCKS(a_chain))->datum_index;
                it && l_counter < l_end;
                it = it->hh.next) {
        dap_chain_datum_t *l_datum = it->block_cache->datum[it->datum_index];
        if (l_datum->header.type_id == DAP_CHAIN_DATUM_TX && l_counter++ >= l_offset) {
            dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_datum->data;
            l_list = dap_list_append(l_list, l_tx);
        }
    }
    return l_list;
}

static int s_compare_fees(dap_chain_cs_blocks_hardfork_fees_t *a_list1, dap_chain_cs_blocks_hardfork_fees_t *a_list2)
{
    return !dap_sign_compare_pkeys(a_list1->owner_sign, a_list2->owner_sign);
}

static int s_aggregate_fees(dap_chain_cs_blocks_hardfork_fees_t **a_out_list, dap_chain_block_autocollect_type_t a_type, dap_sign_t *a_sign, uint256_t a_value)
{
    dap_chain_cs_blocks_hardfork_fees_t l_new_fee = { .owner_sign = a_sign };
    dap_chain_cs_blocks_hardfork_fees_t *l_exist = NULL;
    DL_SEARCH(*a_out_list, l_exist, &l_new_fee, s_compare_fees);
    if (!l_exist) {
        l_exist = DAP_DUP(&l_new_fee);
        if (!l_exist) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return -1;
        }
        DL_APPEND(*a_out_list, l_exist);
    }
    switch (a_type) {
    case DAP_CHAIN_BLOCK_COLLECT_FEES:
        if (SUM_256_256(l_exist->fees_n_rewards_sum, a_value, &l_exist->fees_n_rewards_sum)) {
            log_it(L_ERROR, "Integer overflow of hardfork aggregated data for not withdrowed fees");
            return -2;
        } break;
    case DAP_CHAIN_BLOCK_COLLECT_REWARDS:
        if (SUM_256_256(l_exist->fees_n_rewards_sum, a_value, &l_exist->fees_n_rewards_sum)) {
            log_it(L_ERROR, "Integer overflow of hardfork aggregated data for not withdrowed rewards");
            return -2;
        } break;
    default:
        log_it(L_ERROR, "Illegal block autocollect type %d", a_type);
        return -3;
    }
    return 0;
}

dap_chain_cs_blocks_hardfork_fees_t *dap_chain_cs_blocks_fees_aggregate(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_hardfork_fees_t *ret = NULL;
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    for (dap_chain_block_cache_t *l_block_cache = PVT(l_blocks)->blocks; l_block_cache; l_block_cache = l_block_cache->hh.next) {
        dap_time_t l_ts = l_block_cache->block->hdr.ts_created;
        for (size_t i = 0; i < l_block_cache->sign_count; i++) {
            dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, i);
            if (i == 0) {
                for (size_t j = 0; j < l_block_cache->datum_count; j++) {
                    if (l_block_cache->datum[j]->header.type_id != DAP_CHAIN_DATUM_TX)
                        continue;
                    dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t *)l_block_cache->datum[j]->data;
                    int l_out_idx_tmp = 0;
                    dap_chain_tx_out_cond_t *l_cond = dap_chain_datum_tx_out_cond_get(l_tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_FEE, &l_out_idx_tmp);
                    if (!l_cond)
                        continue;
                    if (!dap_ledger_tx_hash_is_used_out_item(l_net->pub.ledger, l_block_cache->datum_hash + j, l_out_idx_tmp, NULL))
                        s_aggregate_fees(&ret, DAP_CHAIN_BLOCK_COLLECT_FEES, l_sign, l_cond->header.value);
                }
            }
            if (l_ts < DAP_REWARD_INIT_TIMESTAMP)
                break;
            //dap_chain_cs_esbocs_get_precached_key_hash(l_sign);
            dap_hash_fast_t l_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
            if (dap_ledger_is_used_reward(l_net->pub.ledger, &l_block_cache->block_hash, &l_pkey_hash))
                continue;
            dap_pkey_t *l_sign_pkey = dap_pkey_get_from_sign(l_sign);
            uint256_t l_reward_value = s_callback_calc_reward(a_chain, &l_block_cache->block_hash, l_sign_pkey);
            DAP_DELETE(l_sign_pkey);
            s_aggregate_fees(&ret, DAP_CHAIN_BLOCK_COLLECT_REWARDS, l_sign, l_reward_value);
        }
    }
    return ret;
}

/**
 * @brief search pkey in block signs
 * @param a_chain chain to search
 * @param a_pkey_hash - pkey hash
 * @return pointer to dap_pkey_t if finded, other - NULL
 */
dap_pkey_t *dap_chain_cs_blocks_get_pkey_by_hash(dap_chain_net_t *a_net, dap_hash_fast_t *a_pkey_hash)
{
    dap_return_val_if_pass(!a_pkey_hash, NULL);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_TX);
    if (!l_chain || !DAP_CHAIN_CS_BLOCKS(l_chain) || !PVT(DAP_CHAIN_CS_BLOCKS(l_chain)))
        return NULL;
    dap_pkey_t *l_ret = NULL;
    pthread_rwlock_rdlock(&PVT(DAP_CHAIN_CS_BLOCKS(l_chain))->rwlock);
    for (dap_chain_block_cache_t *l_block_cache = PVT(DAP_CHAIN_CS_BLOCKS(l_chain))->blocks; l_block_cache; l_block_cache = l_block_cache->hh.next) {
        for (size_t i = 0; i < l_block_cache->sign_count; i++) {
            dap_sign_t *l_sign = dap_chain_block_sign_get(l_block_cache->block, l_block_cache->block_size, i);
            if (dap_sign_is_use_pkey_hash(l_sign))
                continue;
            dap_chain_hash_fast_t l_sign_hash = {};
            dap_sign_get_pkey_hash(l_sign, &l_sign_hash);
            if(!memcmp(&l_sign_hash, a_pkey_hash, sizeof(dap_chain_hash_fast_t))) {
                l_ret = dap_pkey_get_from_sign(l_sign);
                break;
            }
        }
    }
    pthread_rwlock_unlock(&PVT(DAP_CHAIN_CS_BLOCKS(l_chain))->rwlock);
    return l_ret;
}

