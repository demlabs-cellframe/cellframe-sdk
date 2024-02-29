/*
* Authors:
* Roman Khlopkov <roman.khlopkov@demlabs.net>
* Cellframe       https://cellframe.net
* DeM Labs Inc.   https://demlabs.net
* Copyright  (c) 2017-2023
* All rights reserved.

This file is part of CellFrame SDK the open source project

CellFrame SDK is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

CellFrame SDK is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "dap_common.h"
#include "utlist.h"
#include "dap_timerfd.h"
#include "rand/dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_stream_ch_chain_voting.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_ledger.h"
#include "dap_chain_node_cli.h"
#include "dap_chain_node_cli_cmd.h"

#define LOG_TAG "dap_chain_cs_esbocs"

enum s_esbocs_session_state {
    DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_START,
    DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC,
    DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_SIGNS,
    DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH,
    DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_VOTING,
    DAP_CHAIN_ESBOCS_SESSION_STATE_PREVIOUS     // fictive sate to change back
};

static dap_list_t *s_validator_check(dap_chain_addr_t *a_addr, dap_list_t *a_validators);
static void s_session_state_change(dap_chain_esbocs_session_t *a_session, enum s_esbocs_session_state a_new_state, dap_time_t a_time);
static void s_session_packet_in(void *a_arg, dap_chain_node_addr_t *a_sender_node_addr, dap_chain_node_addr_t *a_receiver_node_addr,
                                dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size);
static void s_session_round_clear(dap_chain_esbocs_session_t *a_session);
static void s_session_round_new(dap_chain_esbocs_session_t *a_session);
static bool s_session_candidate_to_chain(
            dap_chain_esbocs_session_t *a_session, dap_chain_hash_fast_t *a_candidate_hash,
                            dap_chain_block_t *a_candidate, size_t a_candidate_size);
static void s_session_candidate_submit(dap_chain_esbocs_session_t *a_session);
static void s_session_candidate_verify(dap_chain_esbocs_session_t *a_session, dap_chain_block_t *a_candidate,
                                       size_t a_candidate_size, dap_hash_fast_t *a_candidate_hash);
static void s_session_candidate_precommit(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_message_t *a_message);
static void s_session_round_finish(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_store_t *l_store);

static bool s_session_timer(void *a_arg);
static void s_message_send(dap_chain_esbocs_session_t *a_session, uint8_t a_message_type, dap_hash_fast_t *a_block_hash,
                                    const void *a_data, size_t a_data_size, dap_list_t *a_validators);
static void s_message_chain_add(dap_chain_esbocs_session_t * a_session,
                                dap_chain_esbocs_message_t * a_message,
                                size_t a_message_size,
                                dap_chain_hash_fast_t *a_message_hash,
                                dap_chain_addr_t *a_signing_addr);

static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks);
static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg);
static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size);
static int s_callback_block_verify(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);
static uint256_t s_callback_get_minimum_fee(dap_chain_t *a_chain);
static dap_enc_key_t *s_callback_get_sign_key(dap_chain_t *a_chain);
static void s_callback_set_min_validators_count(dap_chain_t *a_chain, uint16_t a_new_value);
static void s_db_change_notifier(dap_store_obj_t *a_obj, void * a_arg);

static int s_cli_esbocs(int a_argc, char **a_argv, void **a_str_reply);

DAP_STATIC_INLINE const char *s_voting_msg_type_to_str(uint8_t a_type)
{
    switch (a_type) {
    case DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC: return "START_SYNC";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_SUBMIT: return "SUBMIT";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE: return "APPROVE";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_REJECT: return "REJECT";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_COMMIT_SIGN: return "COMMIT_SIGN";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_PRE_COMMIT: return "PRE_COMMIT";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_DIRECTIVE: return "DIRECTIVE";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR: return "VOTE_FOR";
    case DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST: return "VOTE_AGAINST";
    default: return "UNKNOWN";
    }
}

DAP_STATIC_INLINE uint32_t s_directive_calc_size(uint8_t a_type)
{
    uint32_t l_ret = sizeof(dap_chain_esbocs_directive_t);
    switch (a_type) {
    case DAP_CHAIN_ESBOCS_DIRECTIVE_KICK:
    case DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT:
        l_ret += sizeof(dap_tsd_t) + sizeof(dap_chain_addr_t);
    default:;
    }
    return l_ret;
}

DAP_STATIC_INLINE char *s_get_penalty_group(dap_chain_net_id_t a_net_id)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    return dap_strdup_printf(DAP_CHAIN_ESBOCS_GDB_GROUPS_PREFIX".%s.penalty", l_net->pub.gdb_groups_prefix);
}

DAP_STATIC_INLINE size_t s_get_esbocs_message_size(dap_chain_esbocs_message_t *a_message)
{
    return sizeof(*a_message) + a_message->hdr.sign_size + a_message->hdr.message_size;
}

static dap_chain_esbocs_session_t *s_session_items;

typedef struct dap_chain_esbocs_pvt {
    // Base params
    dap_enc_key_t *blocks_sign_key;
    dap_hash_fast_t candidate_hash;
    // Validators section
    bool poa_mode;
    uint16_t min_validators_count;
    uint16_t start_validators_min;
    // Debug flag
    bool debug;
    // Emergancy mode with signing by current online validators only
    bool emergency_mode;
    // Round params
    uint16_t new_round_delay;
    uint16_t round_start_sync_timeout;
    uint16_t round_attempts_max;
    uint16_t round_attempt_timeout;
    // PoA section
    dap_list_t *poa_validators;
    // Fee & autocollect params
    dap_chain_addr_t *collecting_addr;
    uint256_t minimum_fee;
    uint256_t collecting_level;
    dap_pkey_t *block_sign_pkey;
} dap_chain_esbocs_pvt_t;

#define PVT(a) ((dap_chain_esbocs_pvt_t *)a->_pvt)

struct sync_params {
    uint64_t attempt;
    dap_global_db_driver_hash_t db_hash;
} DAP_ALIGN_PACKED;

DAP_STATIC_INLINE uint16_t s_get_round_skip_timeout(dap_chain_esbocs_session_t *a_session)
{
    return PVT(a_session->esbocs)->round_attempt_timeout * 6 * PVT(a_session->esbocs)->round_attempts_max;
}

int dap_chain_cs_esbocs_init() {
    dap_stream_ch_chain_voting_init();
    dap_chain_cs_add("esbocs", s_callback_new);
    dap_cli_server_cmd_add ("esbocs", s_cli_esbocs, "ESBOCS commands",
        "esbocs min_validators_count set -net <net_name> -chain <chain_name> -cert <poa_cert_name> -val_count <value>"
            "\tSets minimum validators count for ESBOCS consensus\n"
        "esbocs min_validators_count print -net <net_name> -chain <chain_name>"
            "\tShow minimum validators count for ESBOCS consensus\n\n");
    return 0;
}

void dap_chain_cs_esbocs_deinit(void)
{
}

static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg)
{
    dap_chain_cs_type_create("blocks", a_chain, a_chain_cfg);

    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    int l_ret = 0;
    dap_chain_esbocs_t *l_esbocs = NULL;
    DAP_NEW_Z_RET_VAL(l_esbocs, dap_chain_esbocs_t, -5, NULL);

    l_esbocs->blocks = l_blocks;   
    l_blocks->_inheritor = l_esbocs;
    l_blocks->callback_delete = s_callback_delete;
    l_blocks->callback_block_verify = s_callback_block_verify;
    l_blocks->callback_block_sign = s_callback_block_sign;

    l_esbocs->chain = a_chain;
    a_chain->callback_set_min_validators_count = s_callback_set_min_validators_count;
    a_chain->callback_get_minimum_fee = s_callback_get_minimum_fee;
    a_chain->callback_get_signing_certificate = s_callback_get_sign_key;

    l_esbocs->_pvt = DAP_NEW_Z(dap_chain_esbocs_pvt_t);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);
    if (!l_esbocs_pvt) {
        log_it(L_CRITICAL, "Memory allocation error");
        l_ret = - 5;
        goto lb_err;
    }
    l_esbocs_pvt->debug = dap_config_get_item_bool_default(a_chain_cfg, "esbocs", "consensus_debug", false);
    l_esbocs_pvt->emergency_mode = dap_config_get_item_bool_default(a_chain_cfg, "esbocs", "emergency_mode", false);
    l_esbocs_pvt->poa_mode = dap_config_get_item_bool_default(a_chain_cfg, "esbocs", "poa_mode", false);
    l_esbocs_pvt->round_start_sync_timeout = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "round_start_sync_timeout", 15);
    l_esbocs_pvt->new_round_delay = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "new_round_delay", 10);
    l_esbocs_pvt->round_attempts_max = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "round_attempts_max", 4);
    l_esbocs_pvt->round_attempt_timeout = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "round_attempt_timeout", 10);

    l_esbocs_pvt->start_validators_min = l_esbocs_pvt->min_validators_count =
            dap_config_get_item_uint16(a_chain_cfg, "esbocs", "min_validators_count");
    if (!l_esbocs_pvt->min_validators_count) {
        l_ret = -1;
        goto lb_err;
    }

    const char *l_auth_certs_prefix = dap_config_get_item_str(a_chain_cfg, "esbocs", "auth_certs_prefix");
    uint16_t l_node_addrs_count;
    char **l_addrs = dap_config_get_array_str(a_chain_cfg, "esbocs", "validators_addrs", &l_node_addrs_count);
    uint16_t l_auth_certs_count = l_node_addrs_count;
    if (l_auth_certs_count < l_esbocs_pvt->min_validators_count) {
        l_ret = -2;
        goto lb_err;
    }
    char l_cert_name[512];
    dap_cert_t *l_cert_cur;
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    for (size_t i = 0; i < l_auth_certs_count; i++) {
        snprintf(l_cert_name, sizeof(l_cert_name), "%s.%zu", l_auth_certs_prefix, i);
        if ((l_cert_cur = dap_cert_find_by_name(l_cert_name)) == NULL) {
            snprintf(l_cert_name, sizeof(l_cert_name), "%s.%zu.pub", l_auth_certs_prefix, i);
            if ((l_cert_cur = dap_cert_find_by_name(l_cert_name)) == NULL) {
                log_it(L_ERROR, "Can't find cert \"%s\"", l_cert_name);
                l_ret = -3;
                goto lb_err;
            }
        }
        dap_chain_addr_t l_signing_addr;
        log_it(L_NOTICE, "Initialized auth cert \"%s\"", l_cert_name);
        dap_chain_addr_fill_from_key(&l_signing_addr, l_cert_cur->enc_key, a_chain->net_id);
        dap_chain_node_addr_t l_signer_node_addr;
        if (dap_chain_node_addr_from_str(&l_signer_node_addr, l_addrs[i])) {
            log_it(L_ERROR, "Wrong address format, should be like 0123::4567::89AB::CDEF");
            l_ret = -4;
            goto lb_err;
        }

        dap_chain_esbocs_validator_t *l_validator = DAP_NEW_Z(dap_chain_esbocs_validator_t);
        if (!l_validator) {
        log_it(L_CRITICAL, "Memory allocation error");
            l_ret = - 5;
            goto lb_err;
        }
        l_validator->signing_addr = l_signing_addr;
        l_validator->node_addr = l_signer_node_addr;
        l_validator->weight = uint256_1;
        l_esbocs_pvt->poa_validators = dap_list_append(l_esbocs_pvt->poa_validators, l_validator);
        char *l_signer_addr = dap_chain_hash_fast_to_str_static(&l_signing_addr.data.hash_fast);
        log_it(L_MSG, "add validator addr "NODE_ADDR_FP_STR", signing addr %s", NODE_ADDR_FP_ARGS_S(l_signer_node_addr), l_signer_addr);

        if (!l_esbocs_pvt->poa_mode) { // auth certs in PoA mode will be first PoS validators keys
            dap_hash_fast_t l_stake_tx_hash = {};
            uint256_t l_weight = dap_chain_net_srv_stake_get_allowed_min_value();
            dap_chain_net_srv_stake_key_delegate(l_net, &l_signing_addr, &l_stake_tx_hash,
                                                 l_weight, &l_signer_node_addr);
        }
    }
    // Preset reward for block signs, before first reward decree
    const char *l_preset_reward_str = dap_config_get_item_str(a_chain_cfg, "esbocs", "preset_reward");
    if (l_preset_reward_str) {
        uint256_t l_preset_reward = dap_chain_balance_scan(l_preset_reward_str);
        if (!IS_ZERO_256(l_preset_reward))
            dap_chain_net_add_reward(l_net, l_preset_reward, 0);
    }
    l_blocks->chain->callback_created = s_callback_created;

    return 0;

lb_err:
    dap_list_free_full(l_esbocs_pvt->poa_validators, NULL);
    DAP_DEL_MULTY(l_esbocs_pvt, l_esbocs);
    l_blocks->_inheritor = NULL;
    l_blocks->callback_delete = NULL;
    l_blocks->callback_block_verify = NULL;
    return l_ret;
}

static void s_check_db_collect_callback(dap_global_db_instance_t UNUSED_ARG *a_dbi,
                                        int a_rc, const char *a_group, const char *a_key, const void *a_value,
                                        const size_t a_value_size, dap_nanotime_t UNUSED_ARG a_value_ts,
                                        bool UNUSED_ARG a_is_pinned, void *a_arg)
{
    bool l_fee_collect = strstr(a_group, "fee");
    if (a_rc != DAP_GLOBAL_DB_RC_SUCCESS) {
        log_it(L_ERROR, "Can't add block with hash %s to autocollect %s list", a_key, l_fee_collect ? "fee" : "reward");
        return;
    }
    log_it(L_NOTICE, "The block %s was successfully added to autocollect %s list", a_key, l_fee_collect ? "fee" : "reward");
    assert(a_value_size == sizeof(uint256_t));
    dap_chain_esbocs_session_t *l_session = a_arg;
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_session->esbocs);
    bool l_level_reached = false;
    uint256_t l_value_total = uint256_0;
    size_t l_objs_count = 0;
    dap_global_db_obj_t *l_objs = dap_global_db_get_all_sync(a_group, &l_objs_count);
    if (l_objs_count >= 10) {
        for (size_t i = 0; i < l_objs_count; i++) {
            SUM_256_256(l_value_total, *(uint256_t*)l_objs[i].value, &l_value_total);
            if (compare256(l_value_total, l_esbocs_pvt->collecting_level) >= 0) {
                l_level_reached = true;
                break;
            }
        }
    }
    if (l_level_reached) {
        dap_list_t *l_block_list = NULL;
        for (size_t i = 0; i < l_objs_count; i++) {
            dap_hash_fast_t block_hash;
            dap_chain_hash_fast_from_hex_str(l_objs[i].key, &block_hash);
            l_block_list = dap_list_append(l_block_list, DAP_DUP(&block_hash));
        }
        dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_session->chain);
        char *l_tx_hash_str = l_fee_collect ?
                    dap_chain_mempool_tx_coll_fee_create(l_blocks, l_esbocs_pvt->blocks_sign_key,
                                     l_esbocs_pvt->collecting_addr, l_block_list, l_esbocs_pvt->minimum_fee, "hex")
                  :
                    dap_chain_mempool_tx_reward_create(l_blocks, l_esbocs_pvt->blocks_sign_key,
                                     l_esbocs_pvt->collecting_addr, l_block_list, l_esbocs_pvt->minimum_fee, "hex");
        if (l_tx_hash_str) {
            log_it(L_NOTICE, "%s collect transaction successfully created, hash = %s",
                            l_fee_collect ? "Fee" : "Reward", l_tx_hash_str);
            DAP_DELETE(l_tx_hash_str);
        } else
            log_it(L_ERROR, "%s collect transaction creation error", l_fee_collect ? "Fee" : "Reward");
        dap_global_db_del_sync(a_group, NULL);
    }
    dap_global_db_objs_delete(l_objs, l_objs_count);
}

static void s_new_atom_notifier(void *a_arg, dap_chain_t *a_chain, dap_chain_cell_id_t a_id,
                                void *a_atom, size_t a_atom_size)
{
    dap_chain_esbocs_session_t *l_session = a_arg;
    assert(l_session->chain == a_chain);
    pthread_mutex_lock(&l_session->mutex);
    dap_chain_hash_fast_t l_last_block_hash;
    dap_chain_get_atom_last_hash(l_session->chain, &l_last_block_hash, a_id);
    if (!dap_hash_fast_compare(&l_last_block_hash, &l_session->cur_round.last_block_hash))
        s_session_round_new(l_session);
    pthread_mutex_unlock(&l_session->mutex);
    if (!PVT(l_session->esbocs)->collecting_addr)
        return;
    dap_sign_t *l_sign = dap_chain_block_sign_get(a_atom, a_atom_size, 0);
    if (dap_pkey_match_sign(PVT(l_session->esbocs)->block_sign_pkey, l_sign)) {
        dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
        dap_chain_block_cache_t *l_block_cache = dap_chain_block_cache_get_by_hash(l_blocks, &l_last_block_hash);
        assert(l_block_cache);
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
        assert(l_net);
        uint256_t l_value_fee = uint256_0;
        dap_list_t *l_list_used_out = dap_chain_block_get_list_tx_cond_outs_with_val(
                                        l_net->pub.ledger, l_block_cache, &l_value_fee);
        if (!IS_ZERO_256(l_value_fee)) {
            char *l_fee_group = dap_chain_cs_blocks_get_fee_group(a_chain->net_name);
            dap_global_db_set(l_fee_group, l_block_cache->block_hash_str, &l_value_fee, sizeof(l_value_fee),
                              false, s_check_db_collect_callback, l_session);
            DAP_DELETE(l_fee_group);
        }
        dap_list_free_full(l_list_used_out, NULL);
    }
    if (dap_chain_block_sign_match_pkey(a_atom, a_atom_size, PVT(l_session->esbocs)->block_sign_pkey)) {
        dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
        dap_chain_block_cache_t *l_block_cache = dap_chain_block_cache_get_by_hash(l_blocks, &l_last_block_hash);
        assert(l_block_cache);
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
        assert(l_net);
        if (!dap_ledger_is_used_reward(l_net->pub.ledger, &l_block_cache->block_hash,
                                      &l_session->my_signing_addr.data.hash_fast)) {
            uint256_t l_value_reward = a_chain->callback_calc_reward(a_chain, &l_block_cache->block_hash,
                                                                     PVT(l_session->esbocs)->block_sign_pkey);
            if (!IS_ZERO_256(l_value_reward)) {
                char *l_reward_group = dap_chain_cs_blocks_get_reward_group(a_chain->net_name);
                dap_global_db_set(l_reward_group, l_block_cache->block_hash_str, &l_value_reward, sizeof(l_value_reward),
                                  false, s_check_db_collect_callback, l_session);
                DAP_DELETE(l_reward_group);
            }
        }
    }
}

bool dap_chain_esbocs_get_autocollect_status(dap_chain_net_id_t a_net_id)
{
    dap_chain_esbocs_session_t *l_session;
    DL_FOREACH(s_session_items, l_session) {
        if (l_session->chain->net_id.uint64 == a_net_id.uint64) {
            if (l_session->esbocs && l_session->esbocs->_pvt && PVT(l_session->esbocs)->collecting_addr &&
                    !dap_chain_addr_is_blank(PVT(l_session->esbocs)->collecting_addr))
                return true;
            else
                return false;
        }
    }
    return false;
}

static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);

    l_esbocs_pvt->collecting_addr = dap_chain_addr_from_str(dap_config_get_item_str(a_chain_net_cfg, "esbocs", "fee_addr"));
    l_esbocs_pvt->collecting_level = dap_chain_coins_to_balance(dap_config_get_item_str_default(a_chain_net_cfg, "esbocs", "set_collect_fee", "10.0"));

    dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators(a_chain->net_id, false);
    for (dap_list_t *it = l_validators; it; it = it->next) {
        dap_stream_node_addr_t *l_addr = &((dap_chain_net_srv_stake_item_t *)it->data)->node_addr;
        dap_chain_net_add_validator_to_clusters(a_chain, l_addr);
    }
    dap_chain_esbocs_session_t *l_session = NULL;
    DAP_NEW_Z_RET_VAL(l_session, dap_chain_esbocs_session_t, -8, NULL);
    l_session->chain = a_chain;
    l_session->esbocs = l_esbocs;
    l_esbocs->session = l_session;
    DL_APPEND(s_session_items, l_session);
    log_it(L_INFO, "Init ESBOCS session for net:%s, chain:%s", a_chain->net_name, a_chain->name);

    const char *l_sign_cert_str = NULL;
    if( (l_sign_cert_str = dap_config_get_item_str(a_chain_net_cfg, "esbocs", "blocks-sign-cert")) ) {
        dap_cert_t *l_sign_cert = dap_cert_find_by_name(l_sign_cert_str);
        if (l_sign_cert == NULL) {
            log_it(L_ERROR, "Can't load sign certificate, name \"%s\" is wrong", l_sign_cert_str);
            dap_list_free_full(l_validators, NULL);
            return -1;
        } else if (l_sign_cert->enc_key->priv_key_data) {
            l_esbocs_pvt->blocks_sign_key = l_sign_cert->enc_key;
            log_it(L_INFO, "Loaded \"%s\" certificate for net %s to sign ESBOCS blocks", l_sign_cert_str, a_chain->net_name);
        } else {
            log_it(L_ERROR, "Certificate \"%s\" has no private key", l_sign_cert_str);
            dap_list_free_full(l_validators, NULL);
            return -2;
        }
    } else {
        log_it(L_NOTICE, "No sign certificate provided for net %s, can't sign any blocks. This node can't be a consensus validator", a_chain->net_name);
        dap_list_free_full(l_validators, NULL);
        return -3;
    }
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net);
    if (l_role.enums > NODE_ROLE_MASTER) {
        log_it(L_NOTICE, "Node role is lower than master role, so this node can't be a consensus validator");
        dap_list_free_full(l_validators, NULL);
        return -5;
    }
    dap_chain_addr_t l_my_signing_addr;
    dap_chain_addr_fill_from_key(&l_my_signing_addr, l_esbocs_pvt->blocks_sign_key, a_chain->net_id);
    if (!l_esbocs_pvt->poa_mode) {
        if (!dap_chain_net_srv_stake_key_delegated(&l_my_signing_addr)) {
            log_it(L_WARNING, "Signing key is not delegated by stake service. Switch off validator mode");
            dap_list_free_full(l_validators, NULL);
            return -6;
        }
    } else {
        if (!s_validator_check(&l_my_signing_addr, l_esbocs_pvt->poa_validators)) {
            log_it(L_WARNING, "Signing key is not present in PoA certs list. Switch off validator mode");
            dap_list_free_full(l_validators, NULL);
            return -7;
        }
    }

    l_session->my_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
    l_session->my_signing_addr = l_my_signing_addr;
    char *l_sync_group = s_get_penalty_group(l_net->pub.id);
    l_session->db_cluster = dap_global_db_cluster_add(dap_global_db_instance_get_default(), NULL,
                                                      dap_cluster_guuid_compose(l_net->pub.id.uint64, DAP_CHAIN_CLUSTER_ID_ESBOCS),
                                                      l_sync_group, 72 * 3600, true,
                                                      DAP_GDB_MEMBER_ROLE_NOBODY, DAP_CLUSTER_ROLE_AUTONOMIC);
    DAP_DELETE(l_sync_group);
    dap_global_db_cluster_add_notify_callback(l_session->db_cluster, s_db_change_notifier, l_session);

    for (dap_list_t *it = l_validators; it; it = it->next) {
        dap_stream_node_addr_t *l_addr = &((dap_chain_net_srv_stake_item_t *)it->data)->node_addr;
        dap_global_db_cluster_member_add(l_session->db_cluster, l_addr, DAP_GDB_MEMBER_ROLE_ROOT);
    }
    dap_list_free_full(l_validators, NULL);

    //Find order minimum fee
    l_esbocs_pvt->block_sign_pkey = dap_pkey_from_enc_key(l_esbocs_pvt->blocks_sign_key);
    char *l_gdb_group_str = dap_chain_net_srv_order_get_gdb_group(l_net);
    size_t l_orders_count = 0;
    dap_global_db_obj_t * l_orders = dap_global_db_get_all_sync(l_gdb_group_str, &l_orders_count);
    DAP_DELETE(l_gdb_group_str);
    dap_chain_net_srv_order_t *l_order_service = NULL;
    for (size_t i = 0; i < l_orders_count; i++) {
        if (l_orders[i].value_len < sizeof(dap_chain_net_srv_order_t)) {
            log_it(L_ERROR, "Too small order %s with size %zu", l_orders[i].key, l_orders[i].value_len);
            continue;
        }
        dap_chain_net_srv_order_t *l_order = (dap_chain_net_srv_order_t *)l_orders[i].value;
        if (l_order->srv_uid.uint64 != DAP_CHAIN_NET_SRV_STAKE_POS_DELEGATE_ID)
            continue;
        dap_sign_t *l_order_sign = (dap_sign_t*)(l_order->ext_n_sign + l_order->ext_size);
        if (!dap_pkey_match_sign(l_esbocs_pvt->block_sign_pkey, l_order_sign))
            continue;
        if (!l_order_service)
            l_order_service = l_order;
        else if (l_order_service->ts_created < l_order->ts_created)
            l_order_service = l_order;
    }
    if (l_order_service)
        l_esbocs_pvt->minimum_fee = l_order_service->price;
    dap_global_db_objs_delete(l_orders, l_orders_count);

    if (IS_ZERO_256(l_esbocs_pvt->minimum_fee)) {
        log_it(L_ERROR, "No valid order found was signed by this validator deledgated key. Switch off validator mode.");
        return -4;
    }
    pthread_mutexattr_t l_mutex_attr;
    pthread_mutexattr_init(&l_mutex_attr);
    pthread_mutexattr_settype(&l_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&l_session->mutex, &l_mutex_attr);
    pthread_mutexattr_destroy(&l_mutex_attr);
    dap_stream_ch_chain_voting_in_callback_add(l_session, s_session_packet_in);
    dap_chain_add_callback_notify(a_chain, s_new_atom_notifier, l_session);
    s_session_round_new(l_session);

    l_session->cs_timer = dap_timerfd_start(1000, s_session_timer, l_session);
    debug_if(l_esbocs_pvt->debug, L_MSG, "Consensus main timer is started");

    DAP_CHAIN_PVT(a_chain)->cs_started = true;
    return 0;
}

bool dap_chain_esbocs_started(dap_chain_net_id_t a_net_id)
{
    dap_chain_esbocs_session_t *l_session;
    DL_FOREACH(s_session_items, l_session)
        if (l_session->chain->net_id.uint64 == a_net_id.uint64)
            return DAP_CHAIN_PVT(l_session->chain)->cs_started;
    return false;
}

dap_pkey_t *dap_chain_esbocs_get_sign_pkey(dap_chain_net_id_t a_net_id)
{
    dap_chain_esbocs_session_t *l_session;
    DL_FOREACH(s_session_items, l_session) {
        if (l_session->chain->net_id.uint64 == a_net_id.uint64 &&
                l_session->esbocs && l_session->esbocs->_pvt)
            return PVT(l_session->esbocs)->block_sign_pkey;
    }
    return NULL;
}

uint256_t dap_chain_esbocs_get_fee(dap_chain_net_id_t a_net_id)
{
    dap_chain_esbocs_session_t *l_session;
    DL_FOREACH(s_session_items, l_session) {
        if (l_session->chain->net_id.uint64 == a_net_id.uint64 &&
                l_session->esbocs && l_session->esbocs->_pvt)
            return PVT(l_session->esbocs)->minimum_fee;
    }
    return uint256_0;
}

void dap_chain_esbocs_stop_timer(dap_chain_net_id_t a_net_id)
{
    dap_chain_esbocs_session_t *l_session;
    DL_FOREACH(s_session_items, l_session) {
        if (l_session->chain->net_id.uint64 == a_net_id.uint64 &&
            l_session->cs_timer){
            log_it(L_INFO, "Stop consensus timer for net: %s, chain: %s", dap_chain_net_by_id(a_net_id)->pub.name, l_session->chain->name);
            dap_timerfd_delete_mt(l_session->cs_timer->worker, l_session->cs_timer->esocket_uuid);
            l_session->cs_timer = NULL;
        }
    }
    dap_stream_ch_chain_voting_close_all_clients(a_net_id);
}

void dap_chain_esbocs_start_timer(dap_chain_net_id_t a_net_id)
{
    dap_chain_esbocs_session_t *l_session;
    DL_FOREACH(s_session_items, l_session) {
        if (l_session->chain->net_id.uint64 == a_net_id.uint64){
            log_it(L_INFO, "Start consensus timer for net: %s, chain: %s", dap_chain_net_by_id(a_net_id)->pub.name, l_session->chain->name);
            l_session->cs_timer = dap_timerfd_start(1000, s_session_timer, l_session);
        }
    }
}

bool dap_chain_esbocs_add_validator_to_clusters(dap_chain_net_id_t a_net_id, dap_stream_node_addr_t *a_validator_addr)
{
    dap_return_val_if_fail(a_validator_addr, -1);
    dap_chain_esbocs_session_t *l_session;
    bool l_ret = false;
    DL_FOREACH(s_session_items, l_session)
        if (l_session->chain->net_id.uint64 == a_net_id.uint64) {
            l_ret = dap_chain_net_add_validator_to_clusters(l_session->chain, a_validator_addr);
            if (l_session->db_cluster)
                l_ret &= (bool)dap_global_db_cluster_member_add(l_session->db_cluster, a_validator_addr, DAP_GDB_MEMBER_ROLE_ROOT);
            return l_ret;
        }
    return NULL;
}

bool dap_chain_esbocs_remove_validator_from_clusters(dap_chain_net_id_t a_net_id, dap_stream_node_addr_t *a_validator_addr)
{
    dap_return_val_if_fail(a_validator_addr, -1);
    dap_chain_esbocs_session_t *l_session;
    bool l_ret = false;
    DL_FOREACH(s_session_items, l_session)
        if (l_session->chain->net_id.uint64 == a_net_id.uint64) {
            l_ret = dap_chain_net_remove_validator_from_clusters(l_session->chain, a_validator_addr);
            if (l_session->db_cluster)
                l_ret &= dap_global_db_cluster_member_delete(l_session->db_cluster, a_validator_addr);
            return l_ret;
        }
    return NULL;
}

static uint256_t s_callback_get_minimum_fee(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);

    return l_esbocs_pvt->minimum_fee;
}

static dap_enc_key_t *s_callback_get_sign_key(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);

    return l_esbocs_pvt->blocks_sign_key;
}

static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks)
{
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(a_blocks);
    dap_enc_key_delete(PVT(l_esbocs)->blocks_sign_key);
    DAP_DEL_MULTY(PVT(l_esbocs)->block_sign_pkey, PVT(l_esbocs)->collecting_addr, l_esbocs->_pvt);
    dap_chain_esbocs_session_t *l_session = l_esbocs->session;
    if (!l_session) {
        log_it(L_INFO, "No session found");
        return;
    }
    pthread_mutex_lock(&l_session->mutex);
    DL_DELETE(s_session_items, l_session);
    dap_timerfd_delete_mt(l_session->cs_timer->worker, l_session->cs_timer->esocket_uuid);
    s_session_round_clear(l_session);
    dap_chain_esbocs_sync_item_t *l_sync_item, *l_sync_tmp;
    HASH_ITER(hh, l_session->sync_items, l_sync_item, l_sync_tmp) {
        HASH_DEL(l_session->sync_items, l_sync_item);
        dap_list_free_full(l_sync_item->messages, NULL);
        DAP_DELETE(l_sync_item);
    }
    dap_chain_esbocs_penalty_item_t *l_pen_item, *l_pen_tmp;
    HASH_ITER(hh, l_session->penalty, l_pen_item, l_pen_tmp) {
        HASH_DEL(l_session->penalty, l_pen_item);
        DAP_DELETE(l_pen_item);
    }
    pthread_mutex_unlock(&l_session->mutex);
    pthread_mutex_destroy(&l_session->mutex);
    DAP_DEL_MULTY(l_session, a_blocks->_inheritor); // a_blocks->_inheritor - l_esbocs
}

static void *s_callback_list_copy(const void *a_validator, UNUSED_ARG void *a_data)
{
    return DAP_DUP((dap_chain_esbocs_validator_t *)a_validator);
}

static void *s_callback_list_form(const void *a_srv_validator, UNUSED_ARG void *a_data)
{
// sanity check
    dap_return_val_if_pass(!a_srv_validator, NULL);
    dap_chain_esbocs_validator_t *l_validator = NULL;
// memory alloc
    DAP_NEW_Z_RET_VAL(l_validator, dap_chain_esbocs_validator_t, NULL, NULL);
// func work
    l_validator->node_addr = ((dap_chain_net_srv_stake_item_t *)a_srv_validator)->node_addr;
    l_validator->signing_addr = ((dap_chain_net_srv_stake_item_t *)a_srv_validator)->signing_addr;
    l_validator->weight = ((dap_chain_net_srv_stake_item_t *)a_srv_validator)->value;
    return l_validator;
}

static void s_callback_set_min_validators_count(dap_chain_t *a_chain, uint16_t a_new_value)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);
    if (a_new_value)
        l_esbocs_pvt->min_validators_count = a_new_value;
    else {
        dap_hash_fast_t l_stake_tx_hash = {};
        dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
        uint256_t l_weight = dap_chain_net_srv_stake_get_allowed_min_value();
        for (dap_list_t *it = l_esbocs_pvt->poa_validators; it; it = it->next) {
            dap_chain_esbocs_validator_t *l_validator = it->data;
            dap_chain_net_srv_stake_key_delegate(l_net, &l_validator->signing_addr, &l_stake_tx_hash,
                                                 l_weight, &l_validator->node_addr);
        }
        l_esbocs_pvt->min_validators_count = l_esbocs_pvt->start_validators_min;
    }
}

static dap_list_t *s_get_validators_list(dap_chain_esbocs_session_t *a_session, uint64_t a_skip_count)
{
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(a_session->esbocs);
    dap_list_t *l_ret = NULL;

    if (!l_esbocs_pvt->poa_mode) {
        dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators(a_session->chain->net_id, true);
        uint16_t l_total_validators_count = dap_list_length(l_validators);
        if (l_total_validators_count < l_esbocs_pvt->min_validators_count) {
            log_it(L_MSG, "Can't start new round. Totally active validators count %hu is below minimum count %hu",
                   l_total_validators_count, l_esbocs_pvt->min_validators_count);
            dap_list_free_full(l_validators, NULL);
            return NULL;
        }

        uint256_t l_total_weight = uint256_0;
        for (dap_list_t *it = l_validators; it; it = it->next) {
            if (SUM_256_256(l_total_weight,
                            ((dap_chain_net_srv_stake_item_t *)it->data)->value,
                            &l_total_weight)) {
                log_it(L_CRITICAL, "Total stake locked value overflow"); // Is it possible?
                dap_list_free_full(l_validators, NULL);
                return NULL;
            }
        }

        size_t l_consensus_optimum = (size_t)l_esbocs_pvt->min_validators_count * 2 - 1;
        size_t l_need_vld_cnt = dap_min(l_total_validators_count, l_consensus_optimum);

        dap_pseudo_random_seed(*(uint256_t *)&a_session->cur_round.last_block_hash);
        for (uint64_t i = 0; i < a_skip_count * l_need_vld_cnt; i++)
            dap_pseudo_random_get(uint256_0, NULL);
        for (size_t l_current_vld_cnt = 0; l_current_vld_cnt < l_need_vld_cnt; l_current_vld_cnt++) {
            uint256_t l_raw_result;
            uint256_t l_chosen_weight = dap_pseudo_random_get(l_total_weight, &l_raw_result);
            if (false) { //PVT(a_session->esbocs)->debug) {
                unsigned l_strlen = 1024, l_off = 0;
                char *l_chosen_weight_str, *l_total_weight_str, *l_raw_result_str, l_str[l_strlen];
                dap_uint256_to_char(l_chosen_weight, &l_chosen_weight_str);
                l_off = dap_snprintf(l_str, l_strlen,
                                     "Round seed %s, sync attempt %"DAP_UINT64_FORMAT_U", chosen weight %s ",
                                     dap_hash_fast_to_str_static(&a_session->cur_round.last_block_hash),
                                     a_skip_count + 1, l_chosen_weight_str);
                dap_uint256_to_char(l_total_weight, &l_total_weight_str);
                l_off += dap_snprintf(l_str + l_off, l_strlen - l_off, "from %s, ", l_total_weight_str);
                dap_uint256_to_char(l_raw_result, &l_raw_result_str);
                l_off += dap_snprintf(l_str + l_off, l_strlen - l_off, "by number %s", l_raw_result_str);
                log_it(L_MSG, "%s", l_str);
            }
            dap_list_t *l_chosen = NULL;
            uint256_t l_cur_weight = uint256_0;
            for (dap_list_t *it = l_validators; it; it = it->next) {
                SUM_256_256(l_cur_weight,
                            ((dap_chain_net_srv_stake_item_t *)it->data)->value,
                            &l_cur_weight);
                if (compare256(l_chosen_weight, l_cur_weight) == -1) {
                    l_chosen = it;
                    break;
                }
            }
            l_ret = dap_list_append(l_ret, s_callback_list_form(l_chosen->data, NULL));

            SUBTRACT_256_256(l_total_weight,
                             ((dap_chain_net_srv_stake_item_t *)l_chosen->data)->value,
                             &l_total_weight);
            l_validators = dap_list_remove_link(l_validators, l_chosen);
            DAP_DEL_MULTY(l_chosen->data, l_chosen);
        }
        dap_list_free_full(l_validators, NULL);
    } else
        l_ret = dap_list_copy_deep(l_esbocs_pvt->poa_validators, s_callback_list_copy, NULL);

    return l_ret;
}

static int s_callback_addr_compare(dap_list_t *a_list_elem, dap_list_t *a_addr_elem)
{
    dap_chain_esbocs_validator_t *l_validator = a_list_elem->data;
    dap_chain_addr_t *l_addr = a_addr_elem->data;
    if (!l_validator || !l_addr) {
        log_it(L_CRITICAL, "Invalid argument");
        return -1;
    }
    return memcmp(&l_validator->signing_addr, l_addr, sizeof(dap_chain_addr_t));
}

static dap_list_t *s_validator_check(dap_chain_addr_t *a_addr, dap_list_t *a_validators)
{
    return dap_list_find(a_validators, a_addr, s_callback_addr_compare);
}

static int s_callback_addr_compare_synced(dap_list_t *a_list_elem, dap_list_t *a_addr_elem)
{
    dap_chain_esbocs_validator_t *l_validator = a_list_elem->data;
    dap_chain_addr_t *l_addr = a_addr_elem->data;
    if (!l_validator || !l_addr) {
        log_it(L_CRITICAL, "Invalid argument");
        return -1;
    }
    return memcmp(&l_validator->signing_addr, l_addr, sizeof(dap_chain_addr_t)) || !l_validator->is_synced;
}

static dap_list_t *s_validator_check_synced(dap_chain_addr_t *a_addr, dap_list_t *a_validators)
{
    return dap_list_find(a_validators, a_addr, s_callback_addr_compare_synced);
}


static void s_session_send_startsync(dap_chain_esbocs_session_t *a_session)
{
    if (a_session->cur_round.sync_sent)
        return;     // Sync message already was sent
    dap_chain_hash_fast_t l_last_block_hash;
    dap_chain_get_atom_last_hash(a_session->chain, &l_last_block_hash, c_dap_chain_cell_id_null);
    a_session->ts_round_sync_start = dap_time_now();
    if (!dap_hash_fast_compare(&l_last_block_hash, &a_session->cur_round.last_block_hash))
        return;     // My last block hash has changed, skip sync message
    if (PVT(a_session->esbocs)->debug) {
        dap_string_t *l_addr_list = dap_string_new("");
        for (dap_list_t *it = a_session->cur_round.validators_list; it; it = it->next) {
            dap_string_append_printf(l_addr_list, NODE_ADDR_FP_STR"; ",
                                     NODE_ADDR_FP_ARGS_S(((dap_chain_esbocs_validator_t *)it->data)->node_addr));
        }
        const char *l_sync_hash = dap_global_db_driver_hash_print(a_session->db_hash);
        log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U"."
                       " Sent START_SYNC pkt, sync attempt %"DAP_UINT64_FORMAT_U" current validators list: %s DB sync hash %s",
                            a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                a_session->cur_round.sync_attempt, l_addr_list->str, l_sync_hash);
        dap_string_free(l_addr_list, true);
    }
    struct sync_params l_params = { .attempt = a_session->cur_round.sync_attempt, .db_hash = a_session->db_hash };
    s_message_send(a_session, DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC, &l_last_block_hash,
                   &l_params, sizeof(struct sync_params),
                   a_session->cur_round.all_validators);
    a_session->cur_round.sync_sent = true;
}

static bool s_session_send_startsync_on_timer(void *a_arg)
{
    dap_chain_esbocs_session_t *l_session = a_arg;
    pthread_mutex_lock(&l_session->mutex);
    s_session_send_startsync(l_session);
    l_session->sync_timer = NULL;
    pthread_mutex_unlock(&l_session->mutex);
    return false;
}

static void s_session_update_penalty(dap_chain_esbocs_session_t *a_session)
{
    for (dap_list_t *it = a_session->cur_round.all_validators; it; it = it->next) {
        if (((dap_chain_esbocs_validator_t *)it->data)->is_synced)
            continue;   // Penalty for non synced participants only
        dap_chain_esbocs_penalty_item_t *l_item = NULL;
        dap_chain_addr_t *l_signing_addr = &((dap_chain_esbocs_validator_t *)it->data)->signing_addr;
        HASH_FIND(hh, a_session->penalty, l_signing_addr, sizeof(*l_signing_addr), l_item);
        if (!l_item) {
            DAP_NEW_Z_RET(l_item, dap_chain_esbocs_penalty_item_t, NULL);
            l_item->signing_addr = *l_signing_addr;
            HASH_ADD(hh, a_session->penalty, signing_addr, sizeof(*l_signing_addr), l_item);
        }
        if (l_item->miss_count < DAP_CHAIN_ESBOCS_PENALTY_KICK) {
            if (PVT(a_session->esbocs)->debug) {
                char *l_addr_str = dap_chain_hash_fast_to_str_static(&l_signing_addr->data.hash_fast);
                log_it(L_DEBUG, "Increment miss count %d for addr %s. Miss count for kick is %d",
                                        l_item->miss_count, l_addr_str, DAP_CHAIN_ESBOCS_PENALTY_KICK);
            }
            l_item->miss_count++;
        }
    }
}

static void s_session_round_clear(dap_chain_esbocs_session_t *a_session)
{
    dap_chain_esbocs_message_item_t *l_message_item, *l_message_tmp;
    HASH_ITER(hh, a_session->cur_round.message_items, l_message_item, l_message_tmp) {
        HASH_DEL(a_session->cur_round.message_items, l_message_item);
        DAP_DEL_MULTY(l_message_item->message, l_message_item);
    }
    dap_chain_esbocs_store_t *l_store_item, *l_store_tmp;
    HASH_ITER(hh, a_session->cur_round.store_items, l_store_item, l_store_tmp) {
        HASH_DEL(a_session->cur_round.store_items, l_store_item);
        dap_list_free_full(l_store_item->candidate_signs, NULL);
        DAP_DELETE(l_store_item);
    }
    dap_list_free_full(a_session->cur_round.validators_list, NULL);
    dap_list_free_full(a_session->cur_round.all_validators, NULL);

    DAP_DEL_Z(a_session->cur_round.directive);

    a_session->cur_round = (dap_chain_esbocs_round_t){
            .id = a_session->cur_round.id,
            .attempt_num = 1,
            .last_block_hash = a_session->cur_round.last_block_hash,
            .sync_attempt = a_session->cur_round.sync_attempt
    };
}

static void s_session_round_new(dap_chain_esbocs_session_t *a_session)
{
    if (!a_session->round_fast_forward) {
        s_session_update_penalty(a_session);
        dap_stream_ch_voting_queue_clear();
    }
    s_session_round_clear(a_session);
    a_session->cur_round.id++;
    a_session->cur_round.sync_attempt++;

    if (a_session->sync_timer) {
        dap_timerfd_delete_mt(a_session->sync_timer->worker, a_session->sync_timer->esocket_uuid);
        a_session->sync_timer = NULL;
    }
    a_session->state = DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_START;
    a_session->ts_round_sync_start = 0;
    a_session->ts_stage_entry = 0;

    dap_hash_fast_t l_last_block_hash;
    dap_chain_get_atom_last_hash(a_session->chain, &l_last_block_hash, c_dap_chain_cell_id_null);
    if (!dap_hash_fast_compare(&l_last_block_hash, &a_session->cur_round.last_block_hash) ||
            (!dap_hash_fast_is_blank(&l_last_block_hash) &&
                dap_hash_fast_is_blank(&a_session->cur_round.last_block_hash))) {
        a_session->cur_round.last_block_hash = l_last_block_hash;
        if (!a_session->round_fast_forward)
            a_session->cur_round.sync_attempt = 1;
    }
    if (!PVT(a_session->esbocs)->emergency_mode) {
        a_session->cur_round.validators_list = s_get_validators_list(a_session, a_session->cur_round.sync_attempt - 1);
        if (!a_session->cur_round.validators_list) {
            log_it(L_WARNING, "Minimum active validators not found");
            a_session->ts_round_sync_start = dap_time_now();
            a_session->sync_failed = true;
            return;
        }
    }
    dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators(a_session->chain->net_id, false);
    a_session->cur_round.all_validators = dap_list_copy_deep(l_validators, s_callback_list_form, NULL);
    dap_list_free_full(l_validators, NULL);
    bool l_round_already_started = a_session->round_fast_forward;
    dap_chain_esbocs_sync_item_t *l_item, *l_tmp;
    HASH_FIND(hh, a_session->sync_items, &a_session->cur_round.last_block_hash, sizeof(dap_hash_fast_t), l_item);
    if (l_item) {
        debug_if(PVT(a_session->esbocs)->debug,
                 L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" already started. Process sync messages",
                            a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id);
        l_round_already_started = true;
        for (dap_list_t *it = l_item->messages; it; it = it->next) {
            dap_hash_fast_t l_msg_hash;
            dap_chain_esbocs_message_t *l_msg = it->data;
            size_t l_msg_size = s_get_esbocs_message_size(l_msg);
            dap_hash_fast(l_msg, l_msg_size, &l_msg_hash);
            s_session_packet_in(a_session, NULL, NULL, &l_msg_hash, (uint8_t *)l_msg, l_msg_size);
        }
    }
    HASH_ITER(hh, a_session->sync_items, l_item, l_tmp) {
        HASH_DEL(a_session->sync_items, l_item);
        dap_list_free_full(l_item->messages, NULL);
        DAP_DELETE(l_item);
    }

    if (!a_session->cur_round.sync_sent) {
        uint16_t l_sync_send_delay =  a_session->sync_failed ?
                                            s_get_round_skip_timeout(a_session) :
                                            PVT(a_session->esbocs)->new_round_delay;
        if (l_round_already_started)
            l_sync_send_delay = 0;
        debug_if(PVT(a_session->esbocs)->debug, L_MSG,
                 "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" start. Syncing validators in %u seconds",
                    a_session->chain->net_name, a_session->chain->name,
                        a_session->cur_round.id, l_sync_send_delay);
        if (l_sync_send_delay)
            a_session->sync_timer = dap_timerfd_start(l_sync_send_delay * 1000, s_session_send_startsync_on_timer, a_session);
        else
            s_session_send_startsync(a_session);
    }
    a_session->round_fast_forward = false;
    a_session->sync_failed = false;
    a_session->listen_ensure = 0;
}

static void s_session_attempt_new(dap_chain_esbocs_session_t *a_session)
{
    if (++a_session->cur_round.attempt_num > PVT(a_session->esbocs)->round_attempts_max) {
        a_session->state = DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_START;
        return;
    }
    for (dap_list_t *it = a_session->cur_round.validators_list; it; it = it->next) {
        dap_chain_esbocs_validator_t *l_validator = it->data;
        if (l_validator->is_synced && !l_validator->is_chosen) {
            // We have synced validator with no submitted candidate
            debug_if(PVT(a_session->esbocs)->debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U". Attempt:%hhu is started",
                                                                a_session->chain->net_name, a_session->chain->name,
                                                                    a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC, dap_time_now());
            return;
        }
    }
    debug_if(PVT(a_session->esbocs)->debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U". "
                                                    "All synced validators already tryed their attempts",
                                                        a_session->chain->net_name, a_session->chain->name,
                                                            a_session->cur_round.id);
    a_session->cur_round.attempt_num = PVT(a_session->esbocs)->round_attempts_max + 1;
    a_session->state = DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_START;
}

static uint64_t s_session_calc_current_round_id(dap_chain_esbocs_session_t *a_session)
{
    uint16_t l_total_validators_count = dap_list_length(a_session->cur_round.all_validators);
    struct {
        uint64_t id;
        uint16_t counter;
    } l_id_candidates[l_total_validators_count];
    uint16_t l_fill_idx = 0;
    for (dap_list_t *it = a_session->cur_round.all_validators; it ;it = it->next) {
        dap_chain_esbocs_validator_t *l_validator = it->data;
        if (!l_validator->is_synced)
            continue;
        uint64_t l_id_candidate = 0;
        for (dap_chain_esbocs_message_item_t *l_item = a_session->cur_round.message_items; l_item; l_item = l_item->hh.next) {
            if (l_item->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC &&
                    ((struct sync_params *)l_item->message->msg_n_sign)->attempt == a_session->cur_round.sync_attempt &&
                    dap_chain_addr_compare(&l_item->signing_addr, &l_validator->signing_addr)) {
                l_id_candidate = l_item->message->hdr.round_id;
                break;
            }
        }
        if (l_id_candidate == 0) {
            char *l_signing_addr_str = dap_chain_hash_fast_to_str_static(&l_validator->signing_addr.data.hash_fast);
            log_it(L_ERROR, "Can't find sync message of synced validator %s", l_signing_addr_str);
            continue;
        }
        bool l_candidate_found = false;
        for (uint16_t i = 0; i < l_fill_idx; i++)
            if (l_id_candidates[i].id == l_id_candidate) {
                l_id_candidates[i].counter++;
                l_candidate_found = true;
                break;
            }
        if (!l_candidate_found) {
            l_id_candidates[l_fill_idx].id = l_id_candidate;
            l_id_candidates[l_fill_idx].counter = 1;
            if (++l_fill_idx > l_total_validators_count) {
                log_it(L_ERROR, "Count of sync messages with same sync attempt is greater"
                                  " than total validators count %hu > %hu",
                                    l_fill_idx, l_total_validators_count);
                l_fill_idx--;
                break;
            }
        }
    }
    uint64_t l_ret = 0;
    uint16_t l_counter_max = 0;
    for (uint16_t i = 0; i < l_fill_idx; i++) {
        if (l_id_candidates[i].counter > l_counter_max) { // Choose maximum counter
            l_counter_max = l_id_candidates[i].counter;
            l_ret = l_id_candidates[i].id;
        } else if (l_id_candidates[i].counter == l_counter_max) // Choose maximum round ID
            l_ret = dap_max(l_ret, l_id_candidates[i].id);
    }
    return l_ret ? l_ret : a_session->cur_round.id;
}

static int s_signs_sort_callback(dap_list_t *a_sign1, dap_list_t *a_sign2)
{
    dap_sign_t  *l_sign1 = a_sign1->data,
                *l_sign2 = a_sign2->data;
    if (!l_sign1 || !l_sign2) {
        log_it(L_CRITICAL, "Invalid element");
        return 0;
    }
    size_t  l_size1 = dap_sign_get_size(l_sign1),
            l_size2 = dap_sign_get_size(l_sign2),
            l_size_min = dap_min(l_size1, l_size2);

    int l_ret = memcmp(l_sign1, l_sign2, l_size_min);
    if (!l_ret) {
        l_ret = l_size1 == l_size2 ? 0 : l_size1 > l_size2 ? 1 : -1;
    }
    return l_ret;
}

dap_chain_esbocs_directive_t *s_session_directive_ready(dap_chain_esbocs_session_t *a_session)
{
    size_t l_list_length = dap_list_length(a_session->cur_round.all_validators);
    if (a_session->cur_round.total_validators_synced * 3 < l_list_length * 2)
        return NULL; // Not a valid round, less than 2/3 participants
    bool l_kick = false;
    dap_chain_esbocs_penalty_item_t *l_item, *l_tmp;
    HASH_ITER(hh, a_session->penalty, l_item, l_tmp) {
        int l_key_state = dap_chain_net_srv_stake_key_delegated(&l_item->signing_addr);
        if (l_key_state == 0) {
            HASH_DEL(a_session->penalty, l_item);
            DAP_DELETE(l_item);
            continue;
        }
        if (l_item->miss_count >= DAP_CHAIN_ESBOCS_PENALTY_KICK && l_key_state == 1) {
            l_kick = true;
            break;
        }
        if (l_item->miss_count == 0 && l_key_state == -1)
            break;
    }
    if (!l_item)
        return NULL;
    debug_if(PVT(a_session->esbocs)->debug, L_MSG, "Current consensus online %hu from %zu is acceptable, so issue the directive",
                                                    a_session->cur_round.total_validators_synced, l_list_length);
    uint32_t l_directive_size = s_directive_calc_size(l_kick ? DAP_CHAIN_ESBOCS_DIRECTIVE_KICK : DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT);
    dap_chain_esbocs_directive_t *l_ret = NULL;
    DAP_NEW_Z_SIZE_RET_VAL(l_ret, dap_chain_esbocs_directive_t, l_directive_size, NULL, NULL);
    l_ret->version = DAP_CHAIN_ESBOCS_DIRECTIVE_VERSION;
    l_ret->type = l_kick ? DAP_CHAIN_ESBOCS_DIRECTIVE_KICK : DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT;
    l_ret->size = l_directive_size;
    l_ret->timestamp = dap_nanotime_now();
    dap_tsd_t *l_tsd = (dap_tsd_t *)l_ret->tsd;
    l_tsd->type = DAP_CHAIN_ESBOCS_DIRECTIVE_TSD_TYPE_ADDR;
    l_tsd->size = sizeof(dap_chain_addr_t);
    *(dap_chain_addr_t *)l_tsd->data = l_item->signing_addr;
    return l_ret;
}

static void s_session_state_change(dap_chain_esbocs_session_t *a_session, enum s_esbocs_session_state a_new_state, dap_time_t a_time)
{
    if (a_new_state != DAP_CHAIN_ESBOCS_SESSION_STATE_PREVIOUS)
        a_session->old_state = a_session->state;

    a_session->state = a_new_state;
    a_session->ts_stage_entry = a_time;

    switch (a_new_state) {
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC: {
        dap_chain_esbocs_validator_t *l_validator = NULL;
        if (!a_session->cur_round.validators_list && PVT(a_session->esbocs)->emergency_mode) {
            for (dap_list_t *it = a_session->cur_round.all_validators; it; it = it->next) {
                l_validator = it->data;
                if (l_validator->is_synced)
                    a_session->cur_round.validators_list = dap_list_append(
                                a_session->cur_round.validators_list, DAP_DUP(l_validator));
            }
        }
        for (dap_list_t *it = a_session->cur_round.validators_list; it; it = it->next) {
            l_validator = it->data;
            if (l_validator->is_synced && !l_validator->is_chosen) {
                l_validator->is_chosen = true;
                break;
            }
        }
        a_session->cur_round.attempt_submit_validator = l_validator->signing_addr;
        if (dap_chain_addr_compare(&a_session->cur_round.attempt_submit_validator, &a_session->my_signing_addr)) {
            dap_chain_esbocs_directive_t *l_directive = NULL;
            if (!a_session->cur_round.directive && !PVT(a_session->esbocs)->emergency_mode)
                l_directive = s_session_directive_ready(a_session);
            if (l_directive) {
                dap_hash_fast_t l_directive_hash;
                dap_hash_fast(l_directive, l_directive->size, &l_directive_hash);
                if (PVT(a_session->esbocs)->debug) {
                    char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(&l_directive_hash);
                    log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu. Put on the vote my directive:%s",
                            a_session->chain->net_name, a_session->chain->name,
                                a_session->cur_round.id, a_session->cur_round.attempt_num, l_candidate_hash_str);
                }
                s_message_send(a_session, DAP_CHAIN_ESBOCS_MSG_TYPE_DIRECTIVE, &l_directive_hash,
                                    l_directive, l_directive->size, a_session->cur_round.all_validators);
                DAP_DELETE(l_directive);
            } else
                s_session_candidate_submit(a_session);
        } else {
            for (dap_chain_esbocs_message_item_t *l_item = a_session->cur_round.message_items; l_item; l_item = l_item->hh.next) {
                if (l_item->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_SUBMIT &&
                        dap_chain_addr_compare(&l_item->signing_addr, &a_session->cur_round.attempt_submit_validator)) {
                    dap_hash_fast_t *l_candidate_hash = &l_item->message->hdr.candidate_hash;
                    if (dap_hash_fast_is_blank(l_candidate_hash))
                        s_session_attempt_new(a_session);
                    else {
                        dap_chain_esbocs_store_t *l_store;
                        HASH_FIND(hh, a_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
                        if (l_store) {
                            a_session->cur_round.attempt_candidate_hash = *l_candidate_hash;
                            s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_SIGNS, dap_time_now());
                            // Verify and vote already submitted candidate
                            s_session_candidate_verify(a_session, l_store->candidate, l_store->candidate_size, l_candidate_hash);
                        }
                    }
                    break;
                }
            }
        }
    } break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_VOTING: {
        if (a_session->old_state == DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC) {
            // Clear mark of chosen to submit validator
            dap_list_t *l_list = s_validator_check(
                        &a_session->cur_round.attempt_submit_validator,
                        a_session->cur_round.validators_list
                        );
            dap_chain_esbocs_validator_t *l_validator = l_list ? l_list->data : NULL;
            if (!l_validator || !l_validator->is_chosen) {
                char *l_addr = dap_chain_hash_fast_to_str_static(&a_session->cur_round.attempt_submit_validator.data.hash_fast);
                log_it(L_MSG, "Error: can't find current attmempt submit validator %s in signers list", l_addr);
            }
            l_validator->is_chosen = false;
        } else
            a_session->old_state = DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC;
    } break;

    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH: {
        dap_chain_esbocs_store_t *l_store;
        HASH_FIND(hh, a_session->cur_round.store_items, &a_session->cur_round.attempt_candidate_hash, sizeof(dap_hash_fast_t), l_store);
        if (!l_store) {
            log_it(L_ERROR, "No finish candidate found!");
            break;
        }
        l_store->candidate_signs = dap_list_sort(l_store->candidate_signs, s_signs_sort_callback);
        size_t l_candidate_size_exclude_signs = l_store->candidate_size;
        for (dap_list_t *it = l_store->candidate_signs; it; it = it->next) {
            dap_sign_t *l_candidate_sign = (dap_sign_t *)it->data;
            size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
            dap_chain_addr_t l_signing_addr_cur;
            dap_chain_addr_fill_from_sign(&l_signing_addr_cur, l_candidate_sign, a_session->chain->net_id);
            l_store->candidate = DAP_REALLOC(l_store->candidate, l_store->candidate_size + l_candidate_sign_size);
            if (dap_chain_addr_compare(&l_signing_addr_cur, &a_session->cur_round.attempt_submit_validator) &&
                                       l_store->candidate_size != l_candidate_size_exclude_signs) {
                // If it's the primary attempt validator sign, place it in the beginnig
                if (l_store->candidate_size > l_candidate_size_exclude_signs)
                    memmove((byte_t *)l_store->candidate + l_candidate_size_exclude_signs + l_candidate_sign_size,
                            (byte_t *)l_store->candidate + l_candidate_size_exclude_signs,
                            l_store->candidate_size - l_candidate_size_exclude_signs);
                memcpy((byte_t *)l_store->candidate + l_candidate_size_exclude_signs, l_candidate_sign, l_candidate_sign_size);
            } else
                memcpy(((byte_t *)l_store->candidate) + l_store->candidate_size, l_candidate_sign, l_candidate_sign_size);
            l_store->candidate_size += l_candidate_sign_size;
        }
        l_store->candidate->hdr.meta_n_datum_n_signs_size = l_store->candidate_size - sizeof(l_store->candidate->hdr);
        dap_hash_fast(l_store->candidate, l_store->candidate_size, &l_store->precommit_candidate_hash);
        // Process received earlier PreCommit messages
        dap_chain_esbocs_message_item_t *l_chain_message, *l_chain_message_tmp;
        HASH_ITER(hh, a_session->cur_round.message_items, l_chain_message, l_chain_message_tmp) {
            if (l_chain_message->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_PRE_COMMIT &&
                    dap_hash_fast_compare(&l_chain_message->message->hdr.candidate_hash,
                                          &a_session->cur_round.attempt_candidate_hash)) {
                s_session_candidate_precommit(a_session, l_chain_message->message);
            }
        }
        // Send own PreCommit
        s_message_send(a_session, DAP_CHAIN_ESBOCS_MSG_TYPE_PRE_COMMIT, &l_store->candidate_hash,
                            &l_store->precommit_candidate_hash, sizeof(dap_chain_hash_fast_t),
                                a_session->cur_round.validators_list);
    } break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_PREVIOUS: {
        if (a_session->old_state != DAP_CHAIN_ESBOCS_SESSION_STATE_PREVIOUS)
            s_session_state_change(a_session, a_session->old_state, a_time);
        else {
            log_it(L_ERROR, "No previous state registered, can't roll back");
            s_session_round_new(a_session);
        }
    }
    default:
        break;
    }
}

static void s_session_proc_state(dap_chain_esbocs_session_t *a_session)
{
    if (pthread_mutex_trylock(&a_session->mutex) != 0)
        return; // Session is busy
    bool l_cs_debug = PVT(a_session->esbocs)->debug;
    dap_time_t l_time = dap_time_now();
    switch (a_session->state) {
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_START: {
        a_session->listen_ensure = 1;
        bool l_round_skip = PVT(a_session->esbocs)->emergency_mode ?
                    false : !s_validator_check(&a_session->my_signing_addr, a_session->cur_round.validators_list);
        if (a_session->ts_round_sync_start && l_time - a_session->ts_round_sync_start >=
                (dap_time_t)PVT(a_session->esbocs)->round_start_sync_timeout +
                    (a_session->sync_failed ? s_get_round_skip_timeout(a_session) : 0)) {
            if (a_session->cur_round.attempt_num > PVT(a_session->esbocs)->round_attempts_max ) {
                debug_if(PVT(a_session->esbocs)->debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U"."
                                                                " Round finished by reason: attempts is out",
                                                                    a_session->chain->net_name, a_session->chain->name,
                                                                        a_session->cur_round.id);
                s_session_round_new(a_session);
                break;
            }
            uint16_t l_min_validators_synced = PVT(a_session->esbocs)->emergency_mode ?
                        a_session->cur_round.total_validators_synced : a_session->cur_round.validators_synced_count;
            if (l_min_validators_synced >= PVT(a_session->esbocs)->min_validators_count && !l_round_skip) {
                a_session->cur_round.id = s_session_calc_current_round_id(a_session);
                debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                            " Minimum count of validators are synchronized, wait to submit candidate",
                                                a_session->chain->net_name, a_session->chain->name,
                                                    a_session->cur_round.id, a_session->cur_round.attempt_num);
                s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC, l_time);
            } else { // timeout start sync
                debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                            " Round finished by reason: %s",
                                                a_session->chain->net_name, a_session->chain->name,
                                                    a_session->cur_round.id, a_session->cur_round.attempt_num,
                                                        l_round_skip ? "skipped" : "can't synchronize minimum number of validators");
                a_session->sync_failed = true;
                s_session_round_new(a_session);
            }
        }
    } break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC:
        if (l_time - a_session->ts_stage_entry >= PVT(a_session->esbocs)->round_attempt_timeout * a_session->listen_ensure) {
            a_session->listen_ensure += 2;
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Attempt finished by reason: haven't cantidate submitted",
                                            a_session->chain->net_name, a_session->chain->name,
                                                a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_attempt_new(a_session);
        }
        break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_SIGNS:
        if (l_time - a_session->ts_stage_entry >= PVT(a_session->esbocs)->round_attempt_timeout) {
            dap_chain_esbocs_store_t *l_store;
            HASH_FIND(hh, a_session->cur_round.store_items, &a_session->cur_round.attempt_candidate_hash, sizeof(dap_hash_fast_t), l_store);
            if (!l_store) {
                log_it(L_ERROR, "No round candidate found!");
                s_session_attempt_new(a_session);
                break;
            }
            if (dap_list_length(l_store->candidate_signs) >= PVT(a_session->esbocs)->min_validators_count) {
                if(l_cs_debug) {
                    char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(&a_session->cur_round.attempt_candidate_hash);
                    log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu"
                                            " Candidate %s collected sings of minimum number of validators, so to sent PRE_COMMIT",
                                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                                    a_session->cur_round.attempt_num, l_candidate_hash_str);
                }
                s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH, l_time);
                break;
            }
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Attempt finished by reason: cant't collect minimum number of validator's signs",
                                            a_session->chain->net_name, a_session->chain->name,
                                                a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_attempt_new(a_session);
        }
        break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH:
        if (l_time - a_session->ts_stage_entry >= PVT(a_session->esbocs)->round_attempt_timeout * 2) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Attempt finished by reason: cant't collect minimum number of validator's precommits with same final hash",
                                            a_session->chain->net_name, a_session->chain->name,
                                                a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_attempt_new(a_session);
        }
        break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_VOTING:
        if (l_time - a_session->ts_stage_entry >= PVT(a_session->esbocs)->round_attempt_timeout * 2) {
            const char *l_hash_str = dap_chain_hash_fast_to_str_static(&a_session->cur_round.directive_hash);
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Voting finished by reason: cant't collect minimum number of validator's votes for directive %s",
                                            a_session->chain->net_name, a_session->chain->name,
                                                a_session->cur_round.id, a_session->cur_round.attempt_num,
                                                    l_hash_str);
            s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_PREVIOUS, l_time);
        }
        break;
    default:
        break;
    }

    pthread_mutex_unlock(&a_session->mutex);
}

static bool s_session_timer(void *a_arg)
{
    dap_chain_esbocs_session_t *l_session = a_arg;
    s_session_proc_state(l_session);
    return true;
}

static void s_message_chain_add(dap_chain_esbocs_session_t *a_session,
                                dap_chain_esbocs_message_t *a_message,
                                size_t a_message_size,
                                dap_chain_hash_fast_t *a_message_hash,
                                dap_chain_addr_t *a_signing_addr)
{
    if (NULL == a_message) {
        log_it(L_ERROR, "Argument is NULL for s_message_chain_add");
        return;
    }
    dap_chain_esbocs_round_t *l_round = &a_session->cur_round;
    dap_chain_esbocs_message_item_t *l_message_item = NULL;
    DAP_NEW_Z_RET(l_message_item, dap_chain_esbocs_message_item_t, NULL);
    if (!a_message_hash) {
        dap_chain_hash_fast_t l_message_hash;
        dap_hash_fast(a_message, a_message_size, &l_message_hash);
        l_message_item->message_hash = l_message_hash;
    } else
        l_message_item->message_hash = *a_message_hash;
    l_message_item->signing_addr = *a_signing_addr;
    l_message_item->message = DAP_DUP_SIZE(a_message, a_message_size);
    HASH_ADD(hh, l_round->message_items, message_hash, sizeof(l_message_item->message_hash), l_message_item);
}

static void s_session_candidate_submit(dap_chain_esbocs_session_t *a_session)
{
    dap_chain_t *l_chain = a_session->chain;
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
    dap_chain_block_t *l_candidate;
    size_t l_candidate_size = 0;
    dap_hash_fast_t l_candidate_hash = {0};
    dap_chain_node_mempool_process_all(a_session->chain, false);
    l_candidate = l_blocks->callback_new_block_move(l_blocks, &l_candidate_size);
    if (l_candidate_size) {
        dap_hash_fast(l_candidate, l_candidate_size, &l_candidate_hash);
        if (PVT(a_session->esbocs)->debug) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(&l_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu. Submit my candidate %s",
                    a_session->chain->net_name, a_session->chain->name,
                        a_session->cur_round.id, a_session->cur_round.attempt_num, l_candidate_hash_str);
        }
    } else { // there is no my candidate, send null hash
        if (PVT(a_session->esbocs)->debug)
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                          " I don't have a candidate. I submit a null candidate.",
                                a_session->chain->net_name, a_session->chain->name,
                                    a_session->cur_round.id, a_session->cur_round.attempt_num);
    }
    s_message_send(a_session, DAP_CHAIN_ESBOCS_MSG_TYPE_SUBMIT, &l_candidate_hash,
                    l_candidate, l_candidate_size, a_session->cur_round.validators_list);
    //Save candidate_hash
    memcpy(&(PVT(a_session->esbocs)->candidate_hash), &l_candidate_hash, sizeof(dap_hash_fast_t));
}

static void s_session_candidate_verify(dap_chain_esbocs_session_t *a_session, dap_chain_block_t *a_candidate,
                                       size_t a_candidate_size, dap_hash_fast_t *a_candidate_hash)
{
    if (NULL == a_candidate) {
        log_it(L_ERROR, "Argument is NULL for s_session_candidate_verify");
        return;
    }
    // Process early received messages
    for (dap_chain_esbocs_message_item_t *l_item = a_session->cur_round.message_items; l_item; l_item = l_item->hh.next) {
        if (l_item->unprocessed &&
                (l_item->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE ||
                    l_item->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_REJECT ||
                    l_item->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_COMMIT_SIGN) &&
                dap_hash_fast_compare(&l_item->message->hdr.candidate_hash, a_candidate_hash) &&
                l_item->message->hdr.attempt_num == a_session->cur_round.attempt_num) {
            s_session_packet_in(a_session, NULL, NULL, &l_item->message_hash,
                                (uint8_t *)l_item->message, s_get_esbocs_message_size(l_item->message));
        }
    }
    // Process candidate
    a_session->processing_candidate = a_candidate;
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_session->chain);
    if (l_blocks->chain->callback_atom_verify(l_blocks->chain, a_candidate, a_candidate_size) == ATOM_ACCEPT) {
        // validation - OK, gen event Approve
        s_message_send(a_session, DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE, a_candidate_hash,
                       NULL, 0, a_session->cur_round.validators_list);
        if (PVT(a_session->esbocs)->debug) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(a_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu Sent APPROVE candidate %s",
                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                        a_session->cur_round.attempt_num, l_candidate_hash_str);
        }
    } else {
        // validation - fail, gen event Reject
        s_message_send(a_session, DAP_CHAIN_ESBOCS_MSG_TYPE_REJECT, a_candidate_hash,
                       NULL, 0, a_session->cur_round.validators_list);
        if (PVT(a_session->esbocs)->debug) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(a_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu Sent REJECT candidate %s",
                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                        a_session->cur_round.attempt_num, l_candidate_hash_str);
        }
    }
    a_session->processing_candidate = NULL;
}

static void s_session_candidate_precommit(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_message_t *a_message)
{
    if (NULL == a_message) {
        log_it(L_ERROR, "Argument is NULL for s_session_candidate_precommit");
        return;
    }
    bool l_cs_debug = PVT(a_session->esbocs)->debug;
    uint16_t l_cs_level = PVT(a_session->esbocs)->min_validators_count;
    byte_t *l_message_data = a_message->msg_n_sign;
    dap_chain_hash_fast_t *l_candidate_hash = &a_message->hdr.candidate_hash;
    dap_chain_esbocs_store_t *l_store;
    char *l_candidate_hash_str = NULL;
    HASH_FIND(hh, a_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
    if (!l_store) {
        l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
        log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                          " Receive PRE_COMMIT message for unknown candidate %s",
                            a_session->chain->net_name, a_session->chain->name,
                                a_session->cur_round.id, a_message->hdr.attempt_num,
                                    l_candidate_hash_str);
        return;
    }

    if (dap_hash_fast_is_blank(&l_store->precommit_candidate_hash))
        // We have not yet precommit candidate. Message will be processed later
        return;
    dap_hash_fast_t *l_precommit_hash = (dap_hash_fast_t *)l_message_data;
    if (!dap_hash_fast_compare(l_precommit_hash, &l_store->precommit_candidate_hash)) {
        if (l_cs_debug) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            char *l_my_precommit_hash_str = dap_chain_hash_fast_to_str_new(&l_store->precommit_candidate_hash);
            char *l_remote_precommit_hash_str = dap_chain_hash_fast_to_str_new(l_precommit_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                          " Candidate %s has different final hash of local and remote validators\n"
                          "(%s and %s)",
                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                    a_message->hdr.attempt_num, l_candidate_hash_str,
                                        l_my_precommit_hash_str, l_remote_precommit_hash_str);
            DAP_DEL_MULTY(l_candidate_hash_str, l_my_precommit_hash_str, l_remote_precommit_hash_str);
        }
        return;
    }

    if (l_cs_debug) {
        l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
        log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                        " Receive PRE_COMMIT: candidate %s",
                            a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                a_message->hdr.attempt_num, l_candidate_hash_str);
    }
    if (++l_store->precommit_count >= l_cs_level && !l_store->decide_commit &&
            dap_hash_fast_compare(&a_session->cur_round.attempt_candidate_hash, l_candidate_hash)) {
        l_store->decide_commit = true;
        debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                    " Candidate %s precommited by minimum number of validators, try to finish this round",
                                        a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                            a_message->hdr.attempt_num, l_candidate_hash_str);
        s_session_round_finish(a_session, l_store);
        // ATTENTION: New round will be started by incoming atom notifier event
    }
}

static bool s_session_candidate_to_chain(dap_chain_esbocs_session_t *a_session, dap_chain_hash_fast_t *a_candidate_hash,
                                         dap_chain_block_t *a_candidate, size_t a_candidate_size)
{
    if (NULL == a_candidate) {
        log_it(L_ERROR, "Argument is NULL for s_session_candidate_to_chain");
        return false;
    }
    bool res = false;
    dap_chain_atom_verify_res_t l_res = a_session->chain->callback_atom_add(a_session->chain, a_candidate, a_candidate_size);
    char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(a_candidate_hash);
    switch (l_res) {
    case ATOM_ACCEPT:
        // block save to chain
        if (dap_chain_atom_save(a_session->chain->cells, (uint8_t *)a_candidate, a_candidate_size, a_candidate_hash) < 0)
            log_it(L_ERROR, "Can't save atom %s to the file", l_candidate_hash_str);
        else
        {
            log_it(L_INFO, "block %s added in chain successfully", l_candidate_hash_str);
            res = true;
        }
        break;
    case ATOM_MOVE_TO_THRESHOLD:
        log_it(L_INFO, "Thresholded atom with hash %s", l_candidate_hash_str);
        break;
    case ATOM_PASS:
        log_it(L_WARNING, "Atom with hash %s not accepted (code ATOM_PASS, already present)", l_candidate_hash_str);
        break;
    case ATOM_REJECT:
        log_it(L_WARNING,"Atom with hash %s rejected", l_candidate_hash_str);
        break;
    default:
         log_it(L_CRITICAL, "Wtf is this ret code ? Atom hash %s code %d", l_candidate_hash_str, l_res);
    }
    return res;
}

static void s_session_round_finish(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_store_t *l_store)
{
    bool l_cs_debug = PVT(a_session->esbocs)->debug;
    uint16_t l_cs_level = PVT(a_session->esbocs)->min_validators_count;

    if (!dap_hash_fast_compare(&a_session->cur_round.attempt_candidate_hash, &l_store->candidate_hash)) {
        char *l_current_candidate_hash_str = dap_chain_hash_fast_to_str_new(&a_session->cur_round.attempt_candidate_hash);
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "Trying to finish candidate of not the current attempt (%s but not %s)",
                                        l_current_candidate_hash_str, l_finish_candidate_hash_str);
        DAP_DEL_MULTY(l_current_candidate_hash_str, l_finish_candidate_hash_str);
        return;
    }

    if (l_store->reject_count >= l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_static(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "Trying to finish rejected candidate %s", l_finish_candidate_hash_str);
        return;
    }

    if (l_store->approve_count < l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_static(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "Trying to finish not properly approved candidate %s", l_finish_candidate_hash_str);
        return;
    }

    if (dap_list_length(l_store->candidate_signs) < l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_static(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "Trying to finish not properly signed candidate %s", l_finish_candidate_hash_str);
        return;
    }

    if (l_store->precommit_count < l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_static(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "Trying to finish not properly precommited candidate %s", l_finish_candidate_hash_str);
        return;
    }

    if (l_cs_debug) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        char *l_finish_block_hash_str = dap_chain_hash_fast_to_str_new(&l_store->precommit_candidate_hash);
        log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu Candidate %s passed the consensus!\n"
                      "Move block %s to chains",
                        a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                            a_session->cur_round.attempt_num, l_finish_candidate_hash_str, l_finish_block_hash_str);
        DAP_DEL_MULTY(l_finish_candidate_hash_str, l_finish_block_hash_str);
    }
    s_session_candidate_to_chain(a_session, &l_store->precommit_candidate_hash, l_store->candidate, l_store->candidate_size);
}

void s_session_sync_queue_add(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_message_t *a_message, size_t a_message_size)
{
    if (!a_message) {
        log_it(L_ERROR, "Invalid arguments in s_session_sync_queue_add");
        return;
    }
    dap_chain_esbocs_sync_item_t *l_sync_item;
    HASH_FIND(hh, a_session->sync_items, &a_message->hdr.candidate_hash, sizeof(dap_hash_fast_t), l_sync_item);
    if (!l_sync_item) {
        DAP_NEW_Z_RET(l_sync_item, dap_chain_esbocs_sync_item_t, NULL);
        l_sync_item->last_block_hash = a_message->hdr.candidate_hash;
        HASH_ADD(hh, a_session->sync_items, last_block_hash, sizeof(dap_hash_fast_t), l_sync_item);
    }
    l_sync_item->messages = dap_list_append(l_sync_item->messages, DAP_DUP_SIZE(a_message, a_message_size));
}

void s_session_validator_mark_online(dap_chain_esbocs_session_t *a_session, dap_chain_addr_t *a_signing_addr)
{
    dap_list_t *l_list = s_validator_check(a_signing_addr, a_session->cur_round.all_validators);
    if (l_list) {
        bool l_was_synced = ((dap_chain_esbocs_validator_t *)l_list->data)->is_synced;
        ((dap_chain_esbocs_validator_t *)l_list->data)->is_synced = true;
        if (!l_was_synced)
            a_session->cur_round.total_validators_synced++;
        if (PVT(a_session->esbocs)->debug) {
            const char *l_addr_str = dap_chain_hash_fast_to_str_static(&a_signing_addr->data.hash_fast);
            log_it(L_DEBUG, "Mark validator %s as online", l_addr_str);
        }
    } else {
        const char *l_addr_str = dap_chain_hash_fast_to_str_static(&a_signing_addr->data.hash_fast);
        log_it(L_ERROR, "Can't find validator %s in validators list", l_addr_str);
    }

    dap_chain_esbocs_penalty_item_t *l_item = NULL;
    HASH_FIND(hh, a_session->penalty, a_signing_addr, sizeof(*a_signing_addr), l_item);
    bool l_inactive = dap_chain_net_srv_stake_key_delegated(a_signing_addr) == -1;
    if (l_inactive && !l_item) {
        const char *l_addr_str = dap_chain_hash_fast_to_str_static(&a_signing_addr->data.hash_fast);
        log_it(L_DEBUG, "Validator %s not in penalty list, but currently disabled", l_addr_str);
        DAP_NEW_Z_RET(l_item, dap_chain_esbocs_penalty_item_t, NULL);
        l_item->signing_addr = *a_signing_addr;
        l_item->miss_count = DAP_CHAIN_ESBOCS_PENALTY_KICK;
        HASH_ADD(hh, a_session->penalty, signing_addr, sizeof(*a_signing_addr), l_item);
    }
    if (l_item) {
        if (l_item->miss_count > DAP_CHAIN_ESBOCS_PENALTY_KICK)
            l_item->miss_count = DAP_CHAIN_ESBOCS_PENALTY_KICK;
        if (PVT(a_session->esbocs)->debug) {
            const char *l_addr_str = dap_chain_hash_fast_to_str_static(&a_signing_addr->data.hash_fast);
            log_it(L_DEBUG, "Decrement miss count %d for addr %s. Miss count for kick is %d",
                            l_item->miss_count, l_addr_str, DAP_CHAIN_ESBOCS_PENALTY_KICK);
        }
        if (l_item->miss_count)
            l_item->miss_count--;
        if (!l_inactive && !l_item->miss_count) {
            HASH_DEL(a_session->penalty, l_item);
            DAP_DELETE(l_item);
        }
    }
}

static void s_session_directive_process(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_directive_t *a_directive, dap_chain_hash_fast_t *a_directive_hash)
{
    if (!a_directive) {
        log_it(L_ERROR, "Invalid arguments in s_session_directive_process");
        return;
    }
    if (a_directive->size != s_directive_calc_size(a_directive->type)) {
        log_it(L_ERROR, "Invalid directive size %u (expected %u)",
               a_directive->size, s_directive_calc_size(a_directive->type));
        return;
    }
    bool l_vote_for = false;
    switch (a_directive->type) {
    case DAP_CHAIN_ESBOCS_DIRECTIVE_KICK:
    case DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT: {
        dap_tsd_t *l_tsd = (dap_tsd_t *)a_directive->tsd;
        if (l_tsd->size != sizeof(dap_chain_addr_t)) {
            log_it(L_ERROR, "Invalid directive TSD size %u (expected %zu)",
                   l_tsd->size, sizeof(dap_chain_addr_t));
            return;
        }
        dap_chain_addr_t *l_voting_addr = (dap_chain_addr_t *)l_tsd->data;
        if (l_voting_addr->net_id.uint64 != a_session->chain->net_id.uint64) {
            log_it(L_WARNING, "Got directive to %s for invalid network id 0x%"DAP_UINT64_FORMAT_x
                                    " (current network id is 0x%"DAP_UINT64_FORMAT_x,
                                        a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_KICK ? "KICK" : "LIFT",
                                            l_voting_addr->net_id.uint64, a_session->chain->net_id.uint64);
            return;
        }
        int l_status = dap_chain_net_srv_stake_key_delegated(l_voting_addr);
        if (l_status == 0) {
            const char *l_addr_str = dap_chain_hash_fast_to_str_static(&l_voting_addr->data.hash_fast);
            log_it(L_WARNING, "Trying to put to the vote directive type %s for non delegated key %s",
                                    a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_KICK ? "KICK" : "LIFT",
                                        l_addr_str);
            return;
        }
        dap_chain_esbocs_penalty_item_t *l_item = NULL;
        HASH_FIND(hh, a_session->penalty, l_voting_addr, sizeof(*l_voting_addr), l_item);
        if (l_status == 1) { // Key is active
            if (a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_KICK) {
                if (l_item && l_item->miss_count >= DAP_CHAIN_ESBOCS_PENALTY_KICK)
                    l_vote_for = true;
            } else { // a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT
                if (!l_item || l_item->miss_count < DAP_CHAIN_ESBOCS_PENALTY_KICK)
                    l_vote_for = true;
            }
        } else { // l_status == -1 // Key is inactive
            if (a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT) {
                if (l_item && l_item->miss_count == 0)
                    l_vote_for = true;
            } else { // a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_KICK
                if (!l_item || l_item->miss_count != 0)
                    l_vote_for = true;
            }
        }
    }
    default:;
    }

    if (PVT(a_session->esbocs)->debug) {
        char *l_directive_hash_str = dap_chain_hash_fast_to_str_static(a_directive_hash);
        log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu Send VOTE %s directive %s",
                            a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                    a_session->cur_round.attempt_num, l_vote_for ? "FOR" : "AGAINST",
                                            l_directive_hash_str);
    }
    a_session->cur_round.directive_hash = *a_directive_hash;
    a_session->cur_round.directive = DAP_DUP_SIZE(a_directive, a_directive->size);

    s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_VOTING, dap_time_now());

    // Process early received directive votes
    for (dap_chain_esbocs_message_item_t *l_item = a_session->cur_round.message_items; l_item; l_item = l_item->hh.next) {
        if (l_item->unprocessed &&
                (l_item->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR ||
                    l_item->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST) &&
                dap_hash_fast_compare(&l_item->message->hdr.candidate_hash, a_directive_hash) &&
                l_item->message->hdr.attempt_num == a_session->cur_round.attempt_num) {
            s_session_packet_in(a_session, NULL, NULL, &l_item->message_hash,
                                (uint8_t *)l_item->message, s_get_esbocs_message_size(l_item->message));
        }
    }
    // Send own vote
    uint8_t l_type = l_vote_for ? DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR : DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST;
    s_message_send(a_session, l_type, a_directive_hash, NULL, 0, a_session->cur_round.all_validators);
}

static void s_db_change_notifier(dap_store_obj_t *a_obj, void *a_arg)
{
    dap_chain_esbocs_session_t *l_session = a_arg;
    dap_chain_addr_t *l_validator_addr = dap_chain_addr_from_str(a_obj->key);
    if (!l_validator_addr) {
        log_it(L_WARNING, "Unreadable address in esbocs global DB group");
        return;
    }
    if (l_validator_addr->net_id.uint64 != l_session->chain->net_id.uint64) {
        log_it(L_ERROR, "Wrong destination net ID %" DAP_UINT64_FORMAT_x "session net ID %" DAP_UINT64_FORMAT_x,
                                                    l_validator_addr->net_id.uint64, l_session->chain->net_id.uint64);
        return;
    }
    if (dap_chain_net_srv_stake_mark_validator_active(l_validator_addr, a_obj->type != DAP_GLOBAL_DB_OPTYPE_ADD)) {
        log_it(L_ERROR, "Validator with signing address %s not found in network %s",
                                                    a_obj->key, l_session->chain->net_name);
        return;
    }
    log_it(L_DEBUG, "Got new penalty item for group %s with key %s", a_obj->group, a_obj->key);
    l_session->db_hash = dap_global_db_driver_hash_get(a_obj);
}

static int s_session_directive_apply(dap_chain_esbocs_directive_t *a_directive, dap_hash_fast_t *a_directive_hash)
{
    if (!a_directive) {
        log_it(L_ERROR, "Can't apply NULL directive");
        return -1;
    }
    switch (a_directive->type) {
    case DAP_CHAIN_ESBOCS_DIRECTIVE_KICK:
    case DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT: {
        dap_chain_addr_t *l_key_addr = (dap_chain_addr_t *)(((dap_tsd_t *)a_directive->tsd)->data);
        int l_status = dap_chain_net_srv_stake_key_delegated(l_key_addr);
        const char *l_key_str = dap_chain_hash_fast_to_str_new(&l_key_addr->data.hash_fast);
        if (l_status == 0) {
            log_it(L_WARNING, "Invalid key %s with directive type %s applying",
                                    l_key_str, a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_KICK ?
                                        "KICK" : "LIFT");
            DAP_DEL_Z(l_key_str);
            return -3;
        }
        const char *l_penalty_group = s_get_penalty_group(l_key_addr->net_id);
        const char *l_directive_hash_str = dap_chain_hash_fast_to_str_new(a_directive_hash);
        const char *l_key_hash_str = dap_chain_hash_fast_to_str_new(&l_key_addr->data.hash_fast);
        if (l_status == 1 && a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_KICK) {
            // Offline will be set in gdb notifier for aim of sync supporting
            dap_global_db_set(l_penalty_group, l_key_str, NULL, 0, false, NULL, 0);
            log_it(L_MSG, "Applied %s directive to exclude validator %s with pkey hash %s from consensus",
                            l_directive_hash_str, l_key_str, l_key_hash_str);
        } else if (l_status == -1 && a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT) {
            // Online will be set in gdb notifier for aim of sync supporting
            dap_global_db_del(l_penalty_group, l_key_str, NULL, 0);
            log_it(L_MSG, "Applied %s directive to include validator %s with pkey hash %s in consensus",
                            l_directive_hash_str, l_key_str, l_key_hash_str);
        } else {
            log_it(L_MSG, "No need to apply directive %s. Validator %s with pkey hash %s already %s consensus",
                            l_directive_hash_str, l_key_str, l_key_hash_str,
                                a_directive->type == DAP_CHAIN_ESBOCS_DIRECTIVE_KICK ?
                                    "excluded from" : "included in");
        }
        DAP_DEL_MULTY(l_key_str, l_penalty_group, l_directive_hash_str, l_key_hash_str);
        break;
    }
    default:
        log_it(L_ERROR, "Unknown directive type %hu to apply", a_directive->type);
        return -2;
    }
    return 0;
}

/**
 * @brief s_session_packet_in
 * @param a_arg
 * @param a_sender_node_addr
 * @param a_data_hash
 * @param a_data
 * @param a_data_size
 */
static void s_session_packet_in(void *a_arg, dap_chain_node_addr_t *a_sender_node_addr, dap_chain_node_addr_t *a_receiver_node_addr,
                                dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size)
{
    dap_chain_esbocs_session_t *l_session = a_arg;
    dap_chain_esbocs_message_t *l_message = (dap_chain_esbocs_message_t *)a_data;
    bool l_cs_debug = PVT(l_session->esbocs)->debug;
    uint16_t l_cs_level = PVT(l_session->esbocs)->min_validators_count;

    if (a_data_size < sizeof(dap_chain_esbocs_message_hdr_t)) {
        log_it(L_WARNING, "Too smalll message size %zu, less than header size %zu", a_data_size, sizeof(dap_chain_esbocs_message_hdr_t));
        return;
    }

    size_t l_message_data_size = l_message->hdr.message_size;
    void *l_message_data = l_message->msg_n_sign;
    dap_chain_hash_fast_t *l_candidate_hash = &l_message->hdr.candidate_hash;
    dap_sign_t *l_sign = (dap_sign_t *)(l_message_data + l_message_data_size);
    size_t l_sign_size = l_message->hdr.sign_size;
    dap_chain_esbocs_round_t *l_round = &l_session->cur_round;
    dap_chain_addr_t l_signing_addr;
    char l_validator_addr_str[DAP_CHAIN_HASH_FAST_STR_SIZE] = {0};

    if (a_sender_node_addr) { //Process network messages only
        pthread_mutex_lock(&l_session->mutex);
        debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                    " Receive pkt type:0x%x from addr:"NODE_ADDR_FP_STR", my_addr:"NODE_ADDR_FP_STR"",
                                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                            l_session->cur_round.attempt_num, l_message->hdr.type,
                                                NODE_ADDR_FP_ARGS(a_sender_node_addr), NODE_ADDR_FP_ARGS_S(l_session->my_addr));
        if (a_receiver_node_addr->uint64 != l_session->my_addr.uint64) {
            debug_if(l_cs_debug, L_MSG, "Wrong packet destination address");
            goto session_unlock;
        }
        if (l_message->hdr.version != DAP_CHAIN_ESBOCS_PROTOCOL_VERSION) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                        " SYNC message is rejected - different protocol version %hu (need %u)",
                                           l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                               l_message->hdr.version, DAP_CHAIN_ESBOCS_PROTOCOL_VERSION);
            goto session_unlock;
        }
        if (sizeof(*l_message) + l_message->hdr.sign_size + l_message->hdr.message_size != a_data_size) {
            log_it(L_WARNING, "incorrect message size in header is %zu when data size is only %zu and header size is %zu",
                   l_message->hdr.sign_size, a_data_size, sizeof(*l_message));
            goto session_unlock;
        }

        if (l_message->hdr.chain_id.uint64 != l_session->chain->id.uint64) {
            debug_if(l_cs_debug, L_MSG, "Invalid chain ID %"DAP_UINT64_FORMAT_U, l_message->hdr.chain_id.uint64);
            goto session_unlock;
        }

        dap_chain_hash_fast_t l_data_hash = {};
        dap_hash_fast(l_message, a_data_size, &l_data_hash);
        if (!dap_hash_fast_compare(a_data_hash, &l_data_hash)) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Message rejected: message hash does not match",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_session->cur_round.attempt_num);
            goto session_unlock;
        }

        l_message->hdr.sign_size = 0;   // restore header on signing time
        if (dap_sign_verify_all(l_sign, l_sign_size, l_message, l_message_data_size + sizeof(l_message->hdr))) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Message rejected from addr:"NODE_ADDR_FP_STR" not passed verification",
                                            l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                l_session->cur_round.attempt_num, NODE_ADDR_FP_ARGS(a_sender_node_addr));
            goto session_unlock;
        }
        l_message->hdr.sign_size = l_sign_size; // restore original header

        // consensus round start sync
        if (l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC) {
            if (!dap_hash_fast_compare(&l_message->hdr.candidate_hash, &l_session->cur_round.last_block_hash)) {
                debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U"."
                                            " Sync message with different last block hash was added to the queue",
                                                l_session->chain->net_name, l_session->chain->name,
                                                    l_session->cur_round.id);
                s_session_sync_queue_add(l_session, l_message, a_data_size);
                goto session_unlock;
            }
        } else if (l_message->hdr.round_id != l_session->cur_round.id) {
            // round check
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                            " Message passed, but round number %"DAP_UINT64_FORMAT_U
                                                " doesn't match message's one %"DAP_UINT64_FORMAT_U,
                                                    l_session->chain->net_name, l_session->chain->name,
                                                        l_session->cur_round.id, l_session->cur_round.attempt_num,
                                                            l_session->cur_round.id, l_message->hdr.round_id);
        }

        // check hash message dup
        dap_chain_esbocs_message_item_t *l_message_item_temp = NULL;
        HASH_FIND(hh, l_round->message_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_message_item_temp);
        if (l_message_item_temp) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Message rejected: message hash is exists in chain (duplicate)",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_message->hdr.attempt_num);
            goto session_unlock;
        }
        dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, l_session->chain->net_id);
        // check messages chain
        dap_chain_esbocs_message_item_t *l_chain_message, *l_chain_message_tmp;
        HASH_ITER(hh, l_round->message_items, l_chain_message, l_chain_message_tmp) {
            bool l_same_type = l_chain_message->message->hdr.type == l_message->hdr.type ||
                    (l_chain_message->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE &&
                        l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_REJECT) ||
                    (l_chain_message->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_REJECT &&
                        l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE) ||
                    (l_chain_message->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR &&
                        l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST) ||
                    (l_chain_message->message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST &&
                        l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR);
            if (l_same_type && dap_chain_addr_compare(&l_chain_message->signing_addr, &l_signing_addr) &&
                    dap_hash_fast_compare(&l_chain_message->message->hdr.candidate_hash, &l_message->hdr.candidate_hash)) {
                if (l_message->hdr.type != DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC || // Not sync or same sync attempt
                        ((struct sync_params *)l_message_data)->attempt ==
                        ((struct sync_params *)l_chain_message->message->msg_n_sign)->attempt) {
                    debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                                " Message rejected: duplicate message %s",
                                                    l_session->chain->net_name, l_session->chain->name,
                                                        l_session->cur_round.id, l_message->hdr.attempt_num,
                                                            s_voting_msg_type_to_str(l_message->hdr.type));
                    goto session_unlock;
                }
            }
        }
        s_message_chain_add(l_session, l_message, a_data_size, a_data_hash, &l_signing_addr);
    } else
        dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, l_session->chain->net_id);

    // Process local & network messages
    if (l_cs_debug)
        dap_chain_hash_fast_to_str_do(&l_signing_addr.data.hash_fast, l_validator_addr_str);

    bool l_not_in_list = false;
    switch (l_message->hdr.type) {
    case DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC:
        // Add local sync messages, cause a round clear
        if (!a_sender_node_addr)
            s_message_chain_add(l_session, l_message, a_data_size, a_data_hash, &l_signing_addr);
        // Accept all validators
        l_not_in_list = !dap_chain_net_srv_stake_key_delegated(&l_signing_addr);
        break;
    case DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR:
    case DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST:
        // Accept all active synced validators
        l_not_in_list = !s_validator_check_synced(&l_signing_addr, l_session->cur_round.all_validators);
        break;
    default:
        // Accept only current round synced validators
        l_not_in_list = !s_validator_check_synced(&l_signing_addr, l_session->cur_round.validators_list);
        break;
    }
    if (l_not_in_list) {
        debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                    " Message rejected: validator addr:%s not in the current validators list or not synced yet",
                                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                            l_message->hdr.attempt_num, l_validator_addr_str);
        goto session_unlock;
    }

    switch (l_message->hdr.type) {
    case DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC: {
        if (l_message_data_size != sizeof(struct sync_params)) {
            log_it(L_WARNING, "Invalid START_SYNC message size");
            break;
        }
        uint64_t l_sync_attempt = ((struct sync_params *)l_message_data)->attempt;
        debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                    " Receive START_SYNC: from validator:%s, sync attempt %"DAP_UINT64_FORMAT_U,
                                        l_session->chain->net_name, l_session->chain->name, l_message->hdr.round_id,
                                            l_validator_addr_str, l_sync_attempt);
        if (!PVT(l_session->esbocs)->emergency_mode &&
                dap_global_db_driver_hash_compare(((struct sync_params *)l_message_data)->db_hash, l_session->db_hash)) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", sync_attempt %"DAP_UINT64_FORMAT_U
                                        " SYNC message is rejected cause DB hash mismatch",
                                           l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                               l_session->cur_round.sync_attempt);
            break;
        }
        if (l_sync_attempt != l_session->cur_round.sync_attempt) {
            if (l_sync_attempt < l_session->cur_round.sync_attempt) {
                 debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                             " SYNC message is rejected because current sync attempt %"DAP_UINT64_FORMAT_U
                                             " is greater than meassage sync attempt %"DAP_UINT64_FORMAT_U,
                                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                    l_session->cur_round.sync_attempt, l_sync_attempt);
                 break;
            } else {
                uint64_t l_attempts_miss = l_sync_attempt - l_session->cur_round.sync_attempt;
                uint32_t l_attempts_miss_max = UINT16_MAX; // TODO calculate it rely on last block aceeption time & min round duration
                if (l_attempts_miss > l_attempts_miss_max) {
                    debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                                " SYNC message is rejected - too much sync attempt difference %"DAP_UINT64_FORMAT_U,
                                                   l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                       l_attempts_miss);
                    break;
                } else {
                    debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                                " SYNC message sync attempt %"DAP_UINT64_FORMAT_U" is greater than"
                                                " current round sync attempt %"DAP_UINT64_FORMAT_U" so fast-forward this round",
                                                   l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                       l_sync_attempt, l_session->cur_round.sync_attempt);
                    // Process this message in new round, it will increment current sync attempt
                    s_session_sync_queue_add(l_session, l_message, a_data_size);
                    l_session->round_fast_forward = true;
                    l_session->cur_round.id = l_message->hdr.round_id - 1;
                    l_session->cur_round.sync_attempt = l_sync_attempt - 1;
                    s_session_round_new(l_session);
                }
            }
        } else // Send it immediatly, if was not sent yet
            s_session_send_startsync(l_session);

        s_session_validator_mark_online(l_session, &l_signing_addr);
        dap_list_t *l_list = s_validator_check(&l_signing_addr, l_session->cur_round.validators_list);
        if (!l_list)
            break;
        dap_chain_esbocs_validator_t *l_validator = l_list->data;
        if (!l_validator->is_synced) {
            l_validator->is_synced = true;
            if (++l_session->cur_round.validators_synced_count == dap_list_length(l_session->cur_round.validators_list)) {
                l_session->cur_round.id = s_session_calc_current_round_id(l_session);
                debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                            " All validators are synchronized, wait to submit candidate",
                                                l_session->chain->net_name, l_session->chain->name,
                                                    l_session->cur_round.id, l_message->hdr.attempt_num);
                s_session_state_change(l_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC, dap_time_now());
            }
        }
    } break;

    case DAP_CHAIN_ESBOCS_MSG_TYPE_SUBMIT: {
        uint8_t *l_candidate = l_message_data;
        size_t l_candidate_size = l_message_data_size;
        if (!l_candidate_size || dap_hash_fast_is_blank(&l_message->hdr.candidate_hash)) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Receive SUBMIT candidate NULL",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_message->hdr.attempt_num);
            if (dap_chain_addr_compare(&l_session->cur_round.attempt_submit_validator, &l_signing_addr))
                s_session_attempt_new(l_session);
            break;
        }
        // check candidate hash
        dap_chain_hash_fast_t l_check_hash;
        dap_hash_fast(l_candidate, l_candidate_size, &l_check_hash);
        if (!dap_hash_fast_compare(&l_check_hash, l_candidate_hash)) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Receive SUBMIT candidate hash broken",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_message->hdr.attempt_num);
            break;
        }

        if (l_cs_debug) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                            " Receive SUBMIT candidate %s, size %zu",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_message->hdr.attempt_num, l_candidate_hash_str, l_candidate_size);
        }

        dap_chain_esbocs_store_t *l_store;
        HASH_FIND(hh, l_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
        if (l_store) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_WARNING, "Duplicate candidate: %s", l_candidate_hash_str);
            break;
        }

        // store for new candidate
        l_store = DAP_NEW_Z(dap_chain_esbocs_store_t);
        if (!l_store) {
            log_it(L_CRITICAL, "Memory allocation error");
            goto session_unlock;
        }
        l_store->candidate_size = l_candidate_size;
        l_store->candidate_hash = *l_candidate_hash;
        l_store->candidate = DAP_DUP_SIZE(l_candidate, l_candidate_size);

        // save new block candidate
        HASH_ADD(hh, l_session->cur_round.store_items, candidate_hash, sizeof(dap_hash_fast_t), l_store);
        // check it and send APPROVE/REJECT
        if (dap_chain_addr_compare(&l_session->cur_round.attempt_submit_validator, &l_signing_addr)) {
            l_session->cur_round.attempt_candidate_hash = *l_candidate_hash;
            s_session_state_change(l_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_SIGNS, dap_time_now());
            s_session_candidate_verify(l_session, l_store->candidate, l_store->candidate_size, &l_store->candidate_hash);
        }
    } break;

    case DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE:
    case DAP_CHAIN_ESBOCS_MSG_TYPE_REJECT: {
        dap_chain_esbocs_store_t *l_store;
        char *l_candidate_hash_str = NULL;
        bool l_approve = l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE;
        HASH_FIND(hh, l_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
        if (!l_store) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                " Receive %s message for unknown candidate %s, process it later",
                                   l_session->chain->net_name, l_session->chain->name,
                                       l_session->cur_round.id, l_message->hdr.attempt_num,
                                            l_approve ? "APPROVE" : "REJECT", l_candidate_hash_str);
            dap_chain_esbocs_message_item_t *l_unprocessed_item = NULL;
            HASH_FIND(hh, l_round->message_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_unprocessed_item);
            if (l_unprocessed_item)
                l_unprocessed_item->unprocessed = true;
            break;
        }

        if (l_cs_debug) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                            " Receive %s: candidate %s",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_message->hdr.attempt_num, l_approve ? "APPROVE" : "REJECT", l_candidate_hash_str);
        }
        if (l_approve && ++l_store->approve_count >= l_cs_level && !l_store->decide_approve &&
                dap_hash_fast_compare(&l_session->cur_round.attempt_candidate_hash, l_candidate_hash)) {
            l_store->decide_approve = true;
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Candidate %s approved by minimum number of validators, let's sign it",
                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                            l_message->hdr.attempt_num, l_candidate_hash_str);
            size_t l_offset = dap_chain_block_get_sign_offset(l_store->candidate, l_store->candidate_size);
            dap_sign_t *l_candidate_sign = dap_sign_create(PVT(l_session->esbocs)->blocks_sign_key,
                                            l_store->candidate, l_offset + sizeof(l_store->candidate->hdr), 0);
            size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
            s_message_send(l_session, DAP_CHAIN_ESBOCS_MSG_TYPE_COMMIT_SIGN, l_candidate_hash,
                           l_candidate_sign, l_candidate_sign_size, l_session->cur_round.validators_list);
            DAP_DELETE(l_candidate_sign);
        }
        if (!l_approve && ++l_store->reject_count >= l_cs_level && !l_store->decide_reject &&
                dap_hash_fast_compare(&l_session->cur_round.attempt_candidate_hash, l_candidate_hash)) {
            l_store->decide_reject = true;
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Candidate %s rejected by minimum number of validators, attempt failed",
                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                            l_message->hdr.attempt_num, l_candidate_hash_str);
            s_session_attempt_new(l_session);
        }
    } break;

    case DAP_CHAIN_ESBOCS_MSG_TYPE_COMMIT_SIGN: {
        if (l_message_data_size < sizeof(dap_sign_t)) {
            log_it(L_WARNING, "Wrong commit_sign message size, have %zu bytes for candidate sign section"
                                " when requires at least %zu bytes",
                                  l_message_data_size, sizeof(dap_sign_t));
            break;
        }
        dap_sign_t *l_candidate_sign = (dap_sign_t *)l_message_data;
        size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
        if (l_candidate_sign_size != l_message_data_size) {
            log_it(L_WARNING, "Wrong commit_sign message size, have %zu bytes for candidate sign section"
                                " when requires %zu bytes",
                                  l_candidate_sign_size, l_message_data_size);
            break;
        }

        dap_chain_esbocs_store_t *l_store;
        char *l_candidate_hash_str = NULL;
        HASH_FIND(hh, l_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
        if (!l_store) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_WARNING, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                " Receive COMMIT_SIGN message for unknown candidate %s",
                                    l_session->chain->net_name, l_session->chain->name,
                                        l_session->cur_round.id, l_message->hdr.attempt_num,
                                            l_candidate_hash_str);
            break;
        }

        if (l_cs_debug) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                            " Receive COMMIT_SIGN: candidate %s",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_message->hdr.attempt_num, l_candidate_hash_str);
        }

        size_t l_offset = dap_chain_block_get_sign_offset(l_store->candidate, l_store->candidate_size);
        int l_sign_verified = dap_sign_verify(l_candidate_sign, l_store->candidate,
                                                l_offset + sizeof(l_store->candidate->hdr));
        // check candidate's sign
        if (!l_sign_verified) {
            l_store->candidate_signs = dap_list_append(l_store->candidate_signs,
                                                       DAP_DUP_SIZE(l_candidate_sign, l_candidate_sign_size));
            if (dap_list_length(l_store->candidate_signs) == l_round->validators_synced_count) {
                if (PVT(l_session->esbocs)->debug)
                    log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                  " Candidate %s collected signs of all synced validators",
                                        l_session->chain->net_name, l_session->chain->name, l_round->id,
                                            l_message->hdr.attempt_num, l_candidate_hash_str);
                s_session_state_change(l_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH, dap_time_now());
            }
        } else {
            if (!l_candidate_hash_str)
                l_candidate_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_WARNING, "Candidate: %s sign is incorrect: code %d", l_candidate_hash_str, l_sign_verified);
        }
    } break;

    case DAP_CHAIN_ESBOCS_MSG_TYPE_DIRECTIVE: {
        if (l_session->cur_round.directive) {
            log_it(L_WARNING, "Only one directive can be processed by round");
            break;
        }
        dap_chain_esbocs_directive_t *l_directive = l_message_data;
        size_t l_directive_size = l_message_data_size;
        if (l_directive_size < sizeof(dap_chain_esbocs_directive_t) || l_directive_size != l_directive->size) {
            log_it(L_WARNING, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                              " Receive DIRECTIVE with invalid size %zu)",
                                    l_session->chain->net_name, l_session->chain->name,
                                        l_session->cur_round.id, l_message->hdr.attempt_num,
                                            l_directive_size);
            break;
        }
        // check directive hash
        dap_chain_hash_fast_t l_directive_hash;
        dap_hash_fast(l_directive, l_directive_size, &l_directive_hash);
        if (!dap_hash_fast_compare(&l_directive_hash, l_candidate_hash)) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        " Receive DIRECTIVE hash broken",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_message->hdr.attempt_num);
            break;
        }
        if (l_cs_debug) {
            char *l_dirtective_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                            " Receive DIRECTIVE hash %s, size %zu",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_message->hdr.attempt_num, l_dirtective_hash_str, l_directive_size);
        }
        s_session_directive_process(l_session, l_directive, &l_directive_hash);
    } break;

    case DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR:
    case DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST: {
        if (dap_hash_fast_is_blank(l_candidate_hash)) {
            log_it(L_WARNING, "Receive VOTE %s for empty directive",
                                    l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR ?
                                        "FOR" : "AGAINST");
            break;
        }
        if (!dap_hash_fast_compare(&l_session->cur_round.directive_hash, l_candidate_hash)) {
            debug_if(l_cs_debug, L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                                        "Received VOTE %s unknown directive, it will be processed later",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_message->hdr.attempt_num,
                                                    l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR ?
                                                        "FOR" : "AGAINST");
            dap_chain_esbocs_message_item_t *l_unprocessed_item = NULL;
            HASH_FIND(hh, l_round->message_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_unprocessed_item);
            if (l_unprocessed_item)
                l_unprocessed_item->unprocessed = true;
            break;
        }
        if (l_cs_debug) {
            char *l_directive_hash_str = dap_chain_hash_fast_to_str_static(l_candidate_hash);
            log_it(L_MSG, "net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hhu."
                            " Receive VOTE %s directive %s",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_message->hdr.attempt_num, l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR ?
                                    "FOR" : "AGAINST", l_directive_hash_str);
        }
        if (l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR) {
            if (!l_session->cur_round.directive_applied &&
                    ++l_session->cur_round.votes_for_count * 3 >=
                        dap_list_length(l_session->cur_round.all_validators) * 2) {
                s_session_directive_apply(l_session->cur_round.directive, &l_session->cur_round.directive_hash);
                l_session->cur_round.directive_applied = true;
                s_session_state_change(l_session, DAP_CHAIN_ESBOCS_SESSION_STATE_PREVIOUS, dap_time_now());
            }
        } else // l_message->hdr.type == DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST
            if (++l_session->cur_round.votes_against_count * 3 >=
                    dap_list_length(l_session->cur_round.all_validators) * 2)
                s_session_state_change(l_session, DAP_CHAIN_ESBOCS_SESSION_STATE_PREVIOUS, dap_time_now());
    } break;

    case DAP_CHAIN_ESBOCS_MSG_TYPE_PRE_COMMIT:
        s_session_candidate_precommit(l_session, l_message);
    default:
        break;
    }
session_unlock:
    if (a_sender_node_addr) //Process network message
        pthread_mutex_unlock(&l_session->mutex);
}

static void s_message_send(dap_chain_esbocs_session_t *a_session, uint8_t a_message_type, dap_hash_fast_t *a_block_hash,
                                    const void *a_data, size_t a_data_size, dap_list_t *a_validators)
{
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_session->chain->net_id);
    size_t l_message_size = sizeof(dap_chain_esbocs_message_hdr_t) + a_data_size;
    dap_chain_esbocs_message_t *l_message = NULL;
    DAP_NEW_Z_SIZE_RET(l_message, dap_chain_esbocs_message_t, l_message_size, NULL);
    l_message->hdr.version = DAP_CHAIN_ESBOCS_PROTOCOL_VERSION;
    l_message->hdr.round_id = a_session->cur_round.id;
    l_message->hdr.attempt_num = a_session->cur_round.attempt_num;
    l_message->hdr.chain_id = a_session->chain->id;
    l_message->hdr.ts_created = dap_time_now();
    l_message->hdr.type = a_message_type;
    l_message->hdr.message_size = a_data_size;
    l_message->hdr.candidate_hash = *a_block_hash;
    if (a_data && a_data_size)
        memcpy(l_message->msg_n_sign, a_data, a_data_size);

    dap_sign_t *l_sign = dap_sign_create(PVT(a_session->esbocs)->blocks_sign_key, l_message,
                                         sizeof(l_message->hdr) + a_data_size, 0);
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_message_size += l_sign_size;
    l_message = DAP_REALLOC(l_message, l_message_size);
    if (!l_message) {
        log_it(L_CRITICAL, "Memory allocation error");
        return;
    }
    memcpy(l_message->msg_n_sign + a_data_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    l_message->hdr.sign_size = l_sign_size;

    dap_stream_ch_chain_voting_pkt_t *l_voting_pkt =
            dap_stream_ch_chain_voting_pkt_new(l_net->pub.id.uint64, &a_session->my_addr,
                                               NULL, l_message, l_message_size);
    DAP_DELETE(l_message);

    for (dap_list_t *it = a_validators; it; it = it->next) {
        dap_chain_esbocs_validator_t *l_validator = it->data;
        if (l_validator->is_synced ||
                a_message_type == DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC) {
            debug_if(PVT(a_session->esbocs)->debug, L_MSG, "Send pkt type 0x%x to "NODE_ADDR_FP_STR,
                                                            a_message_type, NODE_ADDR_FP_ARGS_S(l_validator->node_addr));
            l_voting_pkt->hdr.receiver_node_addr = l_validator->node_addr;
            dap_stream_ch_chain_voting_message_write(l_net, &l_validator->node_addr, l_voting_pkt);
        }
    }
    DAP_DELETE(l_voting_pkt);
}


static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size)
{
    assert(a_blocks);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(a_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);
    if (!l_esbocs_pvt->blocks_sign_key) {
        log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [esbocs] section");
        return 0;
    }
    if (!a_block_ptr || !(*a_block_ptr) || !a_block_size) {
        log_it(L_WARNING, "Block size or block pointer is NULL");
        return 0;
    }
    return dap_chain_block_sign_add(a_block_ptr, a_block_size, l_esbocs_pvt->blocks_sign_key);
}

static int s_callback_block_verify(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size)
{
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(a_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);

    if (sizeof(a_block->hdr) >= a_block_size) {
        log_it(L_WARNING, "Incorrect header size with block %p on chain %s", a_block, a_blocks->chain->name);
        return  -7;
    }

    /*if (a_block->hdr.meta_n_datum_n_signs_size != a_block_size - sizeof(a_block->hdr)) {
        log_it(L_WARNING, "Incorrect size with block %p on chain %s", a_block, a_blocks->chain->name);
        return -8;
    }*/ // TODO Retun it after hard-fork with correct block sizes

    if (l_esbocs->session && l_esbocs->session->processing_candidate == a_block)
        // It's a block candidate, don't check signs
        return 0;

    size_t l_offset = dap_chain_block_get_sign_offset(a_block, a_block_size);
    if (!l_offset) {
        log_it(L_WARNING, "Block with size %zu parsing error", a_block_size);
        return -5;
    }
    size_t l_signs_count = 0;
    dap_sign_t **l_signs = dap_sign_get_unique_signs(a_block->meta_n_datum_n_sign+l_offset,
                                            a_block_size-sizeof(a_block->hdr)-l_offset, &l_signs_count);
    if (!l_signs_count){
        log_it(L_ERROR, "No any signatures at all for block");
        DAP_DELETE(l_signs);
        return -2;
    }

    if (l_signs_count < l_esbocs_pvt->min_validators_count) {
        log_it(L_ERROR, "Corrupted block: not enough signs: %zu of %hu", l_signs_count, l_esbocs_pvt->min_validators_count);
        DAP_DELETE(l_signs);
        return -1;
    }

    // Parse the rest signs
    int l_ret = 0;
    uint16_t l_signs_verified_count = 0;
    size_t l_block_excl_sign_size = dap_chain_block_get_sign_offset(a_block, a_block_size) + sizeof(a_block->hdr);
    // Get the header on signing operation time
    size_t l_block_original = a_block->hdr.meta_n_datum_n_signs_size;
    a_block->hdr.meta_n_datum_n_signs_size = l_block_excl_sign_size - sizeof(a_block->hdr);
    for (size_t i=0; i< l_signs_count; i++) {
        dap_sign_t *l_sign = (dap_sign_t *)l_signs[i];
        if (!dap_sign_verify_size(l_sign, a_block_size - l_block_excl_sign_size + sizeof(a_block->hdr))) {
            log_it(L_ERROR, "Corrupted block: sign size is bigger than block size");
            l_ret = -3;
            break;
        }

        dap_chain_addr_t l_signing_addr;
        dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, a_blocks->chain->net_id);
        if (!l_esbocs_pvt->poa_mode) {
             // Compare signature with delegated keys
            if (!dap_chain_net_srv_stake_key_delegated(&l_signing_addr)) {
                log_it(L_ATT, "Unknown PoS signer %s",
                    dap_chain_hash_fast_to_str_static(&l_signing_addr.data.hash_fast));
                continue;
            }
        } else {
            // Compare signature with auth_certs
            if (!s_validator_check(&l_signing_addr, l_esbocs_pvt->poa_validators)) {
                log_it(L_ATT, "Unknown PoA signer %s",
                    dap_chain_hash_fast_to_str_static(&l_signing_addr.data.hash_fast));
                continue;
            }
        }
        if (!dap_sign_verify(l_sign, a_block, l_block_excl_sign_size))
            l_signs_verified_count++;
    }
    DAP_DELETE(l_signs);
    // Restore the original header
    a_block->hdr.meta_n_datum_n_signs_size = l_block_original;

    if (l_signs_verified_count < l_esbocs_pvt->min_validators_count) {
        dap_hash_fast_t l_block_hash;
        dap_hash_fast(a_block, a_block_size, &l_block_hash);
        char l_block_hash_str[DAP_CHAIN_HASH_FAST_STR_SIZE];
        dap_hash_fast_to_str(&l_block_hash, l_block_hash_str, DAP_CHAIN_HASH_FAST_STR_SIZE);
        log_it(L_ERROR, "Corrupted block %s: not enough authorized signs: %u of %u",
                    l_block_hash_str, l_signs_verified_count, l_esbocs_pvt->min_validators_count);
        return l_ret ? l_ret : -4;
    }
    return 0;
}

static char *s_esbocs_decree_put(dap_chain_datum_decree_t *a_decree, dap_chain_net_t *a_net)
{
    // Put the transaction to mempool or directly to chains
    size_t l_decree_size = dap_chain_datum_decree_get_size(a_decree);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, a_decree, l_decree_size);
    dap_chain_t *l_chain = dap_chain_net_get_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if (!l_chain) {
        return NULL;
    }
    // Processing will be made according to autoprocess policy
    char *l_ret = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    DAP_DELETE(l_datum);
    return l_ret;
}

static dap_chain_datum_decree_t *s_esbocs_decree_set_min_validators_count(dap_chain_net_t *a_net, dap_chain_t *a_chain,
                                                                          uint256_t a_value, dap_cert_t *a_cert)
{
    size_t l_total_tsd_size = sizeof(dap_tsd_t) + sizeof(uint256_t);
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;
// memory alloc
    DAP_NEW_Z_SIZE_RET_VAL(l_tsd, dap_tsd_t, l_total_tsd_size, NULL, NULL);
    DAP_NEW_Z_SIZE_RET_VAL(l_decree, dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size, NULL, l_tsd);

    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT;
    l_tsd->size = sizeof(uint256_t);
    *(uint256_t*)(l_tsd->data) = a_value;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    dap_chain_t *l_chain = a_chain;
    if (!a_chain)
        l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_ANCHOR);
    if(!l_chain){
        log_it(L_ERROR, "Can't find chain with anchor support.");
        dap_list_free_full(l_tsd_list, NULL);
        DAP_DELETE(l_decree);
        return NULL;
    }
    l_decree->header.common_decree_params.chain_id = l_chain->id;
    l_decree->header.common_decree_params.cell_id = *dap_chain_net_get_cur_cell(a_net);
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT;
    l_decree->header.data_size = l_total_tsd_size;
    l_decree->header.signs_size = 0;

    size_t l_data_tsd_offset = 0;
    for ( dap_list_t* l_iter=dap_list_first(l_tsd_list); l_iter; l_iter=l_iter->next){
        dap_tsd_t * l_b_tsd = (dap_tsd_t *) l_iter->data;
        size_t l_tsd_size = dap_tsd_size(l_b_tsd);
        memcpy((byte_t*)l_decree->data_n_signs + l_data_tsd_offset, l_b_tsd, l_tsd_size);
        l_data_tsd_offset += l_tsd_size;
    }
    dap_list_free_full(l_tsd_list, NULL);

    size_t l_cur_sign_offset = l_decree->header.data_size + l_decree->header.signs_size;
    size_t l_total_signs_size = l_decree->header.signs_size;

    dap_sign_t * l_sign = dap_cert_sign(a_cert,  l_decree,
       sizeof(dap_chain_datum_decree_t) + l_decree->header.data_size, 0);

    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_decree = DAP_REALLOC(l_decree, sizeof(dap_chain_datum_decree_t) + l_cur_sign_offset + l_sign_size);
        if (!l_decree) {
            log_it(L_CRITICAL, "Memory allocation error");
            DAP_DELETE(l_sign);
            return NULL;
        }
        memcpy((byte_t*)l_decree->data_n_signs + l_cur_sign_offset, l_sign, l_sign_size);
        l_total_signs_size += l_sign_size;
        l_cur_sign_offset += l_sign_size;
        l_decree->header.signs_size = l_total_signs_size;
        DAP_DELETE(l_sign);
        log_it(L_DEBUG,"<-- Signed with '%s'", a_cert->name);
    }else{
        log_it(L_ERROR, "Decree signing failed");
        DAP_DELETE(l_decree);
        return NULL;
    }

    return l_decree;
}

/**
 * @brief
 * parse and execute cellframe-node-cli esbocs commands
 * @param argc arguments count
 * @param argv array with arguments
 * @param arg_func
 * @param str_reply
 * @return
 */
static int s_cli_esbocs(int a_argc, char **a_argv, void **a_str_reply)
{
    int ret = -666;
    int l_arg_index = 2;
    dap_chain_net_t * l_chain_net = NULL;
    dap_chain_t * l_chain = NULL;
    const char *l_cert_str = NULL,
               *l_value_str = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index, a_argc, a_argv, a_str_reply, &l_chain, &l_chain_net))
        return -3;
    const char *l_chain_type = dap_chain_net_get_type(l_chain);
    if (strcmp(l_chain_type, "esbocs")) {
            dap_cli_server_cmd_set_reply_text(a_str_reply,
                        "Type of chain \"%s\" is not block. Chain with current consensus \"%s\" is not supported by this command",
                        l_chain->name, l_chain_type);
            return ret;
    }

    if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, l_arg_index + 1, "set", NULL)) {
        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
        if (!l_cert_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'min_validators_count' requires parameter -cert");
            return -3;
        }
        dap_cert_t *l_poa_cert = dap_cert_find_by_name(l_cert_str);
        if (!l_poa_cert) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
            return -25;
        }

        dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-val_count", &l_value_str);
        if (!l_value_str) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'min_validators_count' requires parameter -val_count");
            return -9;
        }
        uint256_t l_value = dap_chain_balance_scan(l_value_str);
        if (IS_ZERO_256(l_value)) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized number in '-val_count' param");
            return -10;
        }

        dap_chain_datum_decree_t *l_decree = s_esbocs_decree_set_min_validators_count(
                                                l_chain_net, l_chain, l_value, l_poa_cert);
        char *l_decree_hash_str = NULL;
        if (l_decree && (l_decree_hash_str = s_esbocs_decree_put(l_decree, l_chain_net))) {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Minimum validators count has been set."
                                                           " Decree hash %s", l_decree_hash_str);
            DAP_DEL_MULTY(l_decree, l_decree_hash_str);
        } else {
            dap_cli_server_cmd_set_reply_text(a_str_reply, "Minimum validators count setting failed");
            DAP_DEL_Z(l_decree);
            return -21;
        }
    } else if (dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, l_arg_index + 1, "print", NULL)) {
        dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
        dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
        dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Minimum validators count is %d",
                                          l_esbocs_pvt->min_validators_count);
    } else
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized subcommand '%s'", a_argv[l_arg_index]);
    return ret;
}
