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
    DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH
};

static dap_list_t *s_validator_check(dap_chain_addr_t *a_addr, dap_list_t *a_validators);
static void s_get_last_block_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_last_hash_ptr);
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
static void s_callback_set_min_validators_count(dap_chain_t *a_chain, uint16_t a_new_value);

static int s_cli_esbocs(int argc, char ** argv, char **str_reply);

DAP_STATIC_INLINE const char *s_voting_msg_type_to_str(uint8_t a_type)
{
    switch (a_type) {
    case DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC: return "START_SYNC";
    case DAP_STREAM_CH_VOTING_MSG_TYPE_SUBMIT: return "SUBMIT";
    case DAP_STREAM_CH_VOTING_MSG_TYPE_APPROVE: return "APPROVE";
    case DAP_STREAM_CH_VOTING_MSG_TYPE_REJECT: return "REJECT";
    case DAP_STREAM_CH_VOTING_MSG_TYPE_COMMIT_SIGN: return "COMMIT_SIGN";
    //case DAP_STREAM_CH_VOTING_MSG_TYPE_VOTE: return "VOTE";
    //case DAP_STREAM_CH_VOTING_MSG_TYPE_VOTE_FOR: return "VOTE_FOR"
    case DAP_STREAM_CH_VOTING_MSG_TYPE_PRE_COMMIT: return "PRE_COMMIT";
    default: return "UNKNOWN";
    }
}

static dap_chain_esbocs_session_t * s_session_items;
static dap_timerfd_t *s_session_cs_timer = NULL;

typedef struct dap_chain_esbocs_pvt {
    // Base params
    dap_enc_key_t *blocks_sign_key;
    dap_hash_fast_t candidate_hash;
    dap_chain_addr_t *fee_addr;
    // Validators section
    bool poa_mode;
    uint16_t min_validators_count;
    // Debug flag
    bool debug;
    // Round params
    uint16_t new_round_delay;
    uint16_t round_start_sync_timeout;
    uint16_t round_attempts_max;
    uint16_t round_attempt_timeout;
    // PoA section
    dap_list_t *poa_validators;  
    uint256_t minimum_fee;
} dap_chain_esbocs_pvt_t;

#define PVT(a) ((dap_chain_esbocs_pvt_t *)a->_pvt)

int dap_chain_cs_esbocs_init()
{
    dap_stream_ch_chain_voting_init();
    dap_chain_cs_add("esbocs", s_callback_new);
    dap_cli_server_cmd_add ("esbocs", s_cli_esbocs, "ESBOCS commands",
        "esbocs min_validators_count -net <net_name> -chain <chain_name> -cert <poa_cert_name> -val_count <value>"
            "\tSets minimum validators count for ESBOCS consensus\n\n");
    return 0;
}

void dap_chain_cs_esbocs_deinit(void)
{
}

static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg)
{
    dap_chain_cs_blocks_new(a_chain, a_chain_cfg);
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    l_blocks->callback_delete = s_callback_delete;
    l_blocks->callback_block_verify = s_callback_block_verify;
    l_blocks->callback_block_sign = s_callback_block_sign;
    dap_chain_esbocs_t *l_esbocs = DAP_NEW_Z(dap_chain_esbocs_t);
    l_esbocs->chain = a_chain;
    l_esbocs->blocks = l_blocks;
    dap_chain_esbocs_session_t *l_session = DAP_NEW_Z(dap_chain_esbocs_session_t);
    l_session->chain = a_chain;
    l_session->esbocs = l_esbocs;

    l_esbocs->chain->callback_set_min_validators_count = s_callback_set_min_validators_count;

    l_esbocs->session = l_session;
    l_blocks->_inheritor = l_esbocs;

    l_esbocs->_pvt = DAP_NEW_Z(dap_chain_esbocs_pvt_t);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);

    a_chain->callback_get_minimum_fee = s_callback_get_minimum_fee;

    l_esbocs_pvt->debug = dap_config_get_item_bool_default(a_chain_cfg, "esbocs", "consensus_debug", false);
    l_esbocs_pvt->poa_mode = dap_config_get_item_bool_default(a_chain_cfg, "esbocs", "poa_mode", false);
    l_esbocs_pvt->round_start_sync_timeout = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "round_start_sync_timeout", 15);
    l_esbocs_pvt->new_round_delay = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "new_round_delay", 10);
    l_esbocs_pvt->round_attempts_max = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "round_attempts_max", 4);
    l_esbocs_pvt->round_attempt_timeout = dap_config_get_item_uint16_default(a_chain_cfg, "esbocs", "round_attempt_timeout", 10);

    int l_ret = 0;
    l_esbocs_pvt->min_validators_count = dap_config_get_item_uint16(a_chain_cfg, "esbocs", "min_validators_count");
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
    for (size_t i = 0; i < l_auth_certs_count; i++) {
        snprintf(l_cert_name, sizeof(l_cert_name), "%s.%zu", l_auth_certs_prefix, i);
        if ((l_cert_cur = dap_cert_find_by_name(l_cert_name)) == NULL) {
            snprintf(l_cert_name, sizeof(l_cert_name), "%s.%zu.pub", l_auth_certs_prefix, i);
            if ((l_cert_cur = dap_cert_find_by_name(l_cert_name)) == NULL) {
                log_it(L_ERROR, "ESBOCS: Can't find cert \"%s\"", l_cert_name);
                l_ret = -3;
                goto lb_err;
            }
        }
        dap_chain_addr_t l_signing_addr;
        log_it(L_NOTICE, "ESBOCS: Initialized auth cert \"%s\"", l_cert_name);
        dap_chain_addr_fill_from_key(&l_signing_addr, l_cert_cur->enc_key, a_chain->net_id);
        dap_chain_node_addr_t l_signer_node_addr;
        if (dap_chain_node_addr_from_str(&l_signer_node_addr, l_addrs[i])) {
            log_it(L_ERROR,"ESBOCS: Wrong address format, should be like 0123::4567::89AB::CDEF");
            l_ret = -4;
            goto lb_err;
        }
        log_it(L_MSG, "ESBOCS: add validator addr:"NODE_ADDR_FP_STR"", NODE_ADDR_FP_ARGS_S(l_signer_node_addr));
        if (l_esbocs_pvt->poa_mode) { // auth by certs in PoA mode
            dap_chain_esbocs_validator_t *l_validator = DAP_NEW(dap_chain_esbocs_validator_t);
            l_validator->signing_addr = l_signing_addr;
            l_validator->node_addr = l_signer_node_addr;
            l_validator->weight = uint256_1;
            l_esbocs_pvt->poa_validators = dap_list_append(l_esbocs_pvt->poa_validators, l_validator);
        } else {
            dap_hash_fast_t l_stake_tx_hash = {};
            dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
            uint256_t l_weight = dap_chain_net_srv_stake_get_allowed_min_value();
            dap_chain_net_srv_stake_key_delegate(l_net, &l_signing_addr, &l_stake_tx_hash,
                                                 l_weight, &l_signer_node_addr);
        }
    }
    l_blocks->chain->callback_created = s_callback_created;
    return 0;

lb_err:
    dap_list_free_full(l_esbocs_pvt->poa_validators, NULL);
    DAP_DELETE(l_esbocs_pvt);
    DAP_DELETE(l_esbocs);
    l_blocks->_inheritor = NULL;
    l_blocks->callback_delete = NULL;
    l_blocks->callback_block_verify = NULL;
    return l_ret;
}

static void s_new_atom_notifier(void *a_arg, UNUSED_ARG dap_chain_t *a_chain, UNUSED_ARG dap_chain_cell_id_t a_id,
                             UNUSED_ARG void* a_atom, UNUSED_ARG size_t a_atom_size)
{
    dap_chain_esbocs_session_t *l_session = a_arg;
    pthread_mutex_lock(&l_session->mutex);
    dap_chain_hash_fast_t l_last_block_hash;
    s_get_last_block_hash(l_session->chain, &l_last_block_hash);
    if (!dap_hash_fast_compare(&l_last_block_hash, &l_session->cur_round.last_block_hash))
        s_session_round_new(l_session);
    pthread_mutex_unlock(&l_session->mutex);
}

static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg)
{

    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);

    l_esbocs_pvt->minimum_fee = dap_chain_coins_to_balance(dap_config_get_item_str_default(a_chain_net_cfg, "esbocs", "minimum_fee", "0.05"));
    l_esbocs_pvt->fee_addr = dap_chain_addr_from_str(dap_config_get_item_str(a_chain_net_cfg, "esbocs", "fee_addr"));

    const char *l_sign_cert_str = NULL;
    if ((l_sign_cert_str = dap_config_get_item_str(a_chain_net_cfg, "esbocs", "blocks-sign-cert")) != NULL) {
        dap_cert_t *l_sign_cert = dap_cert_find_by_name(l_sign_cert_str);
        if (l_sign_cert == NULL) {
            log_it(L_ERROR, "Can't load sign certificate, name \"%s\" is wrong", l_sign_cert_str);
            return 0;
        } else if (l_sign_cert->enc_key->priv_key_data) {
            l_esbocs_pvt->blocks_sign_key = l_sign_cert->enc_key;
            log_it(L_INFO, "Loaded \"%s\" certificate to sign ESBOCS blocks", l_sign_cert_str);
        } else {
            log_it(L_ERROR, "Certificate \"%s\" has no private key", l_sign_cert_str);
            return 0;
        }
    } else {
        log_it(L_NOTICE, "No sign certificate provided, can't sign any blocks. This node can't be a consensus validator");
        return 0;
    }

    dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
    dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net);
    if (l_role.enums > NODE_ROLE_MASTER) {
        log_it(L_NOTICE, "Node role is lower than master role, so this node can't be a consensus validator");
        return 0;
    }

    dap_chain_addr_t l_my_signing_addr;
    dap_chain_addr_fill_from_key(&l_my_signing_addr, l_esbocs_pvt->blocks_sign_key, a_chain->net_id);
    if (!l_esbocs_pvt->poa_mode) {
        if (!dap_chain_net_srv_stake_key_delegated(&l_my_signing_addr)) {
            log_it(L_WARNING, "Signing key is not delegated by stake service. Switch off validator mode");
            return 0;
        }
    } else {
        if (!s_validator_check(&l_my_signing_addr, l_esbocs_pvt->poa_validators)) {
            log_it(L_WARNING, "Signing key is not present in PoA certs list. Switch off validator mode");
            return 0;
        }
    }

    dap_chain_esbocs_session_t *l_session = l_esbocs->session;
    l_session->my_addr.uint64 = dap_chain_net_get_cur_addr_int(l_net);
    l_session->my_signing_addr = l_my_signing_addr;
    pthread_mutexattr_t l_mutex_attr;
    pthread_mutexattr_init(&l_mutex_attr);
    pthread_mutexattr_settype(&l_mutex_attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&l_session->mutex, &l_mutex_attr);
    pthread_mutexattr_destroy(&l_mutex_attr);
    dap_stream_ch_chain_voting_in_callback_add(l_session, s_session_packet_in);
    dap_chain_add_callback_notify(a_chain, s_new_atom_notifier, l_session);
    s_session_round_new(l_session);

    log_it(L_INFO, "ESBOCS: init session for net:%s, chain:%s", a_chain->net_name, a_chain->name);
    DL_APPEND(s_session_items, l_session);
    if (!s_session_cs_timer) {
        s_session_cs_timer = dap_timerfd_start(1000, s_session_timer, NULL);
        debug_if(l_esbocs_pvt->debug, L_MSG, "ESBOCS: Consensus main timer is started");
    }
    return 0;
}

static uint256_t s_callback_get_minimum_fee(dap_chain_t *a_chain)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);

    return l_esbocs_pvt->minimum_fee;
}

static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks)
{
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(a_blocks);
    dap_chain_esbocs_session_t *l_session = l_esbocs->session;
    pthread_mutex_lock(&l_session->mutex);
    DL_DELETE(s_session_items, l_session);
    if (!s_session_items)
        dap_timerfd_delete(s_session_cs_timer);
    s_session_round_clear(l_session);
    dap_chain_esbocs_sync_item_t *l_item, *l_tmp;
    HASH_ITER(hh, l_session->sync_items, l_item, l_tmp) {
        HASH_DEL(l_session->sync_items, l_item);
        dap_list_free_full(l_item->messages, NULL);
        DAP_DELETE(l_item);
    }
    pthread_mutex_unlock(&l_session->mutex);
    DAP_DELETE(l_session);
    if (l_esbocs->_pvt)
        DAP_DELETE(l_esbocs->_pvt);
    DAP_DEL_Z(a_blocks->_inheritor);
}

static void *s_callback_list_copy(const void *a_validator, UNUSED_ARG void *a_data)
{
    return DAP_DUP((dap_chain_esbocs_validator_t *)a_validator);
}

static void *s_callback_list_form(const void *a_srv_validator, UNUSED_ARG void *a_data)
{
    dap_chain_esbocs_validator_t *l_validator = DAP_NEW(dap_chain_esbocs_validator_t);
    l_validator->node_addr = ((dap_chain_net_srv_stake_item_t *)a_srv_validator)->node_addr;
    l_validator->signing_addr = ((dap_chain_net_srv_stake_item_t *)a_srv_validator)->signing_addr;
    l_validator->weight = ((dap_chain_net_srv_stake_item_t *)a_srv_validator)->value;
    l_validator->is_synced = false;
    return l_validator;
}

static void s_callback_set_min_validators_count(dap_chain_t *a_chain, uint16_t a_new_value)
{
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_esbocs_t *l_esbocs = DAP_CHAIN_ESBOCS(l_blocks);
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(l_esbocs);
    l_esbocs_pvt->min_validators_count = a_new_value;
}

static dap_list_t *s_get_validators_list(dap_chain_esbocs_session_t *a_session, dap_chain_hash_fast_t *a_seed_hash)
{
    dap_chain_esbocs_pvt_t *l_esbocs_pvt = PVT(a_session->esbocs);
    dap_list_t *l_ret = NULL;

    if (!l_esbocs_pvt->poa_mode) {
        dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators();
        size_t l_validators_count = dap_list_length(l_validators);
        if (l_validators_count < l_esbocs_pvt->min_validators_count) {
            dap_list_free_full(l_validators, NULL);
            return NULL;
        }
        size_t n = (size_t)l_esbocs_pvt->min_validators_count * 3;
        size_t l_consensus_optimum = (n / 2) + (n % 2);
        size_t l_need_vld_cnt = MIN(l_validators_count, l_consensus_optimum);
        if (l_validators_count == l_need_vld_cnt) {
            l_ret = dap_list_copy_deep(l_validators, s_callback_list_form, NULL);
            dap_list_free_full(l_validators, NULL);
            return l_ret;
        }

        // TODO: make dap_chain_net_srv_stake_get_total_weight() call
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
        if (a_seed_hash)
            dap_pseudo_random_seed(*(uint256_t *)a_seed_hash);
        for (size_t l_current_vld_cnt = 0; l_current_vld_cnt < l_need_vld_cnt; l_current_vld_cnt++) {
            uint256_t l_chosen_weight = dap_pseudo_random_get(l_total_weight);
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
            DAP_DELETE(l_chosen->data);
            DAP_DELETE(l_chosen);
        }
        dap_list_free_full(l_validators, NULL);
    } else
        l_ret = dap_list_copy_deep(l_esbocs_pvt->poa_validators, s_callback_list_copy, NULL);

    return l_ret;
}

static void s_get_last_block_hash(dap_chain_t *a_chain, dap_chain_hash_fast_t *a_last_hash_ptr)
{
    dap_chain_atom_iter_t *l_iter = a_chain->callback_atom_iter_create(a_chain, c_dap_chain_cell_id_null, false);
    dap_chain_atom_ptr_t *l_ptr_list = a_chain->callback_atom_iter_get_lasts(l_iter, NULL, NULL);
    DAP_DEL_Z(l_ptr_list);
    *a_last_hash_ptr = l_iter->cur_hash ? *l_iter->cur_hash : (dap_hash_fast_t){0};
    a_chain->callback_atom_iter_delete(l_iter);
}

static int s_callback_addr_compare(const void *a_list_data, const void *a_user_data)
{
    return memcmp(&((dap_chain_esbocs_validator_t *)a_list_data)->signing_addr,
                  (dap_chain_addr_t *)a_user_data, sizeof(dap_chain_addr_t));
}

static dap_list_t *s_validator_check(dap_chain_addr_t *a_addr, dap_list_t *a_validators)
{
    return dap_list_find_custom(a_validators, a_addr, s_callback_addr_compare);
}

static void s_session_send_startsync(dap_chain_esbocs_session_t *a_session)
{
    dap_chain_hash_fast_t l_last_block_hash;
    s_get_last_block_hash(a_session->chain, &l_last_block_hash);
    a_session->ts_round_sync_start = dap_time_now();
    if (!dap_hash_fast_compare(&l_last_block_hash, &a_session->cur_round.last_block_hash))
        return;     // My last block hash is different, so skip this round
    if (!s_validator_check(&a_session->my_signing_addr, a_session->cur_round.validators_list))
        return;     // I'm not a selected validator, just skip sync message
    debug_if(PVT(a_session->esbocs)->debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U"."
                                                   " Sent START_SYNC pkt, attempt %"DAP_UINT64_FORMAT_U,
                    a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id, a_session->cur_round.sync_attempt);
    s_message_send(a_session, DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC, &l_last_block_hash,
                   &a_session->cur_round.sync_attempt, sizeof(uint64_t),
                   a_session->cur_round.validators_list);
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

static void s_session_round_clear(dap_chain_esbocs_session_t *a_session)
{
    dap_chain_esbocs_message_item_t *l_message_item, *l_message_tmp;
    HASH_ITER(hh, a_session->cur_round.message_items, l_message_item, l_message_tmp) {
        HASH_DEL(a_session->cur_round.message_items, l_message_item);
        DAP_DELETE(l_message_item->message);
        DAP_DELETE(l_message_item);
    }
    dap_chain_esbocs_store_t *l_store_item, *l_store_tmp;
    HASH_ITER(hh, a_session->cur_round.store_items, l_store_item, l_store_tmp) {
        HASH_DEL(a_session->cur_round.store_items, l_store_item);
        dap_list_free_full(l_store_item->candidate_signs, NULL);
        DAP_DELETE(l_store_item);
    }
    dap_list_free_full(a_session->cur_round.validators_list, NULL);

    a_session->cur_round = (dap_chain_esbocs_round_t){
            .id = a_session->cur_round.id,
            .attempt_num = 1,
            .last_block_hash = a_session->cur_round.last_block_hash,
            .sync_attempt = a_session->cur_round.sync_attempt
    };
}

static void s_session_round_new(dap_chain_esbocs_session_t *a_session)
{
    s_session_round_clear(a_session);
    a_session->cur_round.id++;
    a_session->cur_round.sync_attempt++;

    dap_timerfd_delete(a_session->sync_timer);
    a_session->sync_timer = NULL;
    a_session->state = DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_START;
    a_session->ts_round_sync_start = 0;
    a_session->ts_attempt_start = 0;

    dap_hash_fast_t *l_seed_hash = NULL;
    dap_hash_fast_t l_last_block_hash;
    s_get_last_block_hash(a_session->chain, &l_last_block_hash);
    if (dap_hash_fast_is_blank(&a_session->cur_round.last_block_hash) ||
            !dap_hash_fast_compare(&l_last_block_hash, &a_session->cur_round.last_block_hash)) {
        l_seed_hash = &l_last_block_hash;
        a_session->cur_round.last_block_hash = l_last_block_hash;
        a_session->cur_round.sync_attempt = 1;
    }
    a_session->cur_round.validators_list = s_get_validators_list(a_session, l_seed_hash);

    bool l_round_already_started = a_session->round_fast_forward;
    if (s_validator_check(&a_session->my_signing_addr, a_session->cur_round.validators_list)) {
        //I am a current round validator
        dap_chain_esbocs_sync_item_t *l_item, *l_tmp;
        HASH_FIND(hh, a_session->sync_items, &a_session->cur_round.last_block_hash, sizeof(dap_hash_fast_t), l_item);
        if (l_item) {
            debug_if(PVT(a_session->esbocs)->debug,
                     L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" already started. Process sync messages",
                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id);
            l_round_already_started = true;
            for (dap_list_t *it = l_item->messages; it; it = it->next) {
                dap_hash_fast_t l_msg_hash;
                dap_chain_esbocs_message_t *l_msg = it->data;
                size_t l_msg_size = sizeof(*l_msg) + l_msg->hdr.sign_size + l_msg->hdr.message_size;
                dap_hash_fast(l_msg, l_msg_size, &l_msg_hash);
                s_session_packet_in(a_session, NULL, NULL, &l_msg_hash, (uint8_t *)l_msg, l_msg_size);
            }
        }
        HASH_ITER(hh, a_session->sync_items, l_item, l_tmp) {
            HASH_DEL(a_session->sync_items, l_item);
            dap_list_free_full(l_item->messages, NULL);
            DAP_DELETE(l_item);
        }

        debug_if(PVT(a_session->esbocs)->debug, L_MSG,
                 "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" start. Syncing validators in %u seconds",
                    a_session->chain->net_name, a_session->chain->name,
                        a_session->cur_round.id, l_round_already_started ? 0 : PVT(a_session->esbocs)->new_round_delay);
    }
    if (PVT(a_session->esbocs)->new_round_delay && !l_round_already_started)
        a_session->sync_timer = dap_timerfd_start(PVT(a_session->esbocs)->new_round_delay * 1000,
                                                  s_session_send_startsync_on_timer, a_session);
    else
        s_session_send_startsync(a_session);
    a_session->round_fast_forward = false;
}

static void s_session_attempt_new(dap_chain_esbocs_session_t *a_session)
{
    if (a_session->cur_round.attempt_num++ > PVT(a_session->esbocs)->round_attempts_max ) {
        debug_if(PVT(a_session->esbocs)->debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U"."
                                                        " Round finished by reason: attempts is out",
                                                            a_session->chain->net_name, a_session->chain->name,
                                                                a_session->cur_round.id);
        s_session_round_new(a_session);
        return;
    }
    for (dap_list_t *it = a_session->cur_round.validators_list; it; it = it->next) {
        dap_chain_esbocs_validator_t *l_validator = it->data;
        if (l_validator->is_synced && !l_validator->is_chosen) {
            // We have synced validator with no submitted candidate
            debug_if(PVT(a_session->esbocs)->debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U". Attempt:%hu is started",
                                                                a_session->chain->net_name, a_session->chain->name,
                                                                    a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC, dap_time_now());
            return;
        }
    }
    debug_if(PVT(a_session->esbocs)->debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U"."
                                                    " Round finished by reason: all synced validators already tryed its attempt",
                                                        a_session->chain->net_name, a_session->chain->name,
                                                            a_session->cur_round.id);
    s_session_round_new(a_session);
}

static uint64_t s_session_calc_current_round_id(dap_chain_esbocs_session_t *a_session)
{
    struct {
        uint64_t id;
        uint16_t counter;
    } l_id_candidates[a_session->cur_round.validators_synced_count];
    uint16_t l_fill_idx = 0;
    dap_chain_esbocs_message_item_t *l_item, *l_tmp;
    HASH_ITER(hh, a_session->cur_round.message_items, l_item, l_tmp) {
        if (l_item->message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC) {
            uint64_t l_id_candidate = l_item->message->hdr.round_id;
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
                l_fill_idx++;
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
            l_ret = MAX(l_ret, l_id_candidates[i].id);
    }
    return l_ret;
}

static int s_signs_sort_callback(const void *a_sign1, const void *a_sign2, UNUSED_ARG void *a_user_data)
{
    size_t l_size1 = dap_sign_get_size((dap_sign_t *)a_sign1);
    size_t l_size2 = dap_sign_get_size((dap_sign_t *)a_sign2);
    size_t l_size_min = MIN(l_size1, l_size2);
    int l_ret = memcmp(a_sign1, a_sign2, l_size_min);
    if (!l_ret) {
        if (l_size1 < l_size2)
            l_ret = -1;
        else if (l_size1 > l_size2)
            l_ret = 1;
    }
    return l_ret;
}

static void s_session_state_change(dap_chain_esbocs_session_t *a_session, enum s_esbocs_session_state a_new_state, dap_time_t a_time)
{
    a_session->state = a_new_state;
    a_session->ts_attempt_start = a_time;
    switch (a_session->state) {
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC: {
        uint256_t l_total_weight = uint256_0;
        dap_chain_esbocs_validator_t *l_validator;
        for (dap_list_t *it = a_session->cur_round.validators_list; it; it = it->next) {
            l_validator = it->data;
            if (l_validator->is_synced && !l_validator->is_chosen)
                SUM_256_256(l_total_weight, l_validator->weight, &l_total_weight);
        }
        uint256_t l_chosen_weight = dap_pseudo_random_get(l_total_weight);
        uint256_t l_cur_weight = uint256_0;
        for (dap_list_t *it = a_session->cur_round.validators_list; it; it = it->next) {
            l_validator = it->data;
            if (l_validator->is_synced && !l_validator->is_chosen) {
                SUM_256_256(l_total_weight, l_validator->weight, &l_cur_weight);
                if (compare256(l_chosen_weight, l_cur_weight) == -1) {
                    l_validator->is_chosen = true;
                    break;
                }
            }
        }
        a_session->cur_round.attempt_submit_validator = l_validator->signing_addr;
        if (dap_chain_addr_compare(&a_session->cur_round.attempt_submit_validator, &a_session->my_signing_addr))
            s_session_candidate_submit(a_session);
        else {
            dap_chain_esbocs_message_item_t *l_item, *l_tmp;
            HASH_ITER(hh, a_session->cur_round.message_items, l_item, l_tmp) {
                if (l_item->message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_SUBMIT &&
                        dap_chain_addr_compare(&l_item->signing_addr, &a_session->cur_round.attempt_submit_validator)) {
                    // Verify and vote already submitted candidate
                    s_session_candidate_verify(a_session, (dap_chain_block_t *)l_item->message->msg_n_sign,
                                               l_item->message->hdr.message_size, &l_item->message->hdr.candidate_hash);
                }
            }
        }
    } break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH: {
        dap_chain_esbocs_store_t *l_store;
        HASH_FIND(hh, a_session->cur_round.store_items, &a_session->cur_round.attempt_candidate_hash, sizeof(dap_hash_fast_t), l_store);
        if (!l_store) {
            log_it(L_ERROR, "ESBOCS: No finish candidate found!");
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
            if (dap_chain_addr_compare(&l_signing_addr_cur, &a_session->cur_round.attempt_submit_validator)) {
                // If it's the primary attempt validator sign, place it in the beginnig
                if (l_store->candidate_size > l_candidate_size_exclude_signs)
                    memmove((byte_t *)l_store->candidate + l_candidate_size_exclude_signs + l_candidate_sign_size,
                            (byte_t *)l_store->candidate + l_candidate_size_exclude_signs,
                            l_candidate_sign_size);
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
            if (l_chain_message->message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_PRE_COMMIT &&
                    dap_hash_fast_compare(&l_chain_message->message->hdr.candidate_hash,
                                          &a_session->cur_round.attempt_candidate_hash))
            {
                dap_chain_esbocs_message_t *l_msg = l_chain_message->message;
                size_t l_msg_size = sizeof(*l_msg) + l_msg->hdr.sign_size + l_msg->hdr.message_size;
                s_session_packet_in(a_session, NULL, NULL, &l_chain_message->message_hash, (uint8_t*)l_msg, l_msg_size);
            }
        }
        // Send own PreCommit
        s_message_send(a_session, DAP_STREAM_CH_VOTING_MSG_TYPE_PRE_COMMIT, &l_store->candidate_hash,
                            &l_store->precommit_candidate_hash, sizeof(dap_chain_hash_fast_t),
                                a_session->cur_round.validators_list);
    } break;
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
        dap_time_t l_round_timeout = PVT(a_session->esbocs)->round_start_sync_timeout;
        bool l_round_skip = !s_validator_check(&a_session->my_signing_addr, a_session->cur_round.validators_list);
        if (l_round_skip)
            l_round_timeout += PVT(a_session->esbocs)->round_attempt_timeout * PVT(a_session->esbocs)->round_attempts_max;
        if (a_session->ts_round_sync_start && l_time - a_session->ts_round_sync_start >= l_round_timeout) {
            if (a_session->cur_round.validators_synced_count >= PVT(a_session->esbocs)->min_validators_count) {
                a_session->cur_round.id = s_session_calc_current_round_id(a_session);
                debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                            " Minimum count of validators are synchronized, wait to submit candidate",
                                                a_session->chain->net_name, a_session->chain->name,
                                                    a_session->cur_round.id, a_session->cur_round.attempt_num);
                s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC, l_time);
            } else { // timeout start sync
                debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                            " Round finished by reason: %s",
                                                a_session->chain->net_name, a_session->chain->name,
                                                    a_session->cur_round.id, a_session->cur_round.attempt_num,
                                                        l_round_skip ? "skipped" : "can't synchronize minimum number of validators");
                s_session_round_new(a_session);
            }
        }
    } break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC:
        if (l_time - a_session->ts_attempt_start >= PVT(a_session->esbocs)->round_attempt_timeout) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Attempt finished by reason: haven't cantidate submitted",
                                            a_session->chain->net_name, a_session->chain->name,
                                                a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_attempt_new(a_session);
        }
        break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_SIGNS:
        if (l_time - a_session->ts_attempt_start >= PVT(a_session->esbocs)->round_attempt_timeout) {
            dap_chain_esbocs_store_t *l_store;
            HASH_FIND(hh, a_session->cur_round.store_items, &a_session->cur_round.attempt_candidate_hash, sizeof(dap_hash_fast_t), l_store);
            if (!l_store) {
                log_it(L_ERROR, "ESBOCS: No round candidate found!");
                s_session_attempt_new(a_session);
                break;
            }
            if (dap_list_length(l_store->candidate_signs) >= PVT(a_session->esbocs)->min_validators_count) {
                if(l_cs_debug) {
                    char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(&a_session->cur_round.attempt_candidate_hash);
                    log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu"
                                            " Candidate:%s collected sings of minimum number of validators, so to sent PRE_COMMIT",
                                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                                    a_session->cur_round.attempt_num, l_candidate_hash_str);
                    DAP_DELETE(l_candidate_hash_str);
                }
                s_session_state_change(a_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH, l_time);
                break;
            }
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Attempt finished by reason: cant't collect minimum number of validator's signs",
                                            a_session->chain->net_name, a_session->chain->name,
                                                a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_attempt_new(a_session);
        }
        break;
    case DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH:
        if (l_time - a_session->ts_attempt_start >= PVT(a_session->esbocs)->round_attempt_timeout) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Attempt finished by reason: cant't collect minimum number of validator's precommits with same final hash",
                                            a_session->chain->net_name, a_session->chain->name,
                                                a_session->cur_round.id, a_session->cur_round.attempt_num);
            s_session_attempt_new(a_session);
        }
        break;
    default:
        break;
    }

    pthread_mutex_unlock(&a_session->mutex);
}

static bool s_session_timer(void *a_arg)
{
    UNUSED(a_arg);
    dap_chain_esbocs_session_t *l_session = NULL;
    DL_FOREACH(s_session_items, l_session) {
        s_session_proc_state(l_session);
    }
    return true;
}

static void s_message_chain_add(dap_chain_esbocs_session_t *a_session,
                                dap_chain_esbocs_message_t *a_message,
                                size_t a_message_size,
                                dap_chain_hash_fast_t *a_message_hash,
                                dap_chain_addr_t *a_signing_addr)
{
    dap_chain_esbocs_round_t *l_round = &a_session->cur_round;
    dap_chain_esbocs_message_item_t *l_message_item = DAP_NEW_Z(dap_chain_esbocs_message_item_t);
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
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu. Submit my candidate:%s",
                    a_session->chain->net_name, a_session->chain->name,
                        a_session->cur_round.id, a_session->cur_round.attempt_num, l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
        }
    } else { // there is no my candidate, send null hash
        if (PVT(a_session->esbocs)->debug)
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                          " I don't have a candidate. I submit a null candidate.",
                                a_session->chain->net_name, a_session->chain->name,
                                    a_session->cur_round.id, a_session->cur_round.attempt_num);
    }
    s_message_send(a_session, DAP_STREAM_CH_VOTING_MSG_TYPE_SUBMIT, &l_candidate_hash,
                    l_candidate, l_candidate_size, a_session->cur_round.validators_list);
    //Save candidate_hash
    memcpy(&(PVT(a_session->esbocs)->candidate_hash), &l_candidate_hash, sizeof(dap_hash_fast_t));
}

static void s_session_candidate_verify(dap_chain_esbocs_session_t *a_session, dap_chain_block_t *a_candidate,
                                       size_t a_candidate_size, dap_hash_fast_t *a_candidate_hash)
{
    a_session->processing_candidate = a_candidate;
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_session->chain);
    if (l_blocks->chain->callback_atom_verify(l_blocks->chain, a_candidate, a_candidate_size) == ATOM_ACCEPT) {
        // validation - OK, gen event Approve
        s_message_send(a_session, DAP_STREAM_CH_VOTING_MSG_TYPE_APPROVE, a_candidate_hash,
                       NULL, 0, a_session->cur_round.validators_list);
        if (PVT(a_session->esbocs)->debug) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(a_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Sent APPROVE candidate:%s",
                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                        a_session->cur_round.attempt_num, l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
        }
    } else {
        // validation - fail, gen event Reject
        s_message_send(a_session, DAP_STREAM_CH_VOTING_MSG_TYPE_REJECT, a_candidate_hash,
                       NULL, 0, a_session->cur_round.validators_list);
        if (PVT(a_session->esbocs)->debug) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(a_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Sent REJECT candidate:%s",
                                a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                                        a_session->cur_round.attempt_num, l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
        }
    }
    a_session->processing_candidate = NULL;
}

static bool s_session_candidate_to_chain(dap_chain_esbocs_session_t *a_session, dap_chain_hash_fast_t *a_candidate_hash,
                                         dap_chain_block_t *a_candidate, size_t a_candidate_size)
{
    bool res = false;
    dap_chain_block_t *l_candidate = DAP_DUP_SIZE(a_candidate, a_candidate_size);
    dap_chain_atom_verify_res_t l_res = a_session->chain->callback_atom_add(a_session->chain, l_candidate, a_candidate_size);
    char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(a_candidate_hash);
    switch (l_res) {
    case ATOM_ACCEPT:
        // block save to chain
        if (dap_chain_atom_save(a_session->chain, (uint8_t *)l_candidate, a_candidate_size, a_session->chain->cells->id) < 0)
            log_it(L_ERROR, "ESBOCS: Can't save atom %s to the file", l_candidate_hash_str);
        else
        {
            log_it(L_INFO, "ESBOCS: block %s added in chain successfully", l_candidate_hash_str);
            res = true;
        }
        break;
    case ATOM_MOVE_TO_THRESHOLD:
        log_it(L_INFO, "ESBOCS: Thresholded atom with hash %s", l_candidate_hash_str);
        break;
    case ATOM_PASS:
        log_it(L_WARNING, "ESBOCS: Atom with hash %s not accepted (code ATOM_PASS, already present)", l_candidate_hash_str);
        DAP_DELETE(l_candidate);
        break;
    case ATOM_REJECT:
        log_it(L_WARNING,"ESBOCS: Atom with hash %s rejected", l_candidate_hash_str);
        DAP_DELETE(l_candidate);
        break;
    default:
         log_it(L_CRITICAL, "ESBOCS: Wtf is this ret code ? Atom hash %s code %d", l_candidate_hash_str, l_res);
         DAP_DELETE(l_candidate);
    }
    DAP_DELETE(l_candidate_hash_str);
    return res;
}

static void s_session_round_finish(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_store_t *l_store)
{
    bool l_cs_debug = PVT(a_session->esbocs)->debug;
    dap_chain_t *l_chain = a_session->chain;
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
    dap_chain_block_cache_t *l_block_cache = NULL;
    dap_hash_fast_t l_precommit_candidate_hash = {0};
    uint16_t l_cs_level = PVT(a_session->esbocs)->min_validators_count;

    if (!dap_hash_fast_compare(&a_session->cur_round.attempt_candidate_hash, &l_store->candidate_hash)) {
        char *l_current_candidate_hash_str = dap_chain_hash_fast_to_str_new(&a_session->cur_round.attempt_candidate_hash);
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "ESBOCS: Trying to finish candidate of not the current attempt (%s but not %s)",
                                        l_current_candidate_hash_str, l_finish_candidate_hash_str);
        DAP_DELETE(l_current_candidate_hash_str);
        DAP_DELETE(l_finish_candidate_hash_str);
        return;
    }

    if (l_store->reject_count >= l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "ESBOCS: Trying to finish rejected candidate %s", l_finish_candidate_hash_str);
        DAP_DELETE(l_finish_candidate_hash_str);
        return;
    }

    if (l_store->approve_count < l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "ESBOCS: Trying to finish not properly approved candidate %s", l_finish_candidate_hash_str);
        DAP_DELETE(l_finish_candidate_hash_str);
        return;
    }

    if (dap_list_length(l_store->candidate_signs) < l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "ESBOCS: Trying to finish not properly signed candidate %s", l_finish_candidate_hash_str);
        DAP_DELETE(l_finish_candidate_hash_str);
        return;
    }

    if (l_store->precommit_count < l_cs_level) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        debug_if(l_cs_debug, L_WARNING, "ESBOCS: Trying to finish not properly precommited candidate %s", l_finish_candidate_hash_str);
        DAP_DELETE(l_finish_candidate_hash_str);
        return;
    }

    if (l_cs_debug) {
        char *l_finish_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_store->candidate_hash);
        char *l_finish_block_hash_str = dap_chain_hash_fast_to_str_new(&l_store->precommit_candidate_hash);
        log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Candidate:%s passed the consensus!\n"
                      "Move block %s to chains",
                        a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id,
                            a_session->cur_round.attempt_num, l_finish_candidate_hash_str, l_finish_block_hash_str);
        DAP_DELETE(l_finish_candidate_hash_str);
        DAP_DELETE(l_finish_block_hash_str);
    }

    memcpy(&l_precommit_candidate_hash, &l_store->precommit_candidate_hash, sizeof(dap_hash_fast_t));
    bool l_compare = dap_hash_fast_compare(&l_store->candidate_hash,&(PVT(a_session->esbocs)->candidate_hash));
    if(s_session_candidate_to_chain(a_session, &l_store->precommit_candidate_hash, l_store->candidate, l_store->candidate_size) &&
            l_compare && PVT(a_session->esbocs)->fee_addr) {
        dap_list_t *l_block_list = NULL;
        l_block_cache = dap_chain_block_cs_cache_get_by_hash(l_blocks, &l_precommit_candidate_hash);
        l_block_list = dap_list_append(l_block_list, l_block_cache);
        dap_chain_mempool_tx_coll_fee_create(a_session->blocks_sign_key, (PVT(a_session->esbocs)->fee_addr),
                                             l_block_list, PVT(a_session->esbocs)->minimum_fee, "hex");
        dap_list_free(l_block_list);
    }
}

void s_session_sync_queue_add(dap_chain_esbocs_session_t *a_session, dap_chain_esbocs_message_t *a_message, size_t a_message_size)
{
    dap_chain_esbocs_sync_item_t *l_sync_item;
    HASH_FIND(hh, a_session->sync_items, &a_message->hdr.candidate_hash, sizeof(dap_hash_fast_t), l_sync_item);
    if (!l_sync_item) {
        l_sync_item = DAP_NEW_Z(dap_chain_esbocs_sync_item_t);
        l_sync_item->last_block_hash = a_message->hdr.candidate_hash;
        HASH_ADD(hh, a_session->sync_items, last_block_hash, sizeof(dap_hash_fast_t), l_sync_item);
    }
    l_sync_item->messages = dap_list_append(l_sync_item->messages, DAP_DUP_SIZE(a_message, a_message_size));
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
    size_t l_message_data_size = l_message->hdr.message_size;
    byte_t *l_message_data = l_message->msg_n_sign;
    dap_sign_t *l_sign = (dap_sign_t *)(l_message_data + l_message_data_size);
    size_t l_sign_size = l_message->hdr.sign_size;

    if (a_sender_node_addr) { //Process network message
        pthread_mutex_lock(&l_session->mutex);
        debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                    " Receive pkt type:%x from addr:"NODE_ADDR_FP_STR", my_addr:"NODE_ADDR_FP_STR"",
                                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                            l_session->cur_round.attempt_num, l_message->hdr.type,
                                                NODE_ADDR_FP_ARGS(a_sender_node_addr), NODE_ADDR_FP_ARGS_S(l_session->my_addr));
        if (a_receiver_node_addr->uint64 != l_session->my_addr.uint64) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: Wrong packet destination address");
            goto session_unlock;
        }

        if (sizeof(*l_message) + l_message->hdr.sign_size + l_message->hdr.message_size != a_data_size) {
            log_it(L_WARNING, "ESBOCS: incorrect message size in header is %zu when data size is only %zu and header size is %zu",
                   l_message->hdr.sign_size, a_data_size, sizeof(*l_message));
            goto session_unlock;
        }

        if (l_message->hdr.chain_id.uint64 != l_session->chain->id.uint64) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: Invalid chain ID %"DAP_UINT64_FORMAT_U, l_message->hdr.chain_id.uint64);
            goto session_unlock;
        }

        dap_chain_hash_fast_t l_data_hash = {};
        dap_hash_fast(l_message, a_data_size, &l_data_hash);
        if (!dap_hash_fast_compare(a_data_hash, &l_data_hash)) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Message rejected: message hash does not match",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_session->cur_round.attempt_num);
            goto session_unlock;
        }

        l_message->hdr.sign_size = 0;   // restore header on signing time
        if (dap_sign_verify_all(l_sign, l_sign_size, l_message, l_message_data_size + sizeof(l_message->hdr))) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Message rejected from addr:"NODE_ADDR_FP_STR" not passed verification",
                                            l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                l_session->cur_round.attempt_num, NODE_ADDR_FP_ARGS(a_sender_node_addr));
            goto session_unlock;
        }
        l_message->hdr.sign_size = l_sign_size; // restore original header

        // consensus round start sync
        if (l_message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC) {
            if (!dap_hash_fast_compare(&l_message->hdr.candidate_hash, &l_session->cur_round.last_block_hash)) {
                s_session_sync_queue_add(l_session, l_message, a_data_size);
                goto session_unlock;
            }
        } else if (l_message->hdr.round_id != l_session->cur_round.id ||
                   l_message->hdr.attempt_num < l_session->cur_round.attempt_num) {
            // round check
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Message rejected: round or attempt in message does not match",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_session->cur_round.attempt_num);
            goto session_unlock;
        }
    }
    // Process local & network messages
    dap_chain_addr_t l_signing_addr;
    char *l_validator_addr_str = NULL;
    dap_chain_addr_fill_from_sign(&l_signing_addr, l_sign, l_session->chain->net_id);
    if (l_cs_debug)
        l_validator_addr_str = dap_chain_addr_to_str(&l_signing_addr);
    if (!s_validator_check(&l_signing_addr, l_session->cur_round.validators_list)) {
        debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                    " Message rejected: validator addr:%s not in the list.",
                                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                            l_session->cur_round.attempt_num, l_validator_addr_str);
        goto session_unlock;
    }

    dap_chain_esbocs_round_t *l_round = &l_session->cur_round;

    // check hash message dup
    dap_chain_esbocs_message_item_t *l_message_item_temp = NULL;
    HASH_FIND(hh, l_round->message_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_message_item_temp);
    if (l_message_item_temp) {
        debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                    " Message rejected: message hash is exists in chain (duplicate)",
                                        l_session->chain->net_name, l_session->chain->name,
                                            l_session->cur_round.id, l_session->cur_round.attempt_num);
        goto session_unlock;
    }

    // check messages chain
    dap_chain_esbocs_message_item_t *l_chain_message, *l_chain_message_tmp;
    HASH_ITER(hh, l_round->message_items, l_chain_message, l_chain_message_tmp) {
        bool l_same_type = l_chain_message->message->hdr.type == l_message->hdr.type ||
                (l_chain_message->message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_APPROVE &&
                 l_message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_REJECT) ||
                (l_chain_message->message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_REJECT &&
                 l_message->hdr.type == DAP_STREAM_CH_VOTING_MSG_TYPE_APPROVE);
        if (l_same_type && dap_chain_addr_compare(&l_chain_message->signing_addr, &l_signing_addr) &&
                dap_hash_fast_compare(&l_chain_message->message->hdr.candidate_hash, &l_message->hdr.candidate_hash)) {
            if (l_message->hdr.type != DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC || // Not sync or same sync attempt
                    *(uint64_t *)l_message_data == *(uint64_t *)l_chain_message->message->msg_n_sign) {
                debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                            " Message rejected: duplicate message %s",
                                                l_session->chain->net_name, l_session->chain->name,
                                                    l_session->cur_round.id, l_session->cur_round.attempt_num,
                                                        s_voting_msg_type_to_str(l_message->hdr.type));
                goto session_unlock;
            }
        }
    }

    s_message_chain_add(l_session, l_message, a_data_size, a_data_hash, &l_signing_addr);

    dap_chain_hash_fast_t *l_candidate_hash = &l_message->hdr.candidate_hash;
    switch (l_message->hdr.type) {
    case DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC: {
        uint64_t l_sync_attempt = *(uint64_t *)l_message_data;
        debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                    " Receive START_SYNC: from validator:%s, sync attempt %"DAP_UINT64_FORMAT_U,
                                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                            l_validator_addr_str, l_sync_attempt);
        if (l_sync_attempt != l_session->cur_round.sync_attempt) {
            if (l_sync_attempt < l_session->cur_round.sync_attempt) {
                 debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                             " SYNC message is rejected because current sync attempt %"DAP_UINT64_FORMAT_U
                                             " is greater than meassage sync attempt %"DAP_UINT64_FORMAT_U,
                                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                    l_session->cur_round.sync_attempt, l_sync_attempt);
                 break;
            } else {
                uint64_t l_attempts_miss = l_sync_attempt - l_session->cur_round.sync_attempt;
                if (l_attempts_miss > UINT16_MAX) {
                    debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                                " SYNC message is rejected - too much sync attempt difference %"DAP_UINT64_FORMAT_U,
                                                   l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                       l_attempts_miss);
                    break;
                }
                debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U
                                            " SYNC message sync attempt %"DAP_UINT64_FORMAT_U" is greater than"
                                            " current round sync attempt %"DAP_UINT64_FORMAT_U" so fast-forward this round",
                                               l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                   l_sync_attempt, l_session->cur_round.sync_attempt);
                for (uint64_t i = 0; i < l_attempts_miss - 1; i++) {
                    // Fast-forward current sync attempt
                    s_get_validators_list(l_session, NULL);
                    l_session->cur_round.sync_attempt++;
                }
                // Process this message in new round
                s_session_sync_queue_add(l_session, l_message, a_data_size);
                l_session->round_fast_forward = true;
                s_session_round_new(l_session);
                break;
            }
        }

        for (dap_list_t *it = l_session->cur_round.validators_list; it; it = it->next) {
            dap_chain_esbocs_validator_t *l_validator = it->data;
            if (dap_chain_addr_compare(&l_validator->signing_addr, &l_signing_addr))
                l_validator->is_synced = true;
        }
        if (++l_session->cur_round.validators_synced_count == dap_list_length(l_session->cur_round.validators_list)) {
            l_session->cur_round.id = s_session_calc_current_round_id(l_session);
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " All validators are synchronized, wait to submit candidate",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_session->cur_round.attempt_num);
            s_session_state_change(l_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_PROC, dap_time_now());
        }
    } break;
    case DAP_STREAM_CH_VOTING_MSG_TYPE_SUBMIT: {
        uint8_t *l_candidate = l_message->msg_n_sign;
        size_t l_candidate_size = l_message->hdr.message_size;
        if (!l_candidate_size || dap_hash_fast_is_blank(&l_message->hdr.candidate_hash)) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Receive SUBMIT candidate NULL",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_session->cur_round.attempt_num);
            if (dap_chain_addr_compare(&l_session->cur_round.attempt_submit_validator, &l_signing_addr))
                s_session_attempt_new(l_session);
            break;
        }
        // check candidate hash
        dap_chain_hash_fast_t l_check_hash;
        dap_hash_fast(l_candidate, l_candidate_size, &l_check_hash);
        if (!dap_hash_fast_compare(&l_check_hash, l_candidate_hash)) {
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Receive SUBMIT candidate hash broken",
                                            l_session->chain->net_name, l_session->chain->name,
                                                l_session->cur_round.id, l_session->cur_round.attempt_num);
            break;
        }

        if (l_cs_debug) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                            " Receive SUBMIT candidate %s, size %zu",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_session->cur_round.attempt_num, l_candidate_hash_str, l_candidate_size);
            DAP_DELETE(l_candidate_hash_str);
        }

        dap_chain_esbocs_store_t *l_store;
        HASH_FIND(hh, l_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
        if (l_store) {
            char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_WARNING, "ESBOCS: Duplicate candidate:%s", l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
            break;
        }

        // store for new candidate
        l_store = DAP_NEW_Z(dap_chain_esbocs_store_t);
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

    case DAP_STREAM_CH_VOTING_MSG_TYPE_REJECT: {
        dap_chain_esbocs_store_t *l_store;
        char *l_candidate_hash_str = NULL;
        HASH_FIND(hh, l_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
        if (!l_store) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_WARNING, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                " Receive REJECT message for unknown candidate:%s",
                                   l_session->chain->net_name, l_session->chain->name,
                                       l_session->cur_round.id, l_session->cur_round.attempt_num,
                                            l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
            break;
        }

        if (l_cs_debug) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                            " Receive REJECT: candidate:%s",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_session->cur_round.attempt_num, l_candidate_hash_str);
        }
        if (++l_store->reject_count >= l_cs_level && !l_store->decide_reject &&
                dap_hash_fast_compare(&l_session->cur_round.attempt_candidate_hash, l_candidate_hash)) {
            l_store->decide_reject = true;
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Candidate:%s rejected by minimum number of validators, attempt failed",
                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                            l_session->cur_round.attempt_num, l_candidate_hash_str);
            s_session_attempt_new(l_session);
        }
        DAP_DEL_Z(l_candidate_hash_str);
    } break;

    case DAP_STREAM_CH_VOTING_MSG_TYPE_APPROVE: {
        dap_chain_esbocs_store_t *l_store;
        char *l_candidate_hash_str = NULL;
        HASH_FIND(hh, l_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
        if (!l_store) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_WARNING, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                " Receive APPROVE message for unknown candidate:%s",
                                   l_session->chain->net_name, l_session->chain->name,
                                       l_session->cur_round.id, l_session->cur_round.attempt_num,
                                            l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
            break;
        }

        if (l_cs_debug) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                            " Receive APPROVE: candidate:%s",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_session->cur_round.attempt_num, l_candidate_hash_str);
        }
        if (++l_store->approve_count >= l_cs_level && !l_store->decide_approve &&
                dap_hash_fast_compare(&l_session->cur_round.attempt_candidate_hash, l_candidate_hash)) {
            l_store->decide_approve = true;
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Candidate:%s approved by minimum number of validators, let's sign it",
                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                            l_session->cur_round.attempt_num, l_candidate_hash_str);
            size_t l_offset = dap_chain_block_get_sign_offset(l_store->candidate, l_store->candidate_size);
            dap_sign_t *l_candidate_sign = dap_sign_create(PVT(l_session->esbocs)->blocks_sign_key,
                                            l_store->candidate, l_offset + sizeof(l_store->candidate->hdr), 0);
            size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
            s_message_send(l_session, DAP_STREAM_CH_VOTING_MSG_TYPE_COMMIT_SIGN, l_candidate_hash,
                           l_candidate_sign, l_candidate_sign_size, l_session->cur_round.validators_list);
            DAP_DELETE(l_candidate_sign);
        }
        DAP_DEL_Z(l_candidate_hash_str);
    } break;

    case DAP_STREAM_CH_VOTING_MSG_TYPE_COMMIT_SIGN: {
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
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_WARNING, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                " Receive COMMIT_SIGN message for unknown candidate:%s",
                                    l_session->chain->net_name, l_session->chain->name,
                                        l_session->cur_round.id, l_session->cur_round.attempt_num,
                                            l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
            break;
        }

        if (l_cs_debug) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                            " Receive COMMIT_SIGN: candidate:%s",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_session->cur_round.attempt_num, l_candidate_hash_str);
        }

        size_t l_offset = dap_chain_block_get_sign_offset(l_store->candidate, l_store->candidate_size);
        bool l_sign_verified = dap_sign_verify(l_candidate_sign, l_store->candidate,
                                                l_offset + sizeof(l_store->candidate->hdr)) == 1;
        // check candidate's sign
        if (l_sign_verified) {
            l_store->candidate_signs = dap_list_append(l_store->candidate_signs,
                                                       DAP_DUP_SIZE(l_candidate_sign, l_candidate_sign_size));
            if (dap_list_length(l_store->candidate_signs) == l_round->validators_synced_count) {
                if (PVT(l_session->esbocs)->debug)
                    log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                  " Candidate:%s collected signs of all synced validators",
                                        l_session->chain->net_name, l_session->chain->name, l_round->id,
                                            l_session->cur_round.attempt_num, l_candidate_hash_str);
                s_session_state_change(l_session, DAP_CHAIN_ESBOCS_SESSION_STATE_WAIT_FINISH, dap_time_now());
            }
        } else {
            if (!l_candidate_hash_str)
                l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_WARNING, "Candidate:%s sign is incorrect: code %d", l_candidate_hash_str, l_sign_verified);
        }
        DAP_DEL_Z(l_candidate_hash_str);
    } break;

    case DAP_STREAM_CH_VOTING_MSG_TYPE_PRE_COMMIT: {
        dap_chain_esbocs_store_t *l_store;
        char *l_candidate_hash_str = NULL;
        HASH_FIND(hh, l_session->cur_round.store_items, l_candidate_hash, sizeof(dap_chain_hash_fast_t), l_store);
        if (!l_store) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_WARNING, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                              " Receive PRE_COMMIT message for unknown candidate:%s",
                                l_session->chain->net_name, l_session->chain->name,
                                    l_session->cur_round.id, l_session->cur_round.attempt_num,
                                        l_candidate_hash_str);
            DAP_DELETE(l_candidate_hash_str);
            break;
        }

        if (dap_hash_fast_is_blank(&l_store->precommit_candidate_hash))
            // We have not yet precommit candidate. Message will be processed later
            break;

        dap_hash_fast_t *l_precommit_hash = (dap_hash_fast_t *)l_message_data;
        if (!dap_hash_fast_compare(l_precommit_hash, &l_store->precommit_candidate_hash)) {
            if (l_cs_debug) {
                l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
                char *l_my_precommit_hash_str = dap_chain_hash_fast_to_str_new(&l_store->precommit_candidate_hash);
                char *l_remote_precommit_hash_str = dap_chain_hash_fast_to_str_new(l_precommit_hash);
                log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                              " Candidate:%s has different final hash of local and remote validators\n"
                              "(%s and %s)",
                                    l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                        l_session->cur_round.attempt_num, l_candidate_hash_str,
                                            l_my_precommit_hash_str, l_remote_precommit_hash_str);
                DAP_DELETE(l_candidate_hash_str);
                DAP_DELETE(l_my_precommit_hash_str);
                DAP_DELETE(l_remote_precommit_hash_str);
            }
            break;
        }

        if (l_cs_debug) {
            l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
            log_it(L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                            " Receive PRE_COMMIT: candidate:%s",
                                l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                    l_session->cur_round.attempt_num, l_candidate_hash_str);
        }
        if (++l_store->precommit_count >= l_cs_level && !l_store->decide_commit &&
                dap_hash_fast_compare(&l_session->cur_round.attempt_candidate_hash, l_candidate_hash)) {
            l_store->decide_commit = true;
            debug_if(l_cs_debug, L_MSG, "ESBOCS: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu."
                                        " Candidate:%s precommted by minimum number of validators, try to finish this round",
                                            l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id,
                                                l_session->cur_round.attempt_num, l_candidate_hash_str);
            s_session_round_finish(l_session, l_store);
            // ATTENTION: New round will be started by incoming atom notifier event
        }
        DAP_DEL_Z(l_candidate_hash_str);
    } break;
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
    dap_chain_esbocs_message_t *l_message =
                        DAP_NEW_Z_SIZE(dap_chain_esbocs_message_t, l_message_size);
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
    memcpy(l_message->msg_n_sign + a_data_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    l_message->hdr.sign_size = l_sign_size;

    dap_stream_ch_chain_voting_pkt_t *l_voting_pkt =
            dap_stream_ch_chain_voting_pkt_new(l_net->pub.id.uint64, &a_session->my_addr,
                                               NULL, l_message, l_message_size);
    DAP_DELETE(l_message);

    for (dap_list_t *it = a_validators; it; it = it->next) {
        dap_chain_esbocs_validator_t *l_validator = it->data;
        if (l_validator->is_synced || a_message_type == DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC) {
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
    if (a_blocks->chain->ledger == NULL) {
        log_it(L_CRITICAL,"Ledger is NULL can't check consensus conditions on this chain %s", a_blocks->chain->name);
        return -3;
    }
    if (sizeof(a_block->hdr) >= a_block_size) {
        log_it(L_WARNING, "Incorrect header size with block %p on chain %s", a_block, a_blocks->chain->name);
        return  -7;
    }

    if (a_block->hdr.meta_n_datum_n_signs_size != a_block_size - sizeof(a_block->hdr)) {
        log_it(L_WARNING, "Incorrect size with block %p on chain %s", a_block, a_blocks->chain->name);
        return -8;
    }

    if (l_esbocs->session->processing_candidate == a_block)
        // It's a block candidate, don't check signs
        return 0;

    size_t l_offset = dap_chain_block_get_sign_offset(a_block, a_block_size);
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
                char *l_bad_addr = dap_chain_addr_to_str(&l_signing_addr);
                log_it(L_ATT, "Unknown PoS signer %s", l_bad_addr);
                DAP_DELETE(l_bad_addr);
                continue;
            }
        } else {
            // Compare signature with auth_certs
            if (!s_validator_check(&l_signing_addr, l_esbocs_pvt->poa_validators)) {
                char *l_bad_addr = dap_chain_addr_to_str(&l_signing_addr);
                log_it(L_ATT, "Unknown PoA signer %s", l_bad_addr);
                DAP_DELETE(l_bad_addr);
                continue;
            }
        }
        if (dap_sign_verify(l_sign, a_block, l_block_excl_sign_size) == 1)
            l_signs_verified_count++;
    }
    DAP_DELETE(l_signs);
    // Restore the original header
    a_block->hdr.meta_n_datum_n_signs_size = a_block_size - sizeof(a_block->hdr);

    if ( l_ret != 0 ) {
        return l_ret;
    }
    if (l_signs_verified_count < l_esbocs_pvt->min_validators_count) {
        log_it(L_ERROR, "Corrupted block: not enough authorized signs: %u of %u", l_signs_verified_count, l_esbocs_pvt->min_validators_count);
        return -1;
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

static dap_chain_datum_decree_t *s_esbocs_decree_set_min_validators_count(dap_chain_net_t *a_net, uint256_t a_value, dap_cert_t *a_cert)
{
    size_t l_total_tsd_size = 0;
    dap_chain_datum_decree_t *l_decree = NULL;
    dap_list_t *l_tsd_list = NULL;
    dap_tsd_t *l_tsd = NULL;

    l_total_tsd_size += sizeof(dap_tsd_t) + sizeof(uint256_t);
    l_tsd = DAP_NEW_Z_SIZE(dap_tsd_t, l_total_tsd_size);
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT;
    l_tsd->size = sizeof(uint256_t);
    *(uint256_t*)(l_tsd->data) = a_value;
    l_tsd_list = dap_list_append(l_tsd_list, l_tsd);

    l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, sizeof(dap_chain_datum_decree_t) + l_total_tsd_size);
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net->pub.id;
    dap_chain_t *l_chain = dap_chain_net_get_default_chain_by_chain_type(a_net, CHAIN_TYPE_DECREE);
    if(!l_chain){
        log_it(L_ERROR, "Can't find chain with decree support.");
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
static int s_cli_esbocs(int a_argc, char ** a_argv, char **a_str_reply)
{
    int ret = -666;
    int l_arg_index = 1;
    dap_chain_net_t * l_chain_net = NULL;
    dap_chain_t * l_chain = NULL;
    const char *l_cert_str = NULL,
               *l_value_str = NULL;

    if (dap_chain_node_cli_cmd_values_parse_net_chain(&l_arg_index,a_argc,a_argv,a_str_reply,&l_chain,&l_chain_net)) {
        return -3;
    }

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-cert", &l_cert_str);
    if (!l_cert_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'min_validators_count' required parameter -cert");
        return -3;
    }
    dap_cert_t *l_poa_cert = dap_cert_find_by_name(l_cert_str);
    if (!l_poa_cert) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Specified certificate not found");
        return -25;
    }

    dap_cli_server_cmd_find_option_val(a_argv, l_arg_index, a_argc, "-val_count", &l_value_str);
    if (!l_value_str) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Command 'min_validators_count' required parameter -val_count");
        return -9;
    }
    uint256_t l_value = dap_chain_balance_scan(l_value_str);
    if (IS_ZERO_256(l_value)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Unrecognized number in '-val_count' param");
        return -10;
    }

    dap_chain_datum_decree_t *l_decree = s_esbocs_decree_set_min_validators_count(l_chain_net, l_value, l_poa_cert);
    if (l_decree && s_esbocs_decree_put(l_decree, l_chain_net)) {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Minimum validators count is setted");
        DAP_DELETE(l_decree);
    } else {
        dap_cli_server_cmd_set_reply_text(a_str_reply, "Minimum validators count setting failed");
        DAP_DELETE(l_decree);
        return -21;
    }

    return ret;
}
