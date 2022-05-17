
#include "dap_timerfd.h"
#include "utlist.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_block_ton.h"
#include "dap_stream_ch_chain_voting.h"
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_cs_blocks_ton"

static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
static void s_session_packet_in(void * a_arg, dap_chain_node_addr_t * a_sender_node_addr, 
								dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size);
static void s_session_candidate_to_chain(
			dap_chain_cs_block_ton_items_t *a_session, dap_chain_hash_fast_t *a_candidate_hash,
							dap_chain_block_t *a_candidate, size_t a_candidate_size);
static bool s_session_candidate_submit(dap_chain_cs_block_ton_items_t *a_session);
static bool s_session_timer();
static int s_session_atom_validation(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);
static uint8_t *s_message_data_sign(dap_chain_cs_block_ton_items_t *a_session,
						dap_chain_cs_block_ton_message_t *a_message, size_t *a_sign_size);
static void s_message_send(dap_chain_cs_block_ton_items_t *a_session, uint8_t a_message_type,
									uint8_t *a_data, size_t a_data_size, dap_list_t *a_validators);
static void s_message_chain_add(dap_chain_cs_block_ton_items_t * a_session, dap_chain_node_addr_t * a_sender_node_addr, 
									dap_chain_cs_block_ton_message_t * a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash);
static void s_session_round_start(dap_chain_cs_block_ton_items_t *a_session);
static void s_session_block_new_delete(dap_chain_cs_block_ton_items_t *a_session);
static void s_session_my_candidate_delete(dap_chain_cs_block_ton_items_t *a_session);
static bool s_session_round_finish(dap_chain_cs_block_ton_items_t *a_session);
static dap_chain_node_addr_t *s_session_get_validator(
					dap_chain_cs_block_ton_items_t *a_session, dap_chain_node_addr_t *a_addr,
						dap_list_t *a_validators);
static uint16_t s_session_message_count(
			dap_chain_cs_block_ton_items_t *a_session, uint8_t a_round_name, uint8_t a_type,
						dap_chain_hash_fast_t *a_candidate_hash, uint16_t *a_attempt_number);
static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks);
static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg);
static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size);
static int s_callback_block_verify(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);

static int s_compare_validators_list_stake(const void * a_item1, const void * a_item2, void *a_unused);
static int s_compare_validators_list_addr(const void * a_item1, const void * a_item2, void *a_unused);
static dap_list_t *s_get_validators_addr_list(dap_chain_cs_block_ton_items_t *a_session); //(dap_chain_t *a_chain);

static bool s_hash_is_null(dap_chain_hash_fast_t *a_hash);

static dap_chain_cs_block_ton_items_t * s_session_items;
static dap_timerfd_t * s_session_cs_timer = NULL; 

typedef struct dap_chain_cs_block_ton_pvt
{
    dap_enc_key_t *blocks_sign_key;
    char **tokens_hold;
    uint64_t *tokens_hold_value;
    dap_config_t *chain_cfg;
    size_t tokens_hold_size;
    // uint16_t confirmations_minimum;
    dap_chain_callback_new_cfg_t prev_callback_created;

    uint16_t poa_validators_count;
    bool flag_sign_verify;

	bool debug;
	bool validators_list_by_stake;
	uint16_t round_start_sync_timeout;
	uint16_t round_start_multiple_of;
	uint32_t allowed_clock_offset;
	uint32_t session_idle_min;
	uint16_t round_candidates_max;
	uint16_t next_candidate_delay;
	uint16_t round_attempts_max;
	uint16_t round_attempt_duration;
	uint16_t first_message_delay;
   	uint16_t my_candidate_attempts_max;

	dap_list_t *ton_nodes_addrs; // dap_chain_node_addr_t

   	uint16_t auth_certs_count;
    char *auth_certs_prefix;
    dap_cert_t ** auth_certs;
} dap_chain_cs_block_ton_pvt_t;

#define PVT(a) ((dap_chain_cs_block_ton_pvt_t *)a->_pvt)

int dap_chain_cs_block_ton_init() {
	dap_stream_ch_chain_voting_init();
	dap_chain_cs_add("block_ton", s_callback_new);
    return 0;
}

void dap_chain_cs_block_ton_deinit(void) {

}

static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg) {
    dap_chain_cs_blocks_new(a_chain, a_chain_cfg);
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_cs_block_ton_t *l_ton = DAP_NEW_Z(dap_chain_cs_block_ton_t);
    l_blocks->_inheritor = l_ton;
    l_blocks->callback_delete = s_callback_delete;
    l_blocks->callback_block_verify = s_callback_block_verify;
    l_blocks->callback_block_sign = s_callback_block_sign;
    l_ton->_pvt = DAP_NEW_Z(dap_chain_cs_block_ton_pvt_t);

    dap_chain_cs_block_ton_pvt_t *l_ton_pvt = PVT(l_ton);

    char ** l_tokens_hold = NULL;
    char ** l_tokens_hold_value_str = NULL;
    uint16_t l_tokens_hold_size = 0;
    uint16_t l_tokens_hold_value_size = 0;

    l_tokens_hold = dap_config_get_array_str(a_chain_cfg, "block-ton", "stake_tokens", &l_tokens_hold_size);
    l_tokens_hold_value_str = dap_config_get_array_str(a_chain_cfg, "block-ton", "stake_tokens_value", &l_tokens_hold_value_size);

    if (l_tokens_hold_size != l_tokens_hold_value_size){
        log_it(L_CRITICAL, "Entries tokens_hold and tokens_hold_value are different size!");
        goto lb_err;
    }
    //l_ton_pvt->confirmations_minimum = dap_config_get_item_uint16_default(a_chain_cfg, "block-ton", "verifications_minimum", 1);
    l_ton_pvt->flag_sign_verify = true;
    l_ton_pvt->tokens_hold_size = l_tokens_hold_size;
    l_ton_pvt->tokens_hold = DAP_NEW_Z_SIZE(char *, sizeof(char *) * l_tokens_hold_size);
    l_ton_pvt->tokens_hold_value = DAP_NEW_Z_SIZE(uint64_t, l_tokens_hold_value_size * sizeof(uint64_t));
	l_ton_pvt->debug = dap_config_get_item_bool_default(a_chain_cfg,"block-ton","consensus_debug", true);

	l_ton_pvt->validators_list_by_stake = dap_config_get_item_bool_default(a_chain_cfg,"block-ton","validators_list_by_stake", false);
	l_ton_pvt->round_start_sync_timeout = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "round_start_sync_timeout", 10);
	l_ton_pvt->round_start_multiple_of = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "round_start_multiple_of", 30);
	l_ton_pvt->allowed_clock_offset = dap_config_get_item_uint32_default(a_chain_cfg,"block-ton", "allowed_clock_offset", 5);
	l_ton_pvt->session_idle_min = dap_config_get_item_uint32_default(a_chain_cfg,"block-ton", "session_idle_min", 15);
	l_ton_pvt->round_candidates_max = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "round_candidates_max", 3);
	l_ton_pvt->next_candidate_delay = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "next_candidate_delay", 2);
	l_ton_pvt->round_attempts_max = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "round_attempts_max", 4);
	l_ton_pvt->round_attempt_duration = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "round_attempt_duration", 10);
	l_ton_pvt->first_message_delay = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "first_message_delay", 3);
	l_ton_pvt->my_candidate_attempts_max = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton", "my_candidate_attempts_max", 2);
    
    l_ton_pvt->ton_nodes_addrs = NULL;
    l_ton_pvt->auth_certs_prefix = strdup( dap_config_get_item_str_default(a_chain_cfg,"block-ton","auth_certs_prefix", "ton") );
   	l_ton_pvt->auth_certs_count = dap_config_get_item_uint16_default(a_chain_cfg,"block-ton","auth_certs_number", 0);
    if ( !l_ton_pvt->validators_list_by_stake ) { // auth by cert for PoA mode
	    if (l_ton_pvt->auth_certs_count) {
	        l_ton_pvt->auth_certs = DAP_NEW_Z_SIZE(dap_cert_t *, l_ton_pvt->auth_certs_count * sizeof(dap_cert_t));
	        char l_cert_name[512];
	        for (size_t i = 0; i < l_ton_pvt->auth_certs_count; i++ ){
	            dap_snprintf(l_cert_name, sizeof(l_cert_name), "%s.%zu", l_ton_pvt->auth_certs_prefix, i);
	            if ((l_ton_pvt->auth_certs[i] = dap_cert_find_by_name( l_cert_name)) == NULL) {
	                dap_snprintf(l_cert_name, sizeof(l_cert_name), "%s.%zu.pub", l_ton_pvt->auth_certs_prefix, i);
	                if ((l_ton_pvt->auth_certs[i] = dap_cert_find_by_name(l_cert_name)) == NULL) {
	                    log_it(L_ERROR, "TON: Can't find cert \"%s\"", l_cert_name);
	                    return -1;
	                }
	            }
	            log_it(L_NOTICE, "TON: Initialized auth cert \"%s\"", l_cert_name);
	        }
	    }
	
	    uint16_t l_node_addrs_count;
	    char **l_addrs = dap_config_get_array_str(a_chain_cfg, "block-ton", "ton_nodes_addrs", &l_node_addrs_count);
	    l_ton_pvt->poa_validators_count = l_node_addrs_count;
	    for(size_t i = 0; i < l_node_addrs_count; i++) {
	        dap_chain_node_addr_t *l_node_addr = DAP_NEW_Z(dap_chain_node_addr_t);
            if (dap_sscanf(l_addrs[i],NODE_ADDR_FP_STR, NODE_ADDR_FPS_ARGS(l_node_addr) ) != 4 ){
	            log_it(L_ERROR,"TON: Wrong address format,  should be like 0123::4567::890AB::CDEF");
	            DAP_DELETE(l_node_addr);
	            //DAP_DELETE(l_node_info);
	            l_node_addr = NULL;
	            continue;
	        }
	        if (l_node_addr) {
	            log_it(L_MSG, "TON: add validator addr:"NODE_ADDR_FP_STR"", NODE_ADDR_FP_ARGS(l_node_addr));
	        	l_ton_pvt->ton_nodes_addrs = dap_list_append(l_ton_pvt->ton_nodes_addrs, l_node_addr);
	        }
	    }

	}
	else { // stake
	    for (size_t i = 0; i < l_tokens_hold_value_size; i++) {
	        l_ton_pvt->tokens_hold[i] = dap_strdup(l_tokens_hold[i]);
	        if ((l_ton_pvt->tokens_hold_value[i] =
	               strtoull(l_tokens_hold_value_str[i],NULL,10)) == 0) {
	             log_it(L_CRITICAL, "Token %s has inproper hold value %s",
	                                l_ton_pvt->tokens_hold[i], l_tokens_hold_value_str[i]);
	             goto lb_err;
	        }
	    }
	}


    // Save old callback if present and set the call of its own (chain callbacks)
    l_ton_pvt->prev_callback_created = l_blocks->chain->callback_created;
    l_blocks->chain->callback_created = s_callback_created;
    return 0;

lb_err:
    for (int i = 0; i < l_tokens_hold_size; i++)
        DAP_DELETE(l_tokens_hold[i]);
    DAP_DELETE(l_tokens_hold);
    DAP_DELETE(l_ton_pvt->tokens_hold_value);
    DAP_DELETE(l_ton_pvt);
    DAP_DELETE(l_ton );
    l_blocks->_inheritor = NULL;
    l_blocks->callback_delete = NULL;
    l_blocks->callback_block_verify = NULL;
    return -1;

}

static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks) {
    dap_chain_cs_block_ton_t *l_ton = DAP_CHAIN_CS_BLOCK_TON(a_blocks);
    if (l_ton->_pvt)
        DAP_DELETE(l_ton->_pvt);
}


static int s_compare_validators_list_stake(const void * a_item1, const void * a_item2, void *a_unused)
{
    UNUSED(a_unused);
    dap_chain_net_srv_stake_item_t *l_item1 = (dap_chain_net_srv_stake_item_t *)a_item1;
    dap_chain_net_srv_stake_item_t *l_item2 = (dap_chain_net_srv_stake_item_t *)a_item2;
    return compare256(l_item1->value, l_item2->value)*-1;
}

static int s_compare_validators_list_addr(const void * a_item1, const void * a_item2, void *a_unused)
{
    UNUSED(a_unused);
    dap_chain_node_addr_t *l_item1 = (dap_chain_node_addr_t *)a_item1;
    dap_chain_node_addr_t *l_item2 = (dap_chain_node_addr_t *)a_item2;
    if(!l_item1 || !l_item2 || l_item1->uint64 == l_item2->uint64)
        return 0;
    if(l_item1->uint64 > l_item2->uint64)
        return 1;
    return -1;
}

static dap_list_t *s_get_validators_addr_list(dap_chain_cs_block_ton_items_t *a_session) {//(dap_chain_t *a_chain) {

    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_session->chain);
    dap_chain_cs_block_ton_t *l_ton = DAP_CHAIN_CS_BLOCK_TON(l_blocks);
    dap_chain_cs_block_ton_pvt_t *l_ton_pvt = PVT(l_ton);
	dap_list_t *l_ret = NULL;

	if ( l_ton_pvt->validators_list_by_stake) {
		dap_list_t *l_validators = dap_chain_net_srv_stake_get_validators();
		l_validators = dap_list_sort(l_validators, s_compare_validators_list_stake);
		dap_list_t *l_list = dap_list_first(l_validators);
		while (l_list){
	        dap_list_t *l_next = l_list->next;
	        dap_chain_node_addr_t *l_addr =
	        		(dap_chain_node_addr_t *)DAP_DUP_SIZE(
	        			&((dap_chain_net_srv_stake_item_t * )l_list->data)->node_addr,
	        				sizeof(dap_chain_node_addr_t));
	        DAP_DELETE(l_list->data);
	        l_ret = dap_list_append(l_ret, l_addr);
	        l_list = l_next;
	    }
	    dap_list_free(l_list);
	}
	else {
		// dap_chain_net_t *l_net = dap_chain_net_by_id(a_session->chain->net_id);
		dap_list_t *l_list = dap_list_first(PVT(a_session->ton)->ton_nodes_addrs);
		while (l_list) {
			dap_chain_node_addr_t *l_addr =
					(dap_chain_node_addr_t *)DAP_DUP_SIZE(
							l_list->data, sizeof(dap_chain_node_addr_t));
			l_ret = dap_list_append(l_ret, l_addr);
			l_list = l_list->next;
		}
		l_ret = dap_list_sort(l_ret, s_compare_validators_list_addr);
	}
   	return l_ret;
}

static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg) {

    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_cs_block_ton_t *l_ton = DAP_CHAIN_CS_BLOCK_TON(l_blocks);
    dap_chain_cs_block_ton_pvt_t *l_ton_pvt = PVT(l_ton);

    const char *l_sign_cert_str = NULL;
    if ((l_sign_cert_str = dap_config_get_item_str(a_chain_net_cfg,"block-ton","blocks-sign-cert")) != NULL) {
        dap_cert_t *l_sign_cert = dap_cert_find_by_name(l_sign_cert_str);
        if (l_sign_cert == NULL) {
            log_it(L_ERROR, "Can't load sign certificate, name \"%s\" is wrong", l_sign_cert_str);
        } else if (l_sign_cert->enc_key->priv_key_data) {
            l_ton_pvt->blocks_sign_key = l_sign_cert->enc_key;
            log_it(L_INFO, "Loaded \"%s\" certificate to sign TON blocks", l_sign_cert_str);
        } else {
            log_it(L_ERROR, "Certificate \"%s\" has no private key", l_sign_cert_str);
        }
    } else {
        log_it(L_ERROR, "No sign certificate provided, can't sign any blocks");
    }

	dap_chain_net_t *l_net = dap_chain_net_by_id(a_chain->net_id);
	dap_chain_cs_block_ton_items_t *l_session = DAP_NEW_Z(dap_chain_cs_block_ton_items_t);
	l_session->chain = a_chain;
	l_session->ton = l_ton;

    l_session->my_candidate = NULL;
    l_session->my_candidate_size = 0;
    l_session->my_candidate_attempts_count = 0;

	l_session->old_round.validators_list = 
				l_session->cur_round.validators_list = 
								s_get_validators_addr_list(l_session);
	l_session->cur_round.validators_count = dap_list_length(l_session->cur_round.validators_list);

    l_session->my_addr = DAP_NEW(dap_chain_node_addr_t);
	l_session->my_addr->uint64 = dap_chain_net_get_cur_addr_int(l_net);

	l_session->cur_round.id.uint64 = 1000;
	l_session->old_round.id.uint64 = 0;
	l_session->gdb_group_store = dap_strdup_printf("local.ton.%s.%s.store", 
										a_chain->net_name, a_chain->name);
	l_session->gdb_group_message = dap_strdup_printf("local.ton.%s.%s.message",
										a_chain->net_name, a_chain->name);
	l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE;
	l_session->time_proc_lock = false;
	
	dap_time_t l_time = dap_time_now();
	while (true) {
		l_time++;
		if ( (l_time % PVT(l_session->ton)->round_start_multiple_of) == 0) {
			l_session->ts_round_sync_start = l_time;
			break;
		}
	}
	pthread_rwlock_init(&l_session->rwlock, NULL);

	log_it(L_INFO, "TON: init session for net:%s, chain:%s", a_chain->net_name, a_chain->name);
	DL_APPEND(s_session_items, l_session);
    dap_chain_node_role_t l_role = dap_chain_net_get_role(l_net);
    if ( PVT(l_session->ton)->validators_list_by_stake ||
                    (l_role.enums == NODE_ROLE_MASTER || l_role.enums == NODE_ROLE_ROOT) ) {
		if ( s_session_get_validator(l_session, l_session->my_addr, l_session->cur_round.validators_list) ) {
			if (!s_session_cs_timer) {
				s_session_cs_timer = dap_timerfd_start(1*1000, 
		                        (dap_timerfd_callback_t)s_session_timer, 
		                        NULL);
				if (PVT(l_session->ton)->debug)
					log_it(L_MSG, "TON: Consensus main timer is started");
			}
			dap_stream_ch_chain_voting_in_callback_add(l_session, s_session_packet_in);
		}
	}
	return 0;
}

static void s_session_round_start(dap_chain_cs_block_ton_items_t *a_session) {

	a_session->cur_round.validators_start = NULL;
	a_session->cur_round.validators_start_count = 0;

	a_session->cur_round.validators_list = NULL;
	a_session->cur_round.validators_count = 0;

	a_session->cur_round.candidates_count = 0;

	a_session->ts_round_start = 0;
	a_session->ts_round_state_commit = 0;
	a_session->attempt_current_number = 1;

	a_session->cur_round.my_candidate_hash = NULL;
	a_session->cur_round.last_message_hash = NULL;
	a_session->cur_round.messages_count = 0;
	a_session->cur_round.submit = false;

	a_session->ts_round_sync_start = dap_time_now();
	a_session->cur_round.id.uint64++;

    size_t l_objs_size = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(a_session->gdb_group_store, &l_objs_size);
    if (l_objs_size) {
    	dap_chain_cs_block_ton_store_t *l_store_candidate_ready = NULL;
    	size_t l_candidate_ready_size = 0;
        for (size_t i = 0; i < l_objs_size; i++) {
            if (!l_objs[i].value_len)
                continue;
            dap_chain_cs_block_ton_store_t *l_store = 
										(dap_chain_cs_block_ton_store_t *)l_objs[i].value;
			if ( l_store->hdr.round_id.uint64 != a_session->cur_round.id.uint64 ) {
				// dap_chain_global_db_gr_del(dap_strdup(l_objs[i].key), a_session->gdb_group_store);
				if ( l_store->hdr.sign_collected ) {
					l_store_candidate_ready = l_store;
				}
			}
        }
        if (l_store_candidate_ready) {
        	s_session_candidate_to_chain(a_session, &l_store_candidate_ready->hdr.candidate_hash, 
        					(dap_chain_block_t*)l_store_candidate_ready->candidate_n_signs, l_store_candidate_ready->hdr.candidate_size);
        }
        dap_chain_global_db_objs_delete(l_objs, l_objs_size);
    }
}

static bool s_session_send_startsync(dap_chain_cs_block_ton_items_t *a_session){
	dap_chain_cs_block_ton_message_startsync_t *l_startsync =
											DAP_NEW_Z(dap_chain_cs_block_ton_message_startsync_t);
	l_startsync->ts = a_session->ts_round_sync_start;
	l_startsync->round_id.uint64 = a_session->cur_round.id.uint64;
	s_message_send(a_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC, 
							(uint8_t*)l_startsync, sizeof(dap_chain_cs_block_ton_message_startsync_t),
								a_session->cur_round.validators_list);
	if (PVT(a_session->ton)->debug)
        log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" Sent START_SYNC pkt",
					a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id.uint64);

	DAP_DELETE(l_startsync);
	return false;
}

typedef struct s_session_send_votefor_data {
	dap_chain_cs_block_ton_message_votefor_t *votefor;
	dap_chain_cs_block_ton_items_t *session;
} DAP_ALIGN_PACKED s_session_send_votefor_data_t;

static bool s_session_send_votefor(s_session_send_votefor_data_t *a_data){
	dap_chain_cs_block_ton_message_votefor_t *l_votefor = a_data->votefor;
	dap_chain_cs_block_ton_items_t *l_session = a_data->session;
	l_votefor->round_id.uint64 = l_session->cur_round.id.uint64;
	s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR,
	 					(uint8_t*)l_votefor, sizeof(dap_chain_cs_block_ton_message_votefor_t),
	 						l_session->cur_round.validators_start);
	DAP_DELETE(l_votefor);
	DAP_DELETE(a_data);
	return false;
}

static bool s_session_timer() {
	dap_time_t l_time = dap_time_now();
	dap_chain_cs_block_ton_items_t *l_session = NULL;
	DL_FOREACH(s_session_items, l_session) {
		if ( l_session->time_proc_lock ) {
			continue;
		}
		pthread_rwlock_rdlock(&l_session->rwlock);
		l_session->time_proc_lock = true; // lock - skip check by reasons: prev check is not finish
		switch (l_session->state) {
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE: {
				if ( (((l_time/10)*10) % PVT(l_session->ton)->round_start_multiple_of) == 0 
							&& (l_time - ((l_time/10)*10)) <= 3
							&& l_time > l_session->ts_round_finish
							&& (l_time-l_session->ts_round_finish) >= PVT(l_session->ton)->session_idle_min) {

					// round start
					l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START;
					s_session_round_start(l_session);

					dap_list_free_full(l_session->cur_round.validators_list, free);
					l_session->cur_round.validators_list = s_get_validators_addr_list(l_session);
					l_session->cur_round.validators_count = dap_list_length(l_session->cur_round.validators_list);

					dap_timerfd_start(PVT(l_session->ton)->first_message_delay*1000, 
						(dap_timerfd_callback_t)s_session_send_startsync, 
							l_session);

					if (PVT(l_session->ton)->debug)
                        log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Start syncing validators ",
								l_session->chain->net_name, l_session->chain->name,
									l_session->cur_round.id.uint64, l_session->attempt_current_number);
				}
				goto session_unlock;
			} //break;
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START: {
				if ( (l_time-l_session->ts_round_sync_start) >= PVT(l_session->ton)->round_start_sync_timeout ) { // timeout start sync
					uint16_t l_startsync_count = l_session->cur_round.validators_start_count;
					if ( ((float)l_startsync_count/l_session->cur_round.validators_count) >= ((float)2/3) ) {
						// if sync more 2/3 validators then start round and submit candidate
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu More than 2/3 of the validators are synchronized, so starting the round and send the candidate",
									l_session->chain->net_name, l_session->chain->name,
										l_session->cur_round.id.uint64, l_session->attempt_current_number);

						l_session->ts_round_start = l_time;
						l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC;
						
						// sort validators list
						dap_list_t *l_validators_start = l_session->cur_round.validators_start;
						l_session->cur_round.validators_start = NULL;
						dap_list_t *l_validators_list_temp = dap_list_first(l_session->cur_round.validators_list);
						while (l_validators_list_temp) {
							dap_chain_node_addr_t *l_validator_1 = (dap_chain_node_addr_t *)l_validators_list_temp->data;
							l_validators_list_temp = l_validators_list_temp->next;
							dap_list_t *l_validators_start_temp = dap_list_first(l_validators_start);
							while (l_validators_start_temp) {
								dap_chain_node_addr_t *l_validator_2 = (dap_chain_node_addr_t *)l_validators_start_temp->data;
								l_validators_start_temp = l_validators_start_temp->next;
								if ( l_validator_1->uint64 == l_validator_2->uint64 ) {
									l_session->cur_round.validators_start = 
											dap_list_append(l_session->cur_round.validators_start, l_validator_1);
								}
							}
						}

						// first coordinator
						l_session->attempt_coordinator =
								(dap_chain_node_addr_t *)(dap_list_first(l_session->cur_round.validators_start)->data);
					} else {
						s_session_round_finish(l_session);
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Round finish by reason: can't synchronized 2/3 of the validators",
									l_session->chain->net_name, l_session->chain->name,
										l_session->cur_round.id.uint64, l_session->attempt_current_number);
					}
				}
				goto session_unlock;
			} //break;
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS:
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC: {
				if ( !l_session->cur_round.submit && l_session->attempt_current_number == 1 ) {
					dap_list_t *l_validators_list = dap_list_first(l_session->cur_round.validators_start);
					int l_my_number = -1;
					int i = 0;
					while(l_validators_list) {
						if( ((dap_chain_node_addr_t*)l_validators_list->data)->uint64 == l_session->my_addr->uint64) {
							l_my_number = i;
							break;
						}
						i++;
						l_validators_list = l_validators_list->next;
					}
					if ( l_my_number != -1 ) {
						l_my_number++;
						if ( (l_time-l_session->ts_round_start) >=
									(dap_time_t)((PVT(l_session->ton)->next_candidate_delay*l_my_number)+PVT(l_session->ton)->first_message_delay) ) {
							l_session->cur_round.submit = true;
							s_session_candidate_submit(l_session);
						}
					}
				}

				if ( (l_time-l_session->ts_round_start) >=
							(dap_time_t)(PVT(l_session->ton)->round_attempt_duration*l_session->attempt_current_number) ) {

					l_session->attempt_current_number++;
					if ( l_session->attempt_current_number > PVT(l_session->ton)->round_attempts_max ) {
						s_session_round_finish(l_session); // attempts is out
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Round finish by reason: attempts is out",
									l_session->chain->net_name, l_session->chain->name,
										l_session->cur_round.id.uint64, l_session->attempt_current_number);
						goto session_unlock;
					}
					if ( l_session->cur_round.candidates_count == 0 ) { // no candidates
						s_session_round_finish(l_session);
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Round finish by reason: no block candidates",
									l_session->chain->net_name, l_session->chain->name,
										l_session->cur_round.id.uint64, l_session->attempt_current_number);
						goto session_unlock;
					}
					if ( l_session->state == DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS ) {
						goto session_unlock;
					}
					
					uint16_t l_validators_count = l_session->cur_round.validators_start_count;
					uint64_t l_mod = 0;
					if (!PVT(l_session->ton)->validators_list_by_stake) {
						// rotate validatir list in non-stake mode
						l_mod = l_session->cur_round.id.uint64;
					}
					uint16_t l_validators_index =
									( (l_session->attempt_current_number-2+l_mod)
										- (l_validators_count
												*((l_session->attempt_current_number-2+l_mod)/l_validators_count)));
					
					l_session->attempt_coordinator = (dap_chain_node_addr_t *)
											(dap_list_nth(l_session->cur_round.validators_start, 
													l_validators_index)->data);
					if (PVT(l_session->ton)->debug)
                        log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Start attempt: selected coordinator "NODE_ADDR_FP_STR"(index:%u)",
								l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
									l_session->attempt_current_number, NODE_ADDR_FP_ARGS(l_session->attempt_coordinator),
										l_validators_index);

					if ( l_session->my_addr->uint64 == l_session->attempt_coordinator->uint64 ) {
						// I coordinator :-) select candidate
		                dap_list_t *l_list_candidate = NULL;
		                size_t l_objs_size = 0;
		                dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_objs_size);
		                if (l_objs_size) {
		                    for (size_t i = 0; i < l_objs_size; i++) {
		                        if (!l_objs[i].value_len)
		                            continue;

           						dap_chain_cs_block_ton_store_t *l_store = 
											(dap_chain_cs_block_ton_store_t *)l_objs[i].value;
								if ( l_store->hdr.round_id.uint64 != l_session->cur_round.id.uint64 )
									continue;

								// add candidate in list if it has 2/3 approve
								if ( l_store->hdr.approve_collected ) {
									dap_chain_hash_fast_t * l_hash = DAP_NEW(dap_chain_hash_fast_t);
									dap_chain_hash_fast_from_str(l_objs[i].key, l_hash);
		                       		l_list_candidate = dap_list_append(l_list_candidate, l_hash);
		                       	}
		                    }
		                    dap_chain_global_db_objs_delete(l_objs, l_objs_size);
		                }
		                size_t l_list_candidate_size = (size_t)dap_list_length(l_list_candidate);
						dap_chain_cs_block_ton_message_votefor_t *l_votefor =
														DAP_NEW_Z(dap_chain_cs_block_ton_message_votefor_t);
		                if (l_list_candidate) {
							dap_chain_hash_fast_t *l_candidate_hash = dap_list_nth_data(l_list_candidate, (rand()%l_list_candidate_size));
							memcpy(&l_votefor->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
							dap_list_free_full(l_list_candidate, free);
						}
						else {
							dap_chain_hash_fast_t l_candidate_hash_null={0};
							memcpy(&l_votefor->candidate_hash, &l_candidate_hash_null, sizeof(dap_chain_hash_fast_t));
						}
						l_votefor->attempt_number = l_session->attempt_current_number;
						s_session_send_votefor_data_t *l_data = DAP_NEW_Z(s_session_send_votefor_data_t);
						l_data->votefor = l_votefor;
						l_data->session = l_session;
						dap_timerfd_start(PVT(l_session->ton)->first_message_delay*1000, // pause before send votefor
			                    (dap_timerfd_callback_t)s_session_send_votefor, 
			                    	l_data);
						if (PVT(l_session->ton)->debug) {
							char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_votefor->candidate_hash);
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu I coordinator :-) Sent VoteFor candidate:%s",
									l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
										l_session->attempt_current_number, l_hash_str);
							DAP_DELETE(l_hash_str);
						}
					}
				}
				goto session_unlock;
			}
		}
session_unlock:
		l_session->time_proc_lock = false; // unlock
		pthread_rwlock_unlock(&l_session->rwlock);
	}
	return true;
}

static void s_session_candidate_to_chain(
			dap_chain_cs_block_ton_items_t *a_session, dap_chain_hash_fast_t *a_candidate_hash,
							dap_chain_block_t *a_candidate, size_t a_candidate_size) {

	dap_list_t *l_commitsign_list = NULL;
    dap_chain_cs_block_ton_message_item_t *l_message_item=NULL, *l_message_tmp=NULL;
    HASH_ITER(hh, a_session->old_round.messages_items, l_message_item, l_message_tmp) {
    	uint8_t l_message_type = l_message_item->message->hdr.type;
    	if ( l_message_type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN ) {
    		dap_chain_hash_fast_t *l_candidate_hash = 
    				&((dap_chain_cs_block_ton_message_commitsign_t *)
    						(l_message_item->message->sign_n_message+l_message_item->message->hdr.sign_size))->candidate_hash;
    		if ( memcmp(l_candidate_hash, a_candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
    			l_commitsign_list = dap_list_append(l_commitsign_list, (void*)l_message_item->message);
    		}
    	}
    }
    if (!l_commitsign_list) {
    	return;
    }
    dap_chain_block_t *l_candidate = 
    	(dap_chain_block_t *)DAP_DUP_SIZE(a_candidate, a_candidate_size);

	size_t l_signs_count = 0;
	dap_list_t *l_validators_list = dap_list_first(a_session->old_round.validators_start);
	while(l_validators_list) {
		dap_chain_node_addr_t *l_validator = (dap_chain_node_addr_t *)l_validators_list->data;
		l_validators_list = l_validators_list->next;
		dap_list_t *l_submit_temp = dap_list_first(l_commitsign_list);
		while(l_submit_temp) {
			dap_chain_cs_block_ton_message_t *l_message = (dap_chain_cs_block_ton_message_t *)l_submit_temp->data;
			dap_chain_cs_block_ton_message_commitsign_t *l_commitsign = 
						(dap_chain_cs_block_ton_message_commitsign_t *)
									(l_message->sign_n_message+l_message->hdr.sign_size);
			if( l_message->hdr.is_verified 
					&& l_message->hdr.sender_node_addr.uint64 == l_validator->uint64) {
				dap_sign_t *l_candidate_sign = (dap_sign_t *)l_commitsign->candidate_sign;
				size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
				if (!l_candidate_sign_size) {
        			continue;
				}
        		l_candidate = DAP_REALLOC(l_candidate, a_candidate_size+l_candidate_sign_size);
				memcpy(((byte_t *)l_candidate)+a_candidate_size, l_candidate_sign, l_candidate_sign_size);
				a_candidate_size += l_candidate_sign_size;
				l_signs_count++;
			}
			l_submit_temp = l_submit_temp->next;
		}
	}

	if ( ((float)l_signs_count/a_session->old_round.validators_count) >= ((float)2/3) ) {
		//dap_chain_t *l_chain = a_session->chain;
		//dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
		dap_chain_atom_verify_res_t l_res = a_session->chain->callback_atom_add(a_session->chain, l_candidate, a_candidate_size);
		char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(a_candidate_hash);
		switch (l_res) {
			case ATOM_ACCEPT: {
				// block save to chain
		        if (dap_chain_atom_save(a_session->chain, (uint8_t *)l_candidate, a_candidate_size, a_session->chain->cells->id) < 0) {
		            log_it(L_ERROR, "TON: Can't save atom %s to the file", l_candidate_hash_str);
		        }
		        else {
					log_it(L_INFO, "TON: atom %s added in chain successfully", l_candidate_hash_str);
		        }
		    } break;
		    case ATOM_MOVE_TO_THRESHOLD: {
		        log_it(L_INFO, "TON: Thresholded atom with hash %s", l_candidate_hash_str);
		    } break;
		    case ATOM_PASS: {
		    	log_it(L_WARNING, "TON: Atom with hash %s not accepted (code ATOM_PASS, already present)", l_candidate_hash_str);
                DAP_DELETE(l_candidate);
		    } break;
		    case ATOM_REJECT: {
		        log_it(L_WARNING,"TON: Atom with hash %s rejected", l_candidate_hash_str);
                DAP_DELETE(l_candidate);
		    } break;
		    default:
                // DAP_DELETE(l_candidate);
		        // log_it(L_CRITICAL, "TON: Wtf is this ret code? %d", l_candidate_hash_str);
		        break;
		}
		DAP_DELETE(l_candidate_hash_str);
		dap_chain_hash_fast_t l_my_candidate_hash;
		dap_hash_fast(a_session->my_candidate, a_session->my_candidate_size, &l_my_candidate_hash);
		if (memcmp(&l_my_candidate_hash, a_candidate_hash,
							sizeof(dap_chain_hash_fast_t)) == 0) {
			s_session_my_candidate_delete(a_session);
		}
	}
    //DAP_DELETE(l_candidate);
}

static bool s_session_candidate_submit(dap_chain_cs_block_ton_items_t *a_session){
    
	// if (!a_session->my_candidate 
	// 		|| a_session->my_candidate_attempts_count 
	// 			>= PVT(a_session->ton)->my_candidate_attempts_max) {
	// 	dap_chain_t *l_chain = a_session->chain;
	// 	dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
	// 	s_session_my_candidate_delete(a_session);
	// 	if ( l_blocks->block_new_size && l_blocks->block_new) {
	// 		a_session->my_candidate = (dap_chain_block_t *)DAP_DUP_SIZE(l_blocks->block_new, l_blocks->block_new_size);
	// 		a_session->my_candidate_size = l_blocks->block_new_size;
	// 		s_session_block_new_delete(a_session);
	// 	}
	// }
	
	dap_chain_t *l_chain = a_session->chain;
	dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
	s_session_my_candidate_delete(a_session);
	dap_chain_cs_new_block_add_datums(l_chain); // add new datums from queue
	if ( l_blocks->block_new_size && l_blocks->block_new) {
		a_session->my_candidate = (dap_chain_block_t *)DAP_DUP_SIZE(l_blocks->block_new, l_blocks->block_new_size);
		a_session->my_candidate_size = l_blocks->block_new_size;
		s_session_block_new_delete(a_session);
	}

	size_t l_submit_size = a_session->my_candidate ? 
				sizeof(dap_chain_cs_block_ton_message_submit_t)+a_session->my_candidate_size
					: sizeof(dap_chain_cs_block_ton_message_submit_t);
	
	// dap_chain_cs_new_block_add_datums(dap_chain_t *a_chain);
	// size_t l_submit_size = l_blocks->block_new ? 
	// 			sizeof(dap_chain_cs_block_ton_message_submit_t)+a_session->my_candidate_size
	// 				: sizeof(dap_chain_cs_block_ton_message_submit_t);

	dap_chain_cs_block_ton_message_submit_t *l_submit =
							DAP_NEW_SIZE(dap_chain_cs_block_ton_message_submit_t, l_submit_size);
	l_submit->round_id.uint64 = a_session->cur_round.id.uint64;
	l_submit->candidate_size = a_session->my_candidate_size;

	bool l_candidate_exists = false;
	if ( a_session->my_candidate ) {
		dap_chain_hash_fast_t l_candidate_hash;
		dap_hash_fast(a_session->my_candidate, a_session->my_candidate_size, &l_candidate_hash);
		// pass if this candidate participated in old round
		if ( !a_session->old_round.my_candidate_hash 
						|| memcmp(&l_candidate_hash, a_session->old_round.my_candidate_hash,
										sizeof(dap_chain_hash_fast_t)) != 0 ) {
			memcpy(&l_submit->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
			a_session->cur_round.my_candidate_hash = 
					(dap_chain_hash_fast_t*)DAP_DUP_SIZE(&l_candidate_hash, sizeof(dap_chain_hash_fast_t));
			memcpy(l_submit->candidate, a_session->my_candidate, a_session->my_candidate_size);
			if (PVT(a_session->ton)->debug) {
				char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_candidate_hash);
	            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" Submit my candidate:%s",
						a_session->chain->net_name, a_session->chain->name,
							a_session->cur_round.id.uint64, l_hash_str);
				DAP_DELETE(l_hash_str);
			}
			a_session->my_candidate_attempts_count++;
			l_candidate_exists = true;
		}
	} 

	if (!l_candidate_exists) { // no my candidate, send null hash
		dap_chain_hash_fast_t l_candidate_hash_null={0};
		a_session->cur_round.my_candidate_hash = NULL;
		memcpy(&l_submit->candidate_hash, &l_candidate_hash_null, sizeof(dap_chain_hash_fast_t));
		if (PVT(a_session->ton)->debug)
            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu I don't have a candidate. I submit a null candidate.",
						a_session->chain->net_name, a_session->chain->name,
							a_session->cur_round.id.uint64, a_session->attempt_current_number);
	}
	s_message_send(a_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT,
					(uint8_t*)l_submit, l_submit_size, a_session->cur_round.validators_start);
	DAP_DELETE(l_submit);

    return false; // for timer
}

static int s_session_atom_validation(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size){
    dap_chain_cs_block_ton_t *l_ton = DAP_CHAIN_CS_BLOCK_TON(a_blocks);
	dap_chain_atom_verify_res_t l_res = ATOM_ACCEPT;
	PVT(l_ton)->flag_sign_verify = false;
	l_res = a_blocks->chain->callback_atom_verify(a_blocks->chain, a_block, a_block_size);
	PVT(l_ton)->flag_sign_verify = true;
	if(l_res == ATOM_ACCEPT){
		return 0;
	}
    return -1;
}

static void s_session_block_new_delete(dap_chain_cs_block_ton_items_t *a_session) {
	dap_chain_t *l_chain = a_session->chain;
	dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
	l_blocks->callback_new_block_del(l_blocks);
}

static void s_session_my_candidate_delete(dap_chain_cs_block_ton_items_t *a_session) {
	if (a_session->my_candidate){
		if (PVT(a_session->ton)->debug) {
			dap_chain_hash_fast_t l_candidate_hash;
			dap_hash_fast(a_session->my_candidate, a_session->my_candidate_size, &l_candidate_hash);
			char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_candidate_hash);
		    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Delete my candidate %s",
					a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id.uint64,
						a_session->attempt_current_number, l_hash_str );
			DAP_DELETE(l_hash_str);
		}
		DAP_DEL_Z(a_session->my_candidate);
	}
    a_session->my_candidate_size = 0;
   	a_session->my_candidate_attempts_count = 0;
}

static bool s_hash_is_null(dap_chain_hash_fast_t *a_hash){
	if (!a_hash)
		return true;
	dap_chain_hash_fast_t l_candidate_hash_null={0};
    return (memcmp(&l_candidate_hash_null, a_hash,
                            sizeof(dap_chain_hash_fast_t)) == 0)
						? true : false;
}

static bool s_session_round_finish(dap_chain_cs_block_ton_items_t *a_session) {

	a_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE;
	a_session->ts_round_finish = dap_time_now();

    size_t l_objs_size = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(a_session->gdb_group_store, &l_objs_size);
    if (l_objs_size) {
    	dap_chain_cs_block_ton_store_t *l_store_candidate_ready = NULL;
    	size_t l_candidate_ready_size = 0;
        for (size_t i = 0; i < l_objs_size; i++) {
            if (!l_objs[i].value_len)
                continue;
            dap_chain_cs_block_ton_store_t *l_store = 
										(dap_chain_cs_block_ton_store_t *)l_objs[i].value;
			if ( l_store->hdr.round_id.uint64 != a_session->cur_round.id.uint64
					||  (l_store->hdr.round_id.uint64 == a_session->cur_round.id.uint64
							&& !l_store->hdr.sign_collected) ) {
				dap_chain_global_db_gr_del(dap_strdup(l_objs[i].key), a_session->gdb_group_store);
				if ( l_store->hdr.sign_collected ) {
					l_store_candidate_ready = l_store;
				}
			}

			if ( l_store->hdr.round_id.uint64 == a_session->cur_round.id.uint64 ) {
				if ( a_session->cur_round.my_candidate_hash
						//&& !l_store->hdr.approve_collected
						&& memcmp(&l_store->hdr.candidate_hash,
								a_session->cur_round.my_candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {

					// delete my candidate if it passed consensus or not collected 2/3 approve
					if ( !l_store->hdr.approve_collected || l_store->hdr.sign_collected ) {
						// s_session_my_candidate_delete(a_session);
						// DAP_DELETE(a_session->cur_round.my_candidate_hash);
						// a_session->cur_round.my_candidate_hash=NULL;
						if (PVT(a_session->ton)->debug) {
							char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_store->hdr.candidate_hash);
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu My candidate:%s %s Delete block_new.",
									a_session->chain->net_name, a_session->chain->name, a_session->cur_round.id.uint64,
										a_session->attempt_current_number, l_hash_str,
										(l_store->hdr.sign_collected ? "passed consensus!" : "didn't collected 2/3 approve.") );
							DAP_DELETE(l_hash_str);
						}
					}
				}
			}
        }
        // if (l_store_candidate_ready) {
        // 	s_session_candidate_to_chain(a_session, &l_store_candidate_ready->hdr.candidate_hash, 
        // 					(dap_chain_block_t*)l_store_candidate_ready->candidate_n_signs, l_store_candidate_ready->hdr.candidate_size);
        // }
        dap_chain_global_db_objs_delete(l_objs, l_objs_size);
    }

    dap_chain_cs_block_ton_message_item_t *l_message_item=NULL, *l_message_tmp=NULL;
    HASH_ITER(hh, a_session->old_round.messages_items, l_message_item, l_message_tmp) {
        // Clang bug at this, l_message_item should change at every loop cycle
        HASH_DEL(a_session->old_round.messages_items, l_message_item);
        DAP_DELETE(l_message_item->message);
        DAP_DELETE(l_message_item);
    }

    if ( a_session->old_round.validators_start ) {
    	// delete only links
		dap_list_free(a_session->old_round.validators_start);
	}
	a_session->old_round.validators_start = NULL;

    if ( a_session->old_round.validators_list ) {
    	// delete validators 
		dap_list_free_full(a_session->old_round.validators_list, free);
	}
	a_session->old_round.validators_list = NULL;

    if ( a_session->old_round.last_message_hash ) {
		DAP_DELETE(a_session->old_round.last_message_hash);
		a_session->old_round.last_message_hash = NULL;
	}

    if ( a_session->old_round.my_candidate_hash ) {
		DAP_DELETE(a_session->old_round.my_candidate_hash);
		a_session->old_round.my_candidate_hash = NULL;
	}

	// move cur round to old
	a_session->old_round.id.uint64 = a_session->cur_round.id.uint64;

	a_session->old_round.messages_items = a_session->cur_round.messages_items;
	a_session->cur_round.messages_items = NULL;

	a_session->old_round.validators_start_count = a_session->cur_round.validators_start_count;
	a_session->old_round.validators_start = a_session->cur_round.validators_start;
	a_session->cur_round.validators_start = NULL;

	a_session->old_round.validators_count = a_session->cur_round.validators_count;
	a_session->old_round.validators_list = a_session->cur_round.validators_list;
	a_session->cur_round.validators_list = NULL;

	a_session->old_round.candidates_count = a_session->cur_round.candidates_count;

	a_session->old_round.last_message_hash = a_session->cur_round.last_message_hash;
	a_session->cur_round.last_message_hash = NULL;
	a_session->old_round.messages_count = a_session->cur_round.messages_count;

	a_session->old_round.my_candidate_hash = a_session->cur_round.my_candidate_hash;
	a_session->cur_round.my_candidate_hash = NULL;

	return false;
}

// this is planned for get validator addr if validator addr list to be changed to stakes,
// but currently it using for check validator addr exists
static dap_chain_node_addr_t *s_session_get_validator(
					dap_chain_cs_block_ton_items_t * a_session, dap_chain_node_addr_t * a_addr,
						dap_list_t *a_validators) {
	// dap_chain_cs_block_ton_round_t *l_round = a_round_name == DAP_TON$ROUND_CUR ? // 'c' or 'o'
	// 					&a_session->cur_round : &a_session->old_round;
	dap_list_t* l_list_validator = dap_list_first(a_validators);
	while(l_list_validator) {
		dap_list_t *l_list_validator_next = l_list_validator->next;
		if ( ((dap_chain_node_addr_t *)l_list_validator->data)->uint64 == a_addr->uint64 )
			return l_list_validator->data;
		l_list_validator = l_list_validator_next;
	}
	return NULL;
}

static uint16_t s_session_message_count(
			dap_chain_cs_block_ton_items_t *a_session, uint8_t a_round_name, uint8_t a_type,
						dap_chain_hash_fast_t *a_candidate_hash, uint16_t *a_attempt_number) {
	dap_chain_cs_block_ton_message_item_t *l_messages_items = NULL;
	l_messages_items = a_round_name == DAP_TON$ROUND_CUR ? // 'c' or 'o'
						a_session->cur_round.messages_items
					  : a_session->old_round.messages_items;
	uint16_t l_message_count = 0;
	dap_chain_cs_block_ton_message_item_t *l_chain_message=NULL, *l_chain_message_tmp=NULL;
	HASH_ITER(hh, l_messages_items, l_chain_message, l_chain_message_tmp) {
		dap_chain_cs_block_ton_message_getinfo_t *l_getinfo = 
					(dap_chain_cs_block_ton_message_getinfo_t *)
							(l_chain_message->message->sign_n_message+l_chain_message->message->hdr.sign_size);
		if (
				l_chain_message->message->hdr.type == a_type
				&& (!a_candidate_hash || memcmp(&l_getinfo->candidate_hash, a_candidate_hash,
											sizeof(dap_chain_hash_fast_t)) == 0)
			) {
				switch(a_type) {
					// case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT:
					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR:
					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
						if ( a_attempt_number && *a_attempt_number == l_getinfo->attempt_number) {
							l_message_count++;
						}
					} break;
					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
						if (l_chain_message->message->hdr.is_verified){
							l_message_count++;
						}
					} break;
					default:
						l_message_count++;
						break;
				}
		}
	}
	return l_message_count;
}


static void s_session_packet_in(void *a_arg, dap_chain_node_addr_t *a_sender_node_addr, 
								dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size) {
	bool l_message_delete = true;
	dap_chain_cs_block_ton_items_t *l_session = (dap_chain_cs_block_ton_items_t *)a_arg;
	dap_chain_cs_block_ton_message_t *l_message =
			(dap_chain_cs_block_ton_message_t *)DAP_DUP_SIZE(a_data, a_data_size);

	if (PVT(l_session->ton)->debug)
        log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive pkt type:%x from addr:"NODE_ADDR_FP_STR", my_addr:"NODE_ADDR_FP_STR"",
				l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
					l_session->attempt_current_number, l_message->hdr.type,
						NODE_ADDR_FP_ARGS(a_sender_node_addr), NODE_ADDR_FP_ARGS(l_session->my_addr));

	if ( !PVT(l_session->ton)->validators_list_by_stake ) {
		size_t l_data_size = 0;
		dap_sign_t *l_sign = (dap_sign_t*)l_message->sign_n_message;
		uint8_t *l_data = s_message_data_sign(l_session, l_message, &l_data_size);
		bool l_verify_passed = false;
		for (uint16_t j = 0; j < PVT(l_session->ton)->auth_certs_count; j++) {
		    if ( dap_cert_compare_with_sign(PVT(l_session->ton)->auth_certs[j], l_sign) == 0
		    		&& dap_sign_verify(l_sign, l_data, l_data_size) == 1 ) {
		    	l_verify_passed = true;
		    	break;
		    }
		}
		//DAP_DELETE(l_sign);
		DAP_DELETE(l_data);
		if (!l_verify_passed) {
			if (PVT(l_session->ton)->debug)
		        log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected from addr:"NODE_ADDR_FP_STR" not passed verification",
						l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
							l_session->attempt_current_number, NODE_ADDR_FP_ARGS(a_sender_node_addr));
		    goto handler_finish;
		}
	}
    
    if (l_message->hdr.chain_id.uint64 != l_session->chain->id.uint64 ) {
    	goto handler_finish;
    }

    dap_time_t l_time = dap_time_now();
	l_message->hdr.is_verified=false;

    dap_chain_hash_fast_t l_data_hash = {};
    dap_hash_fast(a_data, a_data_size, &l_data_hash);
    if (memcmp(a_data_hash, &l_data_hash, sizeof(dap_chain_hash_fast_t)) != 0) {
		if (PVT(l_session->ton)->debug)
            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: message hash does not match",
					l_session->chain->net_name, l_session->chain->name,
						l_session->cur_round.id.uint64, l_session->attempt_current_number);
		goto handler_finish;
    }

	// consensus round start sync
	if ( l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC ) {
		// check time offset
		dap_chain_cs_block_ton_message_startsync_t *l_startsync =
							(dap_chain_cs_block_ton_message_startsync_t *)
									(l_message->sign_n_message+l_message->hdr.sign_size);

		if (PVT(l_session->ton)->debug)
            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive START_SYNC: from addr:"NODE_ADDR_FP_STR"",
					l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
						l_session->attempt_current_number, NODE_ADDR_FP_ARGS(a_sender_node_addr));

		dap_chain_node_addr_t *l_validator = 
				s_session_get_validator(l_session, a_sender_node_addr, l_session->cur_round.validators_list);

		if (!l_validator) {
			if (PVT(l_session->ton)->debug)
            	log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: validator addr:"NODE_ADDR_FP_STR" not on the list.",
					l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
						l_session->attempt_current_number, NODE_ADDR_FP_ARGS(a_sender_node_addr));
			goto handler_finish;
		}

		if ( 
			(l_time>l_startsync->ts && (l_time-l_startsync->ts) > PVT(l_session->ton)->allowed_clock_offset )
				|| (l_time<l_startsync->ts && (l_startsync->ts-l_time) > PVT(l_session->ton)->allowed_clock_offset )
					) {
			// offset is more than allowed_clock_offset
			// skip this validator 
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: too much time difference: my time:%"DAP_UINT64_FORMAT_U" sender time:%"DAP_UINT64_FORMAT_U"",
						l_session->chain->net_name, l_session->chain->name,
							l_session->cur_round.id.uint64, l_session->attempt_current_number, l_time, l_startsync->ts);
			goto handler_finish;
		}

		// add check&save sender addr
		dap_list_t *l_list_temp = dap_list_first(l_session->cur_round.validators_start);
		while(l_list_temp) {
			dap_list_t *l_list_next = l_list_temp->next;
			if (((dap_chain_node_addr_t *)l_list_temp->data)->uint64 == l_validator->uint64) {
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: repeated sync message from addr:"NODE_ADDR_FP_STR"",
							l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
								l_session->attempt_current_number, NODE_ADDR_FP_ARGS(a_sender_node_addr));
				goto handler_finish;
			}
			l_list_temp = l_list_next;
		}

		//sync round_id
		if ( l_session->cur_round.id.uint64 < l_startsync->round_id.uint64 ) {
			l_session->cur_round.id.uint64 = l_startsync->round_id.uint64;
		}

		l_session->cur_round.validators_start = dap_list_append(l_session->cur_round.validators_start, l_validator);
		l_session->cur_round.validators_start_count = dap_list_length(l_session->cur_round.validators_start);
		// if ( l_session->ts_round_start_pub < l_startsync->ts )
		// 	l_session->ts_round_start_pub = l_startsync->ts;
		// l_session->ts_round_start = (dap_chain_time_t)time(NULL); // l_startsync->ts; // set max time of start consensus
		goto handler_finish;
	}

	// validator check
	uint64_t l_round_id =
				((dap_chain_cs_block_ton_message_getinfo_t *)
						(l_message->sign_n_message+l_message->hdr.sign_size))->round_id.uint64;
	dap_chain_node_addr_t *l_validator = NULL;
	l_validator = l_round_id == l_session->old_round.id.uint64 ? 
								  s_session_get_validator(l_session, a_sender_node_addr, l_session->old_round.validators_start)
								: s_session_get_validator(l_session, a_sender_node_addr, l_session->cur_round.validators_start);
	if (!l_validator) {
		if (PVT(l_session->ton)->debug) 
            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: validator addr:"NODE_ADDR_FP_STR" not on the list.",
					l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
						l_session->attempt_current_number, NODE_ADDR_FP_ARGS(a_sender_node_addr));
		goto handler_finish;
	}

	// round check
	if ( l_message->hdr.type != DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN ) {
		if ( l_session->state != DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC
				&& l_session->state != DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS ) {
			goto handler_finish;
		}
		if ( l_round_id != l_session->cur_round.id.uint64) {
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: round in message does not match to current round",
						l_session->chain->net_name, l_session->chain->name,
							l_session->cur_round.id.uint64, l_session->attempt_current_number);
			goto handler_finish;
		}
	} else {
		if ( l_round_id != l_session->cur_round.id.uint64
					&& l_round_id != l_session->old_round.id.uint64 ) {
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: round in message does not match to current round",
						l_session->chain->net_name, l_session->chain->name,
							l_session->cur_round.id.uint64, l_session->attempt_current_number);
			goto handler_finish;
		}
	}

	if ( l_session->attempt_current_number != 1 ) {
		switch (l_message->hdr.type) { // this types allow only in first attempt
			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT:
			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: message type:%x allowed only in first attempt",
						l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
							l_session->attempt_current_number, l_message->hdr.type);
				goto handler_finish;
			}
		}
	}

	dap_chain_cs_block_ton_message_item_t *l_messages_items = NULL;
	l_messages_items = l_round_id == l_session->old_round.id.uint64 ?
						l_session->old_round.messages_items : l_session->cur_round.messages_items;

	// check hash message dup
	dap_chain_cs_block_ton_message_item_t *l_message_item_temp = NULL;
	HASH_FIND(hh, l_messages_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_message_item_temp);
	if (l_message_item_temp) {
		if (PVT(l_session->ton)->debug)
            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: message hash is exists in chain (duplicate?)",
					l_session->chain->net_name, l_session->chain->name,
						l_session->cur_round.id.uint64, l_session->attempt_current_number);
		goto handler_finish;
	}

	// check validator index in queue for event Submit
	if ( l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT ) {
		dap_list_t *l_validators_list = dap_list_first(l_session->cur_round.validators_start);
		int l_validator_number = 0;
		int i = 0;
		while(l_validators_list) {
			if( ((dap_chain_node_addr_t *)l_validators_list->data)->uint64 == a_sender_node_addr->uint64) {
				l_validator_number = i;
				break;
			}
			i++;
			l_validators_list = l_validators_list->next;
		}
		if ( l_validator_number ) { // pass if I first validator
			int l_submit_count = 0;
			dap_chain_cs_block_ton_message_item_t *l_chain_message=NULL, *l_chain_message_tmp=NULL;
    		HASH_ITER(hh, l_messages_items, l_chain_message, l_chain_message_tmp) {
    			if ( l_chain_message->message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT ) {
    				l_submit_count++;
    			}
    		}
    		if ( l_validator_number < l_submit_count ) {
    			// Skip this SUBMIT. Validator must wait its queue.
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: Validator must wait its queue for sent SUBMIT",
							l_session->chain->net_name, l_session->chain->name,
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
    			goto handler_finish;
    		}
		}
	}

    uint32_t /* l_approve_count = 0, */ l_vote_count = 0, l_precommit_count = 0;
	// check messages chain
    dap_chain_cs_block_ton_message_item_t *l_chain_message=NULL, *l_chain_message_tmp=NULL;
    HASH_ITER(hh, l_messages_items, l_chain_message, l_chain_message_tmp) {
    	if (l_chain_message->message->hdr.sender_node_addr.uint64 == a_sender_node_addr->uint64) {
    		dap_chain_hash_fast_t *l_candidate_hash_cur = 
    				&((dap_chain_cs_block_ton_message_getinfo_t *)
    						(l_message->sign_n_message+l_message->hdr.sign_size))->candidate_hash;

    		dap_chain_hash_fast_t *l_candidate_hash = 
    			&((dap_chain_cs_block_ton_message_getinfo_t *)
    				(l_chain_message->message->sign_n_message+l_chain_message->message->hdr.sign_size))->candidate_hash;

    		bool l_candidate_hash_match = (memcmp(l_candidate_hash_cur, l_candidate_hash,
															sizeof(dap_chain_hash_fast_t)) == 0);

    		uint8_t l_chain_msg_type = l_chain_message->message->hdr.type;

    		// search & check messages from this validator 
    		switch (l_chain_msg_type) {
    			// check dup messages APPROVE, REJECT for one candidate
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
    				switch (l_message->hdr.type) {
    					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
    					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT:
	    					if (l_candidate_hash_match) {
								if (PVT(l_session->ton)->debug)
                                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: duplicate messages APPROVE or REJECT for one candidate",
											l_session->chain->net_name, l_session->chain->name, 
                                                l_session->cur_round.id.uint64, l_session->attempt_current_number);
								goto handler_finish;
							}
    				}
    			} break;
    			//check dup messages VOTE for one candidate in this attempt
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
    				dap_chain_cs_block_ton_message_vote_t *l_vote = 
    								(dap_chain_cs_block_ton_message_vote_t *)
    									(l_message->sign_n_message+l_message->hdr.sign_size);
    				dap_chain_cs_block_ton_message_vote_t *l_vote_item = 
    								(dap_chain_cs_block_ton_message_vote_t *)
    									(l_chain_message->message->sign_n_message+l_chain_message->message->hdr.sign_size);
    				if ( l_chain_msg_type == l_message->hdr.type
    						&& l_vote->attempt_number == l_vote_item->attempt_number ) {
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: duplicate messages VOTE for one candidate for one attempt",
									l_session->chain->net_name, l_session->chain->name,
                                        l_session->cur_round.id.uint64, l_session->attempt_current_number);
    					goto handler_finish;
    				}
    			} break;
    			// this messages should only appear once per round //attempt
    			// case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: 
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT:{
    				if ( l_chain_msg_type == l_message->hdr.type ){
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: duplicate messages VOTE or PRE_COMMIT for one candidate for one attempt",
									l_session->chain->net_name, l_session->chain->name,
                                        l_session->cur_round.id.uint64, l_session->attempt_current_number);
    					goto handler_finish;
    				}
    			}
    		}
    		// count messages in chain for this candidate
    		if (l_candidate_hash_match) {
	    		switch (l_chain_msg_type) {
	    			// case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE: {
	    			// 	l_approve_count++;
	    			// } break;
	    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
	    				l_vote_count++;
	    			} break;
	    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT: {
	    				l_precommit_count++;
	    			} break;
	    		}
	    	}
    	}
    }

	// check message chain is correct
	switch (l_message->hdr.type) {
		// case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
		// 	if (!l_approve_count) { // if this validator not sent Approve for this candidate
		// 		goto handler_finish;
		// 	}
		// } break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT: {
			if (!l_vote_count) { // if this validator not sent Vote for this candidate
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: this validator can't send a PRE_COMMIT because it didn't send a VOTE for this candidate",
							l_session->chain->net_name, l_session->chain->name,
                                l_session->cur_round.id.uint64, l_session->attempt_current_number);
    			goto handler_finish;
    		}
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
			if (!l_precommit_count) { // if this validator not sent PreCommit for this candidate
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Message rejected: this validator can't send a COMMIT_SIGN because it didn't send a PRE_COMMIT for this candidate",
							l_session->chain->net_name, l_session->chain->name,
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
    			goto handler_finish;
    		}
		} break;
	}

	bool l_finalize_consensus = false;
	switch (l_message->hdr.type) {
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT: {
			dap_chain_cs_block_ton_message_submit_t *l_submit =
							(dap_chain_cs_block_ton_message_submit_t *)
								(l_message->sign_n_message+l_message->hdr.sign_size);

			size_t l_candidate_size = l_submit->candidate_size;
			if (!l_candidate_size || s_hash_is_null(&l_submit->candidate_hash)) { // null candidate - save chain and exit
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive SUBMIT: candidate: NULL",
							l_session->chain->net_name, l_session->chain->name,
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
				goto handler_finish_save;
			}

			dap_chain_block_t *l_candidate = (dap_chain_block_t *)l_submit->candidate;
			dap_chain_hash_fast_t l_candidate_hash;
			dap_hash_fast(l_candidate, l_candidate_size, &l_candidate_hash);
			
			// check candidate hash
			if (memcmp(&l_submit->candidate_hash, &l_candidate_hash,
											sizeof(dap_chain_hash_fast_t)) != 0) {
				goto handler_finish;				
			}

			char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_candidate_hash);
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive SUBMIT: candidate:%s, size:%zu",
						l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
							l_session->attempt_current_number, l_candidate_hash_str, l_candidate_size);

			// check block exist in store
			size_t l_store_temp_size = 0;
			dap_chain_cs_block_ton_store_t *l_store_temp = 
							(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
										l_candidate_hash_str, &l_store_temp_size, l_session->gdb_group_store);
			if (l_store_temp) {
				log_it(L_WARNING, "TON: Duplicate candidate:%s", l_candidate_hash_str);
                DAP_DELETE(l_store_temp);
                DAP_DELETE(l_candidate_hash_str);
                goto handler_finish;
			}

			pthread_rwlock_rdlock(&l_session->rwlock);
		    // stor for new candidate
		    size_t l_store_size = sizeof(dap_chain_cs_block_ton_store_hdr_t)+a_data_size;
		    dap_chain_cs_block_ton_store_t *l_store = 
		    						DAP_NEW_Z_SIZE(dap_chain_cs_block_ton_store_t, l_store_size);
		    l_store->hdr.sign_collected = false;
		    l_store->hdr.approve_collected = false;
		    l_store->hdr.vote_collected = false;
		    l_store->hdr.precommit_collected = false;
		    l_store->hdr.candidate_size = l_candidate_size;
		    l_store->hdr.ts_candidate_submit = l_time;
		    l_store->hdr.round_id.uint64 = l_session->cur_round.id.uint64;
		    memcpy( &l_store->hdr.candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
			memcpy( &l_store->candidate_n_signs, l_candidate, l_candidate_size);

			// save new block candidate
			if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
													l_store_size, l_session->gdb_group_store) ) {
				l_session->cur_round.candidates_count++;
				dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_session->chain);
				if ( !s_session_atom_validation(l_blocks, l_candidate, l_candidate_size) ) {
					// validation - OK, gen event Approve
				    if (PVT(l_session->ton)->blocks_sign_key) {
                        // size_t l_candidate_size = l_store->hdr.candidate_size;
					    dap_sign_t *l_hash_sign = dap_sign_create(PVT(l_session->ton)->blocks_sign_key,
					    								&l_candidate_hash, sizeof(dap_chain_hash_fast_t), 0);

					    size_t l_hash_sign_size = dap_sign_get_size(l_hash_sign);
						size_t l_approve_size = sizeof(dap_chain_cs_block_ton_message_approve_t)+l_hash_sign_size;

						dap_chain_cs_block_ton_message_approve_t *l_approve =
												DAP_NEW_SIZE(dap_chain_cs_block_ton_message_approve_t, l_approve_size);
						l_approve->round_id.uint64 = l_session->cur_round.id.uint64;
						memcpy(&l_approve->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
						memcpy(l_approve->candidate_hash_sign, l_hash_sign, l_hash_sign_size);

						s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE,
												(uint8_t*)l_approve, l_approve_size, l_session->cur_round.validators_start);
						DAP_DELETE(l_approve);
						
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Sent APPROVE candidate:%s",
									l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
											l_session->attempt_current_number, l_candidate_hash_str);
					}
					else
						log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-ton] section");	
				}
				else {
					// validation - fail, gen event Reject
					dap_chain_cs_block_ton_message_reject_t *l_reject =
															DAP_NEW_Z(dap_chain_cs_block_ton_message_reject_t);
					l_reject->round_id.uint64 = l_session->cur_round.id.uint64;
					memcpy(&l_reject->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
					s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT, (uint8_t*)l_reject,
								sizeof(dap_chain_cs_block_ton_message_reject_t), l_session->cur_round.validators_start);
					DAP_DELETE(l_reject);
					if (PVT(l_session->ton)->debug)
                        log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Sent REJECT candidate:%s",
								l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
										l_session->attempt_current_number, l_candidate_hash_str);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
            DAP_DELETE(l_store);
            DAP_DELETE(l_store_temp);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
			dap_chain_cs_block_ton_message_reject_t *l_reject =
							(dap_chain_cs_block_ton_message_reject_t *)
								(l_message->sign_n_message+l_message->hdr.sign_size);
			dap_chain_hash_fast_t *l_candidate_hash = &l_reject->candidate_hash;

			if ( s_hash_is_null(l_candidate_hash) ) {
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive REJECT: NULL",
							l_session->chain->net_name, l_session->chain->name,
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
				goto handler_finish_save;
			}
			char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);

			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive REJECT: candidate:%s",
						l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
							l_session->attempt_current_number, l_candidate_hash_str);

			pthread_rwlock_rdlock(&l_session->rwlock);
			
			uint16_t l_reject_count = s_session_message_count(
						l_session, DAP_TON$ROUND_CUR, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT,
									l_candidate_hash, NULL);
			l_reject_count++;
			if ( ((float)l_reject_count/l_session->cur_round.validators_count) >= ((float)2/3) ) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				dap_chain_hash_fast_t l_my_candidate_hash;
				dap_hash_fast(l_session->my_candidate, l_session->my_candidate_size, &l_my_candidate_hash);
				if (memcmp(&l_my_candidate_hash, l_candidate_hash,
									sizeof(dap_chain_hash_fast_t)) == 0) {
					s_session_my_candidate_delete(l_session);
				}
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Candidate:%s collected rejected more than 2/3 of the validators, so to removed this candidate",
                            l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
                            	l_session->attempt_current_number, l_candidate_hash_str);
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE: {
			dap_chain_cs_block_ton_message_approve_t *l_approve =
								(dap_chain_cs_block_ton_message_approve_t *)
										(l_message->sign_n_message+l_message->hdr.sign_size);
			dap_chain_hash_fast_t *l_candidate_hash = &l_approve->candidate_hash;
			
			if ( s_hash_is_null(l_candidate_hash) ) {
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive APPROVE: candidate: NULL",
							l_session->chain->net_name, l_session->chain->name,
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
				goto handler_finish_save;
			}
			char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);

			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive APPROVE: candidate:%s",
						l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
							l_session->attempt_current_number, l_candidate_hash_str);

			int l_sign_verified=0;
			// check candidate hash sign
			if ( (l_sign_verified=dap_sign_verify( (dap_sign_t*)l_approve->candidate_hash_sign, 
													l_candidate_hash, sizeof(dap_chain_hash_fast_t))) == 1 ) {
				l_message->hdr.is_verified=true;
				pthread_rwlock_rdlock(&l_session->rwlock);

				if ( l_session->attempt_current_number == 1 ) { // if this first attempt then send Vote event
					uint16_t l_approve_count = s_session_message_count(
							l_session, DAP_TON$ROUND_CUR, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE,
										l_candidate_hash, NULL);
					l_approve_count++;
					if ( ((float)l_approve_count/l_session->cur_round.validators_count) >= ((float)2/3) ) {
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" attempt:%hu Candidate:%s collected approve more than 2/3 of the validators",
									l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
										l_session->attempt_current_number, l_candidate_hash_str);

						size_t l_store_size = 0;
						dap_chain_cs_block_ton_store_t *l_store = 
												(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
						if (l_store && !l_store->hdr.approve_collected) {
							if (PVT(l_session->ton)->debug)
								log_it(L_MSG, "TON: APPROVE: candidate found in store:%s & !approve_collected", l_candidate_hash_str);
							l_store->hdr.approve_collected = true;
							if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
                                                                l_store_size, l_session->gdb_group_store) ) {
								if (PVT(l_session->ton)->debug)
									log_it(L_MSG, "TON: APPROVE: candidate update:%s approve_collected=true", l_candidate_hash_str);
                            } else
								if (PVT(l_session->ton)->debug)
									log_it(L_MSG, "TON: APPROVE: can`t update candidate:%s", l_candidate_hash_str);

							// event Vote
							dap_chain_cs_block_ton_message_vote_t *l_vote =
																DAP_NEW_Z(dap_chain_cs_block_ton_message_vote_t);
							l_vote->round_id.uint64 = l_session->cur_round.id.uint64;
							memcpy(&l_vote->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
							l_vote->attempt_number = l_session->attempt_current_number;
							s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE, (uint8_t*)l_vote,
								sizeof(dap_chain_cs_block_ton_message_vote_t), l_session->cur_round.validators_start);
							DAP_DELETE(l_vote);
							if (PVT(l_session->ton)->debug)
                                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu This is first attempt, so to sent a VOTE for candidate:%s",
										l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
											l_session->attempt_current_number, l_candidate_hash_str );

							DAP_DELETE(l_store);
						}
					}
				}
				pthread_rwlock_unlock(&l_session->rwlock);
			} else {
				log_it(L_WARNING, "Candidate hash sign is incorrect: code %d", l_sign_verified);
			}
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR: {
			dap_chain_cs_block_ton_message_votefor_t *l_votefor =
								(dap_chain_cs_block_ton_message_votefor_t *)
										(l_message->sign_n_message+l_message->hdr.sign_size);
			dap_chain_hash_fast_t *l_candidate_hash = &l_votefor->candidate_hash;
			
			uint16_t l_attempt_current = l_session->attempt_current_number;
			if ( l_votefor->attempt_number != l_attempt_current) {
				goto handler_finish; // wrong attempt number in message
			}

			if (PVT(l_session->ton)->debug) {
				char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive VOTE_FOR: candidate:%s",
                        l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
                            l_session->attempt_current_number, l_candidate_hash_str);
				DAP_DELETE(l_candidate_hash_str);
			}

			if ( a_sender_node_addr->uint64 != l_session->attempt_coordinator->uint64 ) {
				goto handler_finish; // wrong coordinator addr
			}

			uint16_t l_votefor_count = s_session_message_count(
						l_session, DAP_TON$ROUND_CUR, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR,
									NULL, &l_attempt_current);
			if ( l_votefor_count != 0 ) {
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Ignored because it's not the first VOTE_FOR in this attempt",
							l_session->chain->net_name, l_session->chain->name, 
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
				goto handler_finish;
			}

			// search candidate with 2/3 vote
			pthread_rwlock_rdlock(&l_session->rwlock);

			size_t l_objs_size = 0;
			dap_chain_cs_block_ton_store_t *l_found_best = NULL;
			dap_chain_cs_block_ton_store_t *l_found_vote = NULL;
			dap_chain_cs_block_ton_store_t *l_found_approve_vf = NULL;
			// dap_chain_cs_block_ton_store_t *l_found_approve = NULL;
            dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_objs_size);
            if (l_objs_size) {
                for (size_t i = 0; i < l_objs_size; i++) {
                    if (!l_objs[i].value_len)
                        continue;
					dap_chain_cs_block_ton_store_t *l_store = 
							(dap_chain_cs_block_ton_store_t *)l_objs[i].value;
					if ( l_store->hdr.round_id.uint64 != l_session->cur_round.id.uint64 )
						continue;
					if (l_store->hdr.vote_collected) {
						// best choice :-) 2/3 vote (i.e. PreCommit) and VoteFor candidate
						if (memcmp(l_candidate_hash, &l_store->hdr.candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
							l_found_best = (dap_chain_cs_block_ton_store_t *)l_objs[i].value;
							break;
						}

						// other PreCommit candidate (ignore VoteFor)
						if ( !l_found_vote
								|| l_found_vote->hdr.ts_candidate_submit<l_store->hdr.ts_candidate_submit ) {
							l_found_vote = (dap_chain_cs_block_ton_store_t *)l_objs[i].value;
						}
                   	}
                   	if ( l_store->hdr.approve_collected ) {
                   		// 2/3 Approve & VoteFor
						if (memcmp(l_candidate_hash, &l_store->hdr.candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
							l_found_approve_vf = (dap_chain_cs_block_ton_store_t *)l_objs[i].value;
							break;
						}
						// 2/3 Approve (ignore VoteFor)
                    	//	if ( !l_found_approve
						// 		|| l_found_approve->hdr.ts_candidate_submit<l_store->hdr.ts_candidate_submit ) {
						// 	l_found_approve = (dap_chain_cs_block_ton_store_t *)l_objs[i].value;
						// }
                   	}
                }

                dap_chain_cs_block_ton_store_t *l_found_candidate = NULL;
                if (l_found_best) {
                	l_found_candidate = l_found_best;
                }
                else if (l_found_vote) {
                	l_found_candidate = l_found_vote;
                }
                else if (l_found_approve_vf) {
                	l_found_candidate = l_found_approve_vf;
                }
                // else if (l_found_approve) {
                // 	l_found_candidate = l_found_approve;
                // }

                if (l_found_candidate) {
    				// candidate found, gen event Vote
					dap_chain_cs_block_ton_message_vote_t *l_vote =
														DAP_NEW_Z(dap_chain_cs_block_ton_message_vote_t);
					memcpy(&l_vote->candidate_hash, &l_found_candidate->hdr.candidate_hash, sizeof(dap_chain_hash_fast_t));
					l_vote->round_id.uint64 = l_session->cur_round.id.uint64;
					l_vote->attempt_number = l_session->attempt_current_number;

					s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE, (uint8_t*)l_vote,
									sizeof(dap_chain_cs_block_ton_message_vote_t), l_session->cur_round.validators_start);
					if (PVT(l_session->ton)->debug) {
						char *l_hash_str = dap_chain_hash_fast_to_str_new(&l_vote->candidate_hash);
                        log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Sent VOTE for candidate:%s",
								l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64, 
									l_session->attempt_current_number, l_hash_str);
						DAP_DELETE(l_hash_str);
					}
					DAP_DELETE(l_vote);
                }
                dap_chain_global_db_objs_delete(l_objs, l_objs_size);
            }
            pthread_rwlock_unlock(&l_session->rwlock);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
			dap_chain_cs_block_ton_message_vote_t *l_vote =
								(dap_chain_cs_block_ton_message_vote_t *)
										(l_message->sign_n_message+l_message->hdr.sign_size);
			dap_chain_hash_fast_t *l_candidate_hash = &l_vote->candidate_hash;

			if ( l_vote->attempt_number != l_session->attempt_current_number) {
				goto handler_finish;
			}
			
			if ( s_hash_is_null(l_candidate_hash) ) {
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive VOTE: candidate: NULL",
							l_session->chain->net_name, l_session->chain->name, 
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
				goto handler_finish_save;
			}

			char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive VOTE: candidate:%s",
						l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
							l_session->attempt_current_number, l_candidate_hash_str);
	
			pthread_rwlock_rdlock(&l_session->rwlock);
			uint16_t l_attempt_number = l_session->attempt_current_number;
			uint16_t l_vote_count = s_session_message_count(
						l_session, DAP_TON$ROUND_CUR, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE,
									l_candidate_hash, &l_attempt_number);
			l_vote_count++;
			if ( ((float)l_vote_count/l_session->cur_round.validators_count) >= ((float)2/3) ) {
				size_t l_store_size = 0;
				dap_chain_cs_block_ton_store_t *l_store = 
									(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
												l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
				if (l_store) {
					l_store->hdr.vote_collected = true;
					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
														l_store_size, l_session->gdb_group_store) ) {
		                // Send PreCommit
						dap_chain_cs_block_ton_message_precommit_t *l_precommit =
													DAP_NEW_Z(dap_chain_cs_block_ton_message_precommit_t);
						l_precommit->round_id.uint64 = l_session->cur_round.id.uint64;
						memcpy(&l_precommit->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
						l_precommit->attempt_number = l_session->attempt_current_number;
						s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT, (uint8_t*)l_precommit,
										sizeof(dap_chain_cs_block_ton_message_precommit_t), l_session->cur_round.validators_start);
						DAP_DELETE(l_precommit);
						if (PVT(l_session->ton)->debug)
                            log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Candidate:%s collected VOTE more than 2/3 of the validators, so to sent a PRE_COMMIT",
									l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64, 
										l_session->attempt_current_number, l_candidate_hash_str);
					}
					DAP_DELETE(l_store);
				}
			}
			DAP_DELETE(l_candidate_hash_str);
			pthread_rwlock_unlock(&l_session->rwlock);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT: {
			dap_chain_cs_block_ton_message_precommit_t *l_precommit =
							(dap_chain_cs_block_ton_message_precommit_t *)
									(l_message->sign_n_message+l_message->hdr.sign_size);
			dap_chain_hash_fast_t *l_candidate_hash = &l_precommit->candidate_hash;

			if ( l_precommit->attempt_number != l_session->attempt_current_number) {
				goto handler_finish;
			}
			if ( s_hash_is_null(l_candidate_hash) ) {
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive PRE_COMMIT: candidate: NULL",
							l_session->chain->net_name, l_session->chain->name,
								l_session->cur_round.id.uint64, l_session->attempt_current_number);
				goto handler_finish_save;
			}

			char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive PRE_COMMIT: candidate:%s",
						l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
							l_session->attempt_current_number, l_candidate_hash_str);

			pthread_rwlock_rdlock(&l_session->rwlock);
			uint16_t l_attempt_number = l_session->attempt_current_number;
			uint16_t l_precommit_count = s_session_message_count(
						l_session, DAP_TON$ROUND_CUR, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT,
									l_candidate_hash, &l_attempt_number);
			l_precommit_count++;
			if ( ((float)l_precommit_count/l_session->cur_round.validators_count) >= ((float)2/3) ) {
				size_t l_store_size = 0;
				dap_chain_cs_block_ton_store_t *l_store = 
									(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
												l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
				// event CommitSign
				if (l_store) {
					if (PVT(l_session->ton)->blocks_sign_key) {
						l_store->hdr.precommit_collected = true;

						if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
															l_store_size, l_session->gdb_group_store) ) {
							size_t l_candidate_size = l_store->hdr.candidate_size;
							dap_chain_block_t *l_candidate = 
									(dap_chain_block_t *)DAP_DUP_SIZE(&l_store->candidate_n_signs, l_candidate_size);
							size_t l_offset = dap_chain_block_get_sign_offset(l_candidate, l_candidate_size);
						    dap_sign_t *l_candidate_sign = dap_sign_create(PVT(l_session->ton)->blocks_sign_key,
						    								l_candidate, l_offset + sizeof(l_candidate->hdr), 0);
						    size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
							
							size_t l_commitsign_size = sizeof(dap_chain_cs_block_ton_message_commitsign_t)+l_candidate_sign_size;
							dap_chain_cs_block_ton_message_commitsign_t *l_commitsign =
													DAP_NEW_SIZE(dap_chain_cs_block_ton_message_commitsign_t, l_commitsign_size);
							l_commitsign->round_id.uint64 = l_session->cur_round.id.uint64;
							memcpy(&l_commitsign->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
							memcpy(l_commitsign->candidate_sign, l_candidate_sign, l_candidate_sign_size);
							s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN, (uint8_t*)l_commitsign,
												l_commitsign_size, l_session->cur_round.validators_start);
							DAP_DELETE(l_commitsign);
							DAP_DELETE(l_candidate);
							DAP_DELETE(l_candidate_sign);
							
							l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS;
							l_session->ts_round_state_commit = dap_time_now();
							
							if (PVT(l_session->ton)->debug)
                                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U" attempt:%hu Candidate:%s collected PRE_COMMIT more than 2/3 of the validators, so to sent a COMMIT_SIGN",
										l_session->chain->net_name, l_session->chain->name, l_session->cur_round.id.uint64,
											l_session->attempt_current_number, l_candidate_hash_str);
						}
					}
					else {
						log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-ton] section");	
					}
					DAP_DELETE(l_store);
				}
			}
			DAP_DELETE(l_candidate_hash_str);
        } break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
			dap_chain_cs_block_ton_message_commitsign_t *l_commitsign =
								(dap_chain_cs_block_ton_message_commitsign_t *)
									(l_message->sign_n_message+l_message->hdr.sign_size);
			dap_chain_hash_fast_t *l_candidate_hash = &l_commitsign->candidate_hash;

			dap_chain_cs_block_ton_round_t *l_round =
						l_commitsign->round_id.uint64 == l_session->old_round.id.uint64 ?
								&l_session->old_round : &l_session->cur_round;

			if ( s_hash_is_null(l_candidate_hash) ) {
				if (PVT(l_session->ton)->debug)
                    log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive COMMIT_SIGN: candidate: NULL",
							l_session->chain->net_name, l_session->chain->name,
								l_round->id.uint64, l_session->attempt_current_number);
				goto handler_finish_save;
			}

			char *l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
			if (PVT(l_session->ton)->debug)
                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Receive COMMIT_SIGN: candidate:%s",
						l_session->chain->net_name, l_session->chain->name, l_round->id.uint64,
							l_session->attempt_current_number, l_candidate_hash_str);

			pthread_rwlock_unlock(&l_session->rwlock);

			size_t l_store_size = 0;
			dap_chain_cs_block_ton_store_t *l_store = 
								(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
											l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			if (l_store) {
				size_t l_candidate_size = l_store->hdr.candidate_size;
				dap_chain_block_t *l_candidate = 
						(dap_chain_block_t *)DAP_DUP_SIZE(&l_store->candidate_n_signs, l_candidate_size);
				size_t l_offset = dap_chain_block_get_sign_offset(l_candidate, l_candidate_size);

				int l_sign_verified=0;
				// check candidate hash sign
				if ( (l_sign_verified=dap_sign_verify((dap_sign_t*)l_commitsign->candidate_sign,
												l_candidate, l_offset+sizeof(l_candidate->hdr))) == 1 ) {
					l_message->hdr.is_verified = true;
					l_store->hdr.sign_collected = true;
					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
									l_store_size, l_session->gdb_group_store) ) {
						uint16_t l_commitsign_count = s_session_message_count(
							l_session, DAP_TON$ROUND_CUR, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN,
										l_candidate_hash, NULL);
						l_commitsign_count++;
						if ( ((float)l_commitsign_count/l_round->validators_count) >= ((float)2/3) ) {
							// s_session_round_finish(l_session);
							if (l_commitsign->round_id.uint64 == l_session->cur_round.id.uint64) {
								l_finalize_consensus = true;
							}
							if (PVT(l_session->ton)->debug)
                                log_it(L_MSG, "TON: net:%s, chain:%s, round:%"DAP_UINT64_FORMAT_U", attempt:%hu Candidate:%s collected COMMIT_SIGN more than 2/3 of the validators, so to finished this round",
										l_session->chain->net_name, l_session->chain->name, l_round->id.uint64,
											l_session->attempt_current_number, l_candidate_hash_str);
						}
					}
				}
				else {
					log_it(L_WARNING, "Candidate:%s sign is incorrect: code %d", l_candidate_hash_str, l_sign_verified);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store);
			DAP_DELETE(l_candidate_hash_str);

		} break;
		default:
			break;
	}

handler_finish_save:
{
	// save to messages chain
	dap_chain_hash_fast_t l_message_hash;
	s_message_chain_add(l_session, a_sender_node_addr, l_message, a_data_size, &l_message_hash);
	l_message_delete = false;
	if (l_finalize_consensus) {
		s_session_round_finish(l_session);
	}
}
handler_finish:
    if (l_message_delete) {
    	DAP_DELETE(l_message);
	}
	return;
}

static uint8_t *s_message_data_sign(dap_chain_cs_block_ton_items_t *a_session,
						dap_chain_cs_block_ton_message_t *a_message, size_t *a_sign_size) {
	size_t l_size[5] = {sizeof(a_message->hdr.id), sizeof(a_message->hdr.ts_created),
						sizeof(a_message->hdr.type), sizeof(a_message->hdr.chain_id),
						sizeof(a_message->hdr.sender_node_addr)};
	size_t l_data_size = 0;
	for(int i=0;i<5;i++) l_data_size+=l_size[i];
    uint8_t *l_data = DAP_NEW_SIZE(uint8_t, l_data_size);	
	size_t l_offset = 0;
	memcpy(l_data+l_offset, &a_message->hdr.id, l_size[0]);
	l_offset+=l_size[0];
	memcpy(l_data+l_offset, &a_message->hdr.ts_created, l_size[1]);
	l_offset+=l_size[1];
	memcpy(l_data+l_offset, &a_message->hdr.type, l_size[2]);
	l_offset+=l_size[2];
	memcpy(l_data+l_offset, &a_message->hdr.chain_id, l_size[3]);
	l_offset+=l_size[3];
	memcpy(l_data+l_offset, &a_message->hdr.sender_node_addr, l_size[4]);
	*a_sign_size = l_data_size;
	return l_data;
}

static void s_message_send(dap_chain_cs_block_ton_items_t *a_session, uint8_t a_message_type,
									uint8_t *a_data, size_t a_data_size, dap_list_t *a_validators) {
	dap_chain_net_t *l_net = dap_chain_net_by_id(a_session->chain->net_id);
	size_t l_message_size = sizeof(dap_chain_cs_block_ton_message_hdr_t)+a_data_size;
	dap_chain_cs_block_ton_message_t *l_message =
						DAP_NEW_SIZE(dap_chain_cs_block_ton_message_t, l_message_size);
	l_message->hdr.id.uint64 = (uint64_t)a_session->cur_round.messages_count;
	l_message->hdr.chain_id.uint64 = a_session->chain->id.uint64;
	l_message->hdr.ts_created = dap_time_now();
	l_message->hdr.type = a_message_type;
	memcpy(&l_message->hdr.sender_node_addr,
				dap_chain_net_get_cur_addr(l_net), sizeof(dap_chain_node_addr_t));

	size_t l_sign_size = 0;
	if ( !PVT(a_session->ton)->validators_list_by_stake ) { 
		size_t l_data_size = sizeof(l_message->hdr.sender_node_addr);
		uint8_t *l_data = s_message_data_sign(a_session, l_message, &l_data_size);
	    dap_sign_t *l_sign = dap_sign_create(PVT(a_session->ton)->blocks_sign_key, l_data, l_data_size, 0);
	    l_sign_size = dap_sign_get_size(l_sign);
	    l_message_size += l_sign_size;
	    l_message = DAP_REALLOC(l_message, l_message_size);
	    memcpy(l_message->sign_n_message, l_sign, l_sign_size);
	    DAP_DELETE(l_sign);
	    DAP_DELETE(l_data);
	}
	l_message->hdr.sign_size = l_sign_size;
	memcpy(l_message->sign_n_message+l_sign_size, a_data, a_data_size);
	l_message->hdr.message_size = a_data_size;

	dap_chain_hash_fast_t l_message_hash;
	dap_hash_fast(l_message, l_message_size, &l_message_hash);

	dap_stream_ch_chain_voting_message_write(l_net, a_validators, //a_session->cur_round.validators_start,
												&l_message_hash, l_message, l_message_size);
    DAP_DELETE(l_message);
}


static void s_message_chain_add(dap_chain_cs_block_ton_items_t *a_session, dap_chain_node_addr_t *a_sender_node_addr, 
									dap_chain_cs_block_ton_message_t *a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash) {
	
	pthread_rwlock_rdlock(&a_session->rwlock);
	dap_chain_cs_block_ton_message_t *l_message = a_message;

	dap_chain_cs_block_ton_message_getinfo_t *l_getinfo =
					(dap_chain_cs_block_ton_message_getinfo_t *)
							(l_message->sign_n_message+l_message->hdr.sign_size);
	dap_chain_cs_block_ton_round_t *l_round =
				l_getinfo->round_id.uint64 == a_session->old_round.id.uint64 ?
						&a_session->old_round : &a_session->cur_round;

	l_message->hdr.is_genesis = !l_round->last_message_hash ? true : false;
	if (!l_message->hdr.is_genesis) {
		memcpy(&l_message->hdr.prev_message_hash, l_round->last_message_hash, sizeof(dap_hash_fast_t));
	}

	dap_chain_hash_fast_t l_message_hash;
	dap_hash_fast(a_message, a_message_size, &l_message_hash);

	dap_chain_cs_block_ton_message_item_t *l_message_items = DAP_NEW_Z(dap_chain_cs_block_ton_message_item_t);
	l_message_items->message = l_message;

	memcpy( &l_message_items->message_hash, &l_message_hash, sizeof(dap_chain_hash_fast_t));
	l_round->last_message_hash = 
			(dap_chain_hash_fast_t*)DAP_DUP_SIZE(&l_message_hash, sizeof(dap_chain_hash_fast_t));
	HASH_ADD(hh, l_round->messages_items, message_hash, sizeof(l_message_items->message_hash), l_message_items);

	l_round->messages_count++;
	memcpy( a_message_hash, &l_message_hash, sizeof(dap_chain_hash_fast_t));

	pthread_rwlock_unlock(&a_session->rwlock);
}

static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size)
{
    assert(a_blocks);
    dap_chain_cs_block_ton_t *l_ton = DAP_CHAIN_CS_BLOCK_TON(a_blocks);
    dap_chain_cs_block_ton_pvt_t *l_ton_pvt = PVT(l_ton);
    if (!l_ton_pvt->blocks_sign_key) {
        log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-ton] section");
        return 0;
    }
    if (!a_block_ptr || !(*a_block_ptr) || !a_block_size) {
        log_it(L_WARNING, "Block size or block pointer is NULL");
        return 0;
    }
    return dap_chain_block_sign_add(a_block_ptr, a_block_size, l_ton_pvt->blocks_sign_key);
}

static int s_callback_block_verify(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size)
{
    dap_chain_cs_block_ton_t *l_ton = DAP_CHAIN_CS_BLOCK_TON(a_blocks);
    dap_chain_cs_block_ton_pvt_t *l_ton_pvt = PVT(l_ton);
    if (a_blocks->chain->ledger == NULL) {
        log_it(L_CRITICAL,"Ledger is NULL can't check TON on this chain %s", a_blocks->chain->name);
        return -3;
    }
    if (sizeof(a_block->hdr) >= a_block_size) {
        log_it(L_WARNING,"Incorrect size with block %p on chain %s", a_block, a_blocks->chain->name);
        return  -7;
    }

    if ( l_ton_pvt->flag_sign_verify && !l_ton_pvt->validators_list_by_stake ) { // PoA mode		
		size_t l_offset = dap_chain_block_get_sign_offset(a_block, a_block_size);
		size_t l_signs_count = 0;
		dap_sign_t **l_signs = dap_sign_get_unique_signs(a_block->meta_n_datum_n_sign+l_offset,
												a_block_size-sizeof(a_block->hdr)-l_offset, &l_signs_count);
		if (!l_signs_count){
	        log_it(L_ERROR, "No any signatures at all for block");
	        DAP_DELETE(l_signs);
	        return -2;
	    }

	    if ( ((float)l_signs_count/l_ton_pvt->poa_validators_count ) < ((float)2/3) ) {
            log_it(L_ERROR, "Corrupted block: not enough signs: %zu of %hu", l_signs_count, l_ton_pvt->poa_validators_count);
	        DAP_DELETE(l_signs);
	    	return -1;
	    }

	    // Parse the rest signs
	    int l_ret = 0;
	    uint16_t l_signs_verified_count = 0;
	    size_t l_block_excl_sign_size = dap_chain_block_get_sign_offset(a_block, a_block_size)+sizeof(a_block->hdr);
	    for (size_t i=0; i<l_signs_count; i++) {
	    	dap_sign_t *l_sign = (dap_sign_t *)l_signs[i];
	        if (!dap_sign_verify_size(l_sign, a_block_size)) {
	            log_it(L_ERROR, "Corrupted block: sign size is bigger than block size");
	            l_ret = -3;
	            break;
	        }

	        // Compare signature with auth_certs
	        for (uint16_t j = 0; j < l_ton_pvt->auth_certs_count; j++) {
	            if (dap_cert_compare_with_sign( l_ton_pvt->auth_certs[j], l_sign) == 0
	            		&& dap_sign_verify(l_sign, a_block, l_block_excl_sign_size) == 1 ){
	                l_signs_verified_count++;
	                break;
	            }
	        }
	    }
		DAP_DELETE(l_signs);
	    if ( l_ret != 0 ) {
	    	return l_ret;
	    }
	    if ( ((float)l_signs_verified_count/l_ton_pvt->poa_validators_count ) < ((float)2/3) ) {
	        log_it(L_ERROR, "Corrupted block: not enough signs: %u of %u", l_signs_verified_count, l_ton_pvt->poa_validators_count);
	    	return -1;
	    }
	}
    return 0;
}

