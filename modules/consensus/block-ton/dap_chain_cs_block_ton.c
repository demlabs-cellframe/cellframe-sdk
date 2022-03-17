
#include "dap_timerfd.h"
#include "utlist.h"
#include "dap_chain_net.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_block_ton.h"
#include "dap_stream_ch_chain_voting.h"
#include "dap_chain_net_srv_stake.h"
#include "dap_chain_ledger.h"

#define LOG_TAG "dap_chain_cs_blocks_ton"

static void s_session_packet_in(void * a_arg, dap_chain_node_addr_t * a_sender_node_addr, 
								dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size);
static void s_session_candidate_to_chain(
			dap_chain_cs_block_ton_items_t *a_session, dap_chain_hash_fast_t *a_candidate_hash,
							dap_chain_cs_block_ton_store_t * a_candidate, size_t a_candidate_size);
static bool s_session_candidate_submit(dap_chain_cs_block_ton_items_t *a_session);
static bool s_session_timer();
static int s_session_datums_validation(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);

static void s_message_send(dap_chain_cs_block_ton_items_t * a_session,
							uint8_t a_message_type, uint8_t *a_data, size_t a_data_size);
static void s_message_chain_add(dap_chain_cs_block_ton_items_t * a_session, dap_chain_node_addr_t * a_sender_node_addr, 
									dap_chain_cs_block_ton_message_t * a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash);
static void s_session_round_start(dap_chain_cs_block_ton_items_t *a_session);
static void s_session_block_new_delete(dap_chain_cs_block_ton_items_t *a_sessio);
static bool s_session_round_finish(dap_chain_cs_block_ton_items_t *a_session);

static dap_chain_node_addr_t * s_session_get_validator_by_addr(
					dap_chain_cs_block_ton_items_t * a_session, dap_chain_node_addr_t * a_addr);
static int s_callback_new(dap_chain_t *a_chain, dap_config_t *a_chain_cfg);
static void s_callback_delete(dap_chain_cs_blocks_t *a_blocks);
static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg);
static size_t s_callback_block_sign(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t **a_block_ptr, size_t a_block_size);
static int s_callback_block_verify(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);

// static char * s_gdb_group_session_store;
// dap_chain_hash_fast_t * s_prev_message_hash = NULL;
static dap_chain_cs_block_ton_items_t * s_session_items; // double-linked list of chains
static dap_timerfd_t * s_session_cs_timer = NULL; 

typedef struct dap_chain_cs_block_ton_pvt
{
    dap_enc_key_t *blocks_sign_key;
    char **tokens_hold;
    uint64_t *tokens_hold_value;
    size_t tokens_hold_size;
    uint16_t confirmations_minimum;
    dap_chain_callback_new_cfg_t prev_callback_created;
} dap_chain_cs_block_ton_pvt_t;

#define PVT(a) ((dap_chain_cs_block_ton_pvt_t *)a->_pvt)

int dap_chain_cs_block_ton_init() {
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
    l_ton_pvt->confirmations_minimum = dap_config_get_item_uint16_default(a_chain_cfg, "block-ton", "verifications_minimum", 1);
    l_ton_pvt->tokens_hold_size = l_tokens_hold_size;
    l_ton_pvt->tokens_hold = DAP_NEW_Z_SIZE(char *, sizeof(char *) * l_tokens_hold_size);
    l_ton_pvt->tokens_hold_value = DAP_NEW_Z_SIZE(uint64_t, l_tokens_hold_value_size * sizeof(uint64_t));

    for (size_t i = 0; i < l_tokens_hold_value_size; i++) {
        l_ton_pvt->tokens_hold[i] = dap_strdup(l_tokens_hold[i]);
        if ((l_ton_pvt->tokens_hold_value[i] =
               strtoull(l_tokens_hold_value_str[i],NULL,10)) == 0) {
             log_it(L_CRITICAL, "Token %s has inproper hold value %s",
                                l_ton_pvt->tokens_hold[i], l_tokens_hold_value_str[i]);
             goto lb_err;
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


// int dap_chain_cs_block_ton_init(dap_chain_t *a_chain, dap_enc_key_t *a_blocks_sign_key)
static int s_callback_created(dap_chain_t *a_chain, dap_config_t *a_chain_net_cfg) {

    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(a_chain);
    dap_chain_cs_block_ton_t *l_ton = DAP_CHAIN_CS_BLOCK_TON(l_blocks);

    const char * l_sign_cert_str = NULL;
    if ((l_sign_cert_str = dap_config_get_item_str(a_chain_net_cfg,"block-ton","blocks-sign-cert")) != NULL) {
        dap_cert_t *l_sign_cert = dap_cert_find_by_name(l_sign_cert_str);
        if (l_sign_cert == NULL) {
            log_it(L_ERROR, "Can't load sign certificate, name \"%s\" is wrong", l_sign_cert_str);
        } else if (l_sign_cert->enc_key->priv_key_data) {
            PVT(l_ton)->blocks_sign_key = l_sign_cert->enc_key;
            log_it(L_NOTICE, "Loaded \"%s\" certificate to sign TON blocks", l_sign_cert_str);
        } else {
            log_it(L_ERROR, "Certificate \"%s\" has no private key", l_sign_cert_str);
        }
    } else {
        log_it(L_ERROR, "No sign certificate provided, can't sign any blocks");
    }

	dap_chain_cs_block_ton_items_t * l_session = DAP_NEW_Z(dap_chain_cs_block_ton_items_t);
	
	// l_session->validators_list = dap_chain_net_get_node_list(l_net);
	// l_session->validators_count = dap_list_length(l_session->validators_list);
	// l_session->validators_list = dap_chain_net_get_node_list(l_net);
	l_session->validators_list = NULL;

	dap_chain_node_addr_t * addr1 = DAP_NEW(dap_chain_node_addr_t);
	addr1->uint64 = 4178375191876571959LLU;
	l_session->validators_list = dap_list_append(l_session->validators_list, addr1);
	
	dap_chain_node_addr_t * addr2 = DAP_NEW(dap_chain_node_addr_t);
	addr2->uint64 = 11242723770690753635LLU;
	l_session->validators_list = dap_list_append(l_session->validators_list, addr2);

	l_session->validators_count = dap_list_length(l_session->validators_list);

//	l_session->gdb_group_store = dap_strdup_printf("local.ton.setup");

// time session
// attempts in round
// attempt time
// rounds count -> max round -> change validator

	dap_chain_net_t * l_net = dap_chain_net_by_id(a_chain->net_id);
    l_session->my_addr = DAP_NEW(dap_chain_node_addr_t);
	l_session->my_addr->uint64 = dap_chain_net_get_cur_addr_int(l_net);

	l_session->cur_round.id.uint64 = 0;
	l_session->old_round.id.uint64 = 0;
	l_session->gdb_group_store = dap_strdup_printf("local.ton.%s.%s.store", 
										a_chain->net_name, a_chain->name);
	l_session->gdb_group_message = dap_strdup_printf("local.ton.%s.%s.message",
										a_chain->net_name, a_chain->name);
	l_session->chain = a_chain;

	// l_session->last_message_hash = NULL;
	// l_session->messages_count = 0;
	// l_session->validators_start = NULL;
	// l_session->validators_start_count = 0;
	
	// cfg
	l_session->round_start_sync_timeout = 10;
	l_session->session_idle_min = 10; // ессли это убрать то надо придумать сколько ждать подписи
	l_session->round_candidates_max = 3;
	l_session->next_candidate_delay = 3;
	l_session->round_attempts_max = 3;
	l_session->round_attempt_duration = 10;
	l_session->allowed_clock_offset = 5;
	
	l_session->consensus_start_period = 20; // hint: if((time()/10) % consensus_start)==0
	l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE;
	l_session->blocks_sign_key = PVT(l_ton)->blocks_sign_key; //a_blocks_sign_key;

	// l_session->timer_consensus_finish = NULL;
	// l_session->timer_consensus_cancel = NULL;
	// l_session->ts_round_sync_start = 0;
	// l_session->ts_round_start = 0;
	// //l_session->ts_round_start_pub = 0;
	// l_session->ts_round_state_commit = 0;
	// l_session->attempt_current_number = 1;
	l_session->time_proc_lock = false;
	
	dap_chain_time_t l_time = (dap_chain_time_t)time(NULL);
	//l_session->ts_round_finish = ((l_time/10)*10) + l_session->consensus_start_period;
	while (true) {
		l_time++;
		if ( (l_time % l_session->consensus_start_period) == 0) {
			//l_session->ts_round_finish = l_time+l_session->session_idle_min;
			l_session->ts_round_sync_start = l_time;
			break;
		}
	}

	pthread_rwlock_init(&l_session->rwlock, NULL);

	DL_APPEND(s_session_items, l_session);
	if (!s_session_cs_timer) {
		s_session_cs_timer = dap_timerfd_start(1*1000, 
                        (dap_timerfd_callback_t)s_session_timer, 
                        NULL);
	}

	dap_stream_ch_chain_voting_in_callback_add(l_session, s_session_packet_in);
	return 0;
}

static void s_session_round_start(dap_chain_cs_block_ton_items_t *a_session) {

	// s_session_candidate_to_chain(a_session);

	a_session->cur_round.validators_start = NULL;
	a_session->cur_round.validators_start_count = 0;

	//a_session->ts_round_sync_start = 0;
	a_session->ts_round_start = 0;
	// a_session->ts_round_start_pub = 0;
	a_session->ts_round_state_commit = 0;
	a_session->attempt_current_number = 1;

	a_session->cur_round.my_candidate_hash = NULL;
	a_session->cur_round.last_message_hash = NULL;
	a_session->cur_round.messages_count = 0;
	a_session->cur_round.submit = false;

	a_session->ts_round_sync_start = (dap_chain_time_t)time(NULL);

	a_session->cur_round.id.uint64++;
}

// static bool s_session_attempt_new(dap_chain_cs_block_ton_items_t *a_session){
// 	// l_session->timer_consensus_finish = NULL;
// 	// l_session->timer_consensus_cancel = NULL;
// 	l_session->ts_round_sync_start = 0;
// 	l_session->ts_round_start = 0;
// 	//l_session->ts_round_start_pub = 0;
// 	l_session->ts_round_state_commit = 0;
// 	l_session->attempt_current_number = 1;
// }


static bool s_session_send_startsync(dap_chain_cs_block_ton_items_t *a_session){
	dap_chain_cs_block_ton_message_startsync_t * l_startsync =
											DAP_NEW_Z(dap_chain_cs_block_ton_message_startsync_t);
	l_startsync->ts = a_session->ts_round_sync_start;
	l_startsync->round_id.uint64 = a_session->cur_round.id.uint64;
	s_message_send(a_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC, 
							(uint8_t*)l_startsync, sizeof(dap_chain_cs_block_ton_message_startsync_t));
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
	 					(uint8_t*)l_votefor, sizeof(dap_chain_cs_block_ton_message_votefor_t));
	DAP_DELETE(l_votefor);
	DAP_DELETE(a_data);
	return false;
}

static bool s_session_timer() {
	dap_chain_time_t l_time = (dap_chain_time_t)time(NULL);
	dap_chain_cs_block_ton_items_t * l_session = NULL;
printf("---!!! s_session_timer() START\n");
	DL_FOREACH(s_session_items, l_session) {
printf("---!!! s_session_timer() DL_FOREACH\n");
		if ( l_session->time_proc_lock ) {
			continue;
		}
		pthread_rwlock_rdlock(&l_session->rwlock);
		l_session->time_proc_lock = true; // lock - skip check by reasons: prev check is not finish
		switch (l_session->state) {
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE: {
printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE \n");
				// dap_chain_time_t l_time_next_round = 
				// 		(l_session->round_attempt_duration * l_session->round_attempts_max) 
				// 			+ l_session->round_start_sync_timeout + l_session->session_idle_min
				// 			+ l_session->ts_round_sync_start;
				if ( (((l_time/10)*10) % l_session->consensus_start_period) == 0 
							&& (l_time - ((l_time/10)*10)) <= 3
							&& l_time > l_session->ts_round_finish
							&& (l_time-l_session->ts_round_finish) >= l_session->session_idle_min) {//l_session->consensus_start_period ) {
				//if (  (((l_time/10)*10) % l_session->consensus_start_period) == 0 ){ // && l_time > l_time_next_round) {

					// round start
					l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START;
					s_session_round_start(l_session);
					//l_session->ts_round_start_sync = l_session->ts_round_start = (dap_chain_time_t)time(NULL);
					//l_session->ts_round_sync_start = l_time;

					dap_chain_net_t * l_net = dap_chain_net_by_id(l_session->chain->net_id);
					// l_session->validators_list = dap_chain_net_get_node_list(l_net);
					// l_session->validators_count = dap_list_length(l_session->validators_list);

					dap_timerfd_start(3*1000, 
						(dap_timerfd_callback_t)s_session_send_startsync, 
							l_session);
				}
				goto session_unlock;
			} //break;
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START: {
printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START \n");
				if ( (l_time-l_session->ts_round_sync_start) >= l_session->round_start_sync_timeout ) { // timeout start sync
					uint16_t l_startsync_count = l_session->cur_round.validators_start_count;// dap_list_length(l_session->validators_start);
printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START 1 sync_count:%d valid_count:%d \n", l_startsync_count, l_session->validators_count);
					if ( ((float)l_startsync_count/l_session->validators_count) >= ((float)2/3) ) {
printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START 2/3 \n");
						l_session->ts_round_start = l_time;
						// if sync 2/3 validators then start round and submit candidate
						l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC;
						l_session->attempt_coordinator = (dap_chain_node_addr_t *)(dap_list_first(l_session->cur_round.validators_start)->data); // temporary: only first
						// dap_timerfd_start(l_session->next_candidate_delay*1000, // pause before candidate submit (todo: by priority and check)
			   //                  (dap_timerfd_callback_t)s_session_candidate_submit, 
			   //                  	l_session);
					} else {
						s_session_round_finish(l_session);
					}
				}
				goto session_unlock;
			} //break;
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS:
printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS \n");
			case DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC: {
printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC attempt:%u \n", l_session->attempt_current_number);

				if ( !l_session->cur_round.submit && l_session->attempt_current_number == 1 ) {
					dap_list_t* l_validators_list = dap_list_first(l_session->validators_list);
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
						if ( (l_time-l_session->ts_round_start) >= (l_session->next_candidate_delay*l_my_number) ) {
							// dap_timerfd_start(3*1000, // pause before candidate submit (todo: by priority and check)
			                //     (dap_timerfd_callback_t)s_session_candidate_submit, 
			                //     	l_session);
printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC Submit time:%llu ts_round_start:%llu\n", l_time, l_session->ts_round_start);
							l_session->cur_round.submit = true;
							s_session_candidate_submit(l_session);
						}
					}
				}

				if ( (l_time-l_session->ts_round_start) 
							>= (l_session->round_attempt_duration*l_session->attempt_current_number) ) {
					l_session->attempt_current_number++;
					if ( l_session->attempt_current_number > l_session->round_attempts_max ) {
						s_session_round_finish(l_session); // attempts is out
						//break;
						goto session_unlock;
					}
					if ( l_session->state == DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS ) {
						//break;
						goto session_unlock;
					}
					uint16_t l_validators_count = l_session->cur_round.validators_start_count;// dap_list_length(l_session->validators_start);
					uint16_t l_validators_index =
						( (l_session->attempt_current_number-1)
								- (l_validators_count
										* ((l_session->attempt_current_number-1)/l_validators_count)));
					//if ( l_validators_count < l_session->attempt_current_number ) {
					//	s_session_round_finish(l_session); // validators is out
					//	break;
					//}
					l_session->attempt_coordinator = (dap_chain_node_addr_t *)
											(dap_list_nth(l_session->cur_round.validators_start, 
													l_validators_index)->data);
													//(l_session->attempt_current_number-2))->data);

printf("---!!! s_session_timer() DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC coordinator:%llu index:%u\n", 
		l_session->attempt_coordinator->uint64, l_validators_index);

					if ( l_session->my_addr->uint64 == l_session->attempt_coordinator->uint64 ) {
						
						// I coordinator :-) select candidate
		                dap_list_t* l_list_candidate = NULL;
		                size_t l_objs_size = 0;
		                dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_objs_size);
		                if (l_objs_size) {
		                    for (size_t i = 0; i < l_objs_size; i++) {
		                        if (!l_objs[i].value_len)
		                            continue;

           						dap_chain_cs_block_ton_store_t * l_store = 
											(dap_chain_cs_block_ton_store_t *)l_objs[i].value;
								if ( l_store->hdr.round_id.uint64 != l_session->cur_round.id.uint64 )
									continue;

								// add candidate in list if it has 2/3 approve
								if ( ((float)l_store->hdr.approve_count/l_session->validators_count) >= ((float)2/3) ) {
									dap_chain_hash_fast_t * l_hash = DAP_NEW(dap_chain_hash_fast_t);
									dap_chain_hash_fast_from_str(l_objs[i].key, l_hash);
		                       		l_list_candidate = dap_list_append(l_list_candidate, l_hash);
		                       	}
		                    }
		                    dap_chain_global_db_objs_delete(l_objs, l_objs_size);
		                }
		                size_t l_list_candidate_size = (size_t)dap_list_length(l_list_candidate);
						dap_chain_cs_block_ton_message_votefor_t * l_votefor =
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
						// l_votefor->round_id = l_session->cur_round.id;
						l_votefor->attempt_number = l_session->attempt_current_number;
						s_session_send_votefor_data_t *l_data = DAP_NEW_Z(s_session_send_votefor_data_t);
						l_data->votefor = l_votefor;
						l_data->session = l_session;
						dap_timerfd_start(3*1000, // pause before send votefor
			                    (dap_timerfd_callback_t)s_session_send_votefor, 
			                    	l_data);
					}
				}
				goto session_unlock;
			}// break;
			// case DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS: {
			// 	if ( (l_time-l_session->ts_round_state_commit) >= 10 )
			// 		s_session_round_finish(l_session);
			// } break;
		}
session_unlock:
		l_session->time_proc_lock = false; // unlock
		pthread_rwlock_unlock(&l_session->rwlock);
	}
	return true;
}

// static void s_session_start (dap_chain_cs_block_ton_items_t * a_session) {
// 	dap_chain_time_t l_time = (dap_chain_time_t)time(NULL);
// }

static void s_session_candidate_to_chain(
			dap_chain_cs_block_ton_items_t *a_session, dap_chain_hash_fast_t *a_candidate_hash,
							dap_chain_cs_block_ton_store_t * a_candidate, size_t a_candidate_size) {

printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 1111 \n");

	// dap_list_t *old_round.validators_start
	dap_list_t *l_submit_list = NULL;
    dap_chain_cs_block_ton_message_item_t *l_message_item=NULL, *l_message_tmp=NULL;
    HASH_ITER(hh, a_session->old_round.messages_items, l_message_item, l_message_tmp) {
    	uint8_t l_message_type = l_message_item->message->hdr.type;
    	if ( l_message_type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN ) {
    		dap_chain_hash_fast_t * l_candidate_hash = 
    					&((dap_chain_cs_block_ton_message_submit_t *)l_message_item->message->message)->candidate_hash;
    		if ( memcmp(l_candidate_hash, a_candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
    			l_submit_list = dap_list_append(l_submit_list, (void*)l_message_item->message);
    		}
    	}
    }

printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 2222\n");

    if (!l_submit_list) {
    	return;
    }

printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 3333\n");

    dap_chain_block_t * l_candidate = 
    	(dap_chain_block_t *)DAP_DUP_SIZE(a_candidate, a_candidate_size);
    // size_t l_candidate_size = a_store_candidate->hdr.candidate_size;
    size_t l_offset = dap_chain_block_get_sign_offset(l_candidate, a_candidate_size);

	dap_list_t *l_validators_list = dap_list_first(a_session->old_round.validators_start);
	size_t l_signs_count = 0;
	while(l_validators_list) {
		dap_list_t *l_submit_temp = dap_list_first(l_submit_list);
printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 3333-1\n");
		while(l_submit_temp) {
			dap_chain_cs_block_ton_message_t *l_message = (dap_chain_cs_block_ton_message_t*)l_submit_temp->data;
			dap_chain_cs_block_ton_message_commitsign_t * l_commitsign =
										(dap_chain_cs_block_ton_message_commitsign_t *)&l_message->message;
printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 3333-2\n");
			if( l_message->hdr.is_verified 
					&& l_message->hdr.sender_node_addr.uint64 == a_session->my_addr->uint64) {

printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 3333-3\n");

				dap_sign_t* l_candidate_sign = (dap_sign_t*)l_commitsign->candidate_sign;
				size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
				if (!l_candidate_sign_size)
        			continue;
printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 3333-4\n");
        		//a_store_candidate->hdr.candidate_size += l_candidate_sign_size;
        		l_candidate = DAP_REALLOC(l_candidate, a_candidate_size+l_candidate_sign_size);

				// size_t l_store_size_new = l_store_size+l_candidate_sign_size;
				// l_store = DAP_REALLOC(l_store, l_store_size_new);
				// memcpy(((byte_t *)l_store)+l_store_size, l_commitsign->candidate_sign, l_candidate_sign_size);
				memcpy(((byte_t *)l_candidate)+a_candidate_size, l_candidate_sign, l_candidate_sign_size);
				a_candidate_size += l_candidate_sign_size;
				l_signs_count++;
			}
			l_submit_temp = l_submit_temp->next;
		}
		l_validators_list = l_validators_list->next;
	}

printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 4444\n");

	//l_candidate a_candidate_size
	if ( ((float)l_signs_count/a_session->validators_count) >= ((float)2/3) ) {
printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 5555\n");
		// delete my new block if it passed consensus
		if ( a_session->old_round.my_candidate_hash 
				&& memcmp(a_session->old_round.my_candidate_hash, 
							a_candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
printf("---!!! s_session_timer() s_session_candidate_to_chain() CHAIN 6666\n");
			s_session_block_new_delete(a_session);
			DAP_DELETE(a_session->old_round.my_candidate_hash);
			a_session->old_round.my_candidate_hash=NULL;
		}

printf("---!!! s_session_timer() s_session_candidate_to_chain() 1\n");
printf("---!!! s_session_timer() s_session_candidate_to_chain() 2 hash:%s, size:%d\n", a_candidate_hash, a_candidate_size);
		// block save to chain
        if (dap_chain_atom_save(a_session->chain, (uint8_t *)l_candidate, a_candidate_size, a_session->chain->cells->id) < 0) {
printf("---!!! s_session_timer() s_session_candidate_to_chain() 2-1\n");
            log_it(L_ERROR, "Can't add new block to the file");
        }
printf("---!!! s_session_timer() s_session_candidate_to_chain() 3\n");
printf("---!!! s_session_timer() s_session_candidate_to_chain() 4\n");
	}

	DAP_DELETE(l_candidate);
}

static bool s_session_candidate_submit(dap_chain_cs_block_ton_items_t *a_session){

//	uint16_t l_net_list_size = 0;
// 	dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_list_size);
// 	for (int i=0; i<l_net_list_size; i++) {
// 		dap_chain_t *l_chain;
// 	    DL_FOREACH(l_net_list[i]->pub.chains, l_chain) {
// 	        if (!l_chain) {
// 	            continue;
// 	        }
// 		}
// 	}

	dap_chain_t * l_chain = a_session->chain;
	// dap_chain_net_t * l_net = dap_chain_net_by_id(l_chain->net_id);
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);

    // if (!l_blocks->block_new)
    // 	return false; // for timer

printf("---!!! s_session_timer() s_session_candidate_submit() SUBMIT 1\n");

	size_t l_submit_size = l_blocks->block_new ? 
				sizeof(dap_chain_cs_block_ton_message_submit_t)+l_blocks->block_new_size
				: sizeof(dap_chain_cs_block_ton_message_submit_t);
	dap_chain_cs_block_ton_message_submit_t * l_submit =
							DAP_NEW_SIZE(dap_chain_cs_block_ton_message_submit_t, l_submit_size);
	l_submit->round_id.uint64 = a_session->cur_round.id.uint64;
	l_submit->candidate_size = l_blocks->block_new_size;


    if (l_blocks->block_new) { // exists my candidate
// printf("---!!! s_session_timer() s_session_candidate_submit() SUBMIT 2\n");
// 		if (  0 == s_session_datums_validation(l_blocks, l_blocks->block_new, l_blocks->block_new_size) ) {
// printf("---!!! s_session_timer() s_session_candidate_submit() SUBMIT 3\n");
// 		}

	    dap_chain_hash_fast_t l_candidate_hash;
		dap_hash_fast(l_blocks->block_new, l_blocks->block_new_size, &l_candidate_hash);
		memcpy(&l_submit->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
		a_session->cur_round.my_candidate_hash = 
				(dap_chain_hash_fast_t*)DAP_DUP_SIZE(&l_candidate_hash, sizeof(dap_chain_hash_fast_t));
		memcpy(l_submit->candidate, l_blocks->block_new, l_blocks->block_new_size);
	}
	else { // no my candidate, send null hash
		dap_chain_hash_fast_t l_candidate_hash_null={0};
		a_session->cur_round.my_candidate_hash = NULL;
		memcpy(&l_submit->candidate_hash, &l_candidate_hash_null, sizeof(dap_chain_hash_fast_t));
	}
	// memcpy(&l_submit->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
	// memcpy(l_submit->candidate, l_blocks->block_new, l_blocks->block_new_size);

	s_message_send(a_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT, (uint8_t*)l_submit, l_submit_size);
	// return false; // for test

	DAP_DELETE(l_submit);

	// this commented by reason: not delete new block if it not passed at consensus
	// надо удалять еще при ошибки, возможно надо удалять если блок не был принят,
	// значит оформить удаление в функцию 
	// DAP_DELETE(l_blocks->block_new);
	// l_blocks->block_new = NULL;
	// l_blocks->block_new_size = 0;

    //return true;
    return false; // for timer
}


static int s_session_datums_validation(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size){
	// a_blocks->chain->ledger
	// dap_chain_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx);

	// return 0;

	size_t l_datums_count = 0;
	dap_chain_datum_t **l_datums = dap_chain_block_get_datums(a_block, a_block_size, &l_datums_count);

printf("---!!! s_session_timer() s_session_datums_validation() VALID 1\n");

    if (!l_datums || !l_datums_count) {
        //log_it(L_WARNING, "No datums in block %p on chain %s", a_block, a_blocks->chain->name);
        return -2;
    }

printf("---!!! s_session_timer() s_session_datums_validation() VALID 2\n");

    for(size_t i=0; i<l_datums_count; i++){
    	dap_chain_datum_t *l_datum = l_datums[i];
    	switch (l_datum->header.type_id) {
    		case DAP_CHAIN_DATUM_TX: {
printf("---!!! s_session_timer() s_session_datums_validation() VALID 3\n");
    			dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
    			int ret = dap_chain_ledger_tx_add_check(a_blocks->chain->ledger, l_tx);
    			if (ret != 0) {
    				return -1;
    			}
    		}
    	}
    }
printf("---!!! s_session_timer() s_session_datums_validation() VALID 4\n");
    return 0;
}

static void s_session_block_new_delete(dap_chain_cs_block_ton_items_t *a_session) {
printf("---!!! s_session_timer() s_session_block_new_delete() BLOCK_NEW_DEL 1111\n");
	dap_chain_t * l_chain = a_session->chain;
	dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);
	if ( l_blocks->block_new ) {
printf("---!!! s_session_timer() s_session_block_new_delete() BLOCK_NEW_DEL 2222\n");
		//DAP_DELETE(l_blocks->block_new);
		//l_blocks->block_new = NULL;
		DAP_DEL_Z(l_blocks->block_new);
		l_blocks->block_new_size = 0;
	}
}

static bool s_session_round_finish(dap_chain_cs_block_ton_items_t *a_session) {

	// if ( a_session->state == DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC ){
	// 	// {...} if exists candidate check sign and save to chain
	// }

	a_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE;
	a_session->ts_round_finish = (dap_chain_time_t)time(NULL);

	// dap_list_free(a_session->validators_start);
	// a_session->validators_start = NULL;
	// a_session->validators_start_count = 0;

	// a_session->ts_round_sync_start = 0;
	// a_session->ts_round_start = 0;
	// // a_session->ts_round_start_pub = 0;
	// a_session->ts_round_state_commit = 0;
	// a_session->attempt_current_number = 1;

	// if (a_session->timer_consensus_cancel)
	// 	dap_timerfd_delete(a_session->timer_consensus_cancel);
	// a_session->timer_consensus_cancel = NULL;

	// if (a_session->timer_consensus_finish)
	// 	dap_timerfd_delete(a_session->timer_consensus_finish);
	// a_session->timer_consensus_finish = NULL;


	// dap_chain_cs_block_ton_round_id_t old_round.id;
	// dap_list_t *old_round.validators_start; // dap_chain_node_addr_t
	// uint16_t old_round.validators_start_count;
	// dap_chain_hash_fast_t *old_round.last_message_hash;
	// dap_chain_cs_block_ton_message_item_t * old_round.messages_items;
	// uint16_t old_round.messages_count;


	// // delete messages chain
 //    l_objs = dap_chain_global_db_gr_load(a_session->gdb_group_message, &l_objs_size);
 //    if (l_objs_size) {
 //        for (size_t i = 0; i < l_objs_size; i++) {
 //            if (!l_objs[i].value_len)
 //                continue;
 //        }
 //        dap_chain_global_db_objs_delete(l_objs, l_objs_size);
 //    }


printf("---!!! s_session_timer() s_session_round_finish() 111111 - search candidate \n");

    size_t l_objs_size = 0;
    dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(a_session->gdb_group_store, &l_objs_size);
    if (l_objs_size) {
    	dap_chain_cs_block_ton_store_t *l_store_candidate_ready = NULL;
    	size_t l_candidate_ready_size = 0;
        for (size_t i = 0; i < l_objs_size; i++) {
            if (!l_objs[i].value_len)
                continue;
            dap_chain_cs_block_ton_store_t * l_store = 
										(dap_chain_cs_block_ton_store_t *)l_objs[i].value;
			if ( l_store->hdr.round_id.uint64 == a_session->old_round.id.uint64 ) {
				dap_chain_global_db_gr_del(dap_strdup(l_objs[i].key), a_session->gdb_group_store);
				if ( ((float)l_store->hdr.sign_count/a_session->validators_count) >= ((float)2/3) ) {
					//l_candidate_ready = (dap_chain_cs_block_ton_store_t *)l_store->candidate_n_signs;
					l_store_candidate_ready = l_store;
				}
			}
			// delete my candidate if it not collected 2/3 approve
			if ( l_store->hdr.round_id.uint64 == a_session->cur_round.id.uint64 ) {
printf("---!!! s_session_timer() s_session_round_finish() 222222 - search candidate \n");
				if ( a_session->cur_round.my_candidate_hash
						&& memcmp(&l_store->hdr.candidate_hash,
								a_session->cur_round.my_candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
printf("---!!! s_session_timer() s_session_round_finish() 333333 - search candidate \n");
					s_session_block_new_delete(a_session);
					DAP_DELETE(a_session->cur_round.my_candidate_hash);
					a_session->cur_round.my_candidate_hash=NULL;
				}
			}
        }
        if (l_store_candidate_ready) {
        	s_session_candidate_to_chain(a_session, &l_store_candidate_ready->hdr.candidate_hash, 
        					l_store_candidate_ready->candidate_n_signs, l_store_candidate_ready->hdr.candidate_size);
        }
        dap_chain_global_db_objs_delete(l_objs, l_objs_size);
    }

    dap_chain_cs_block_ton_message_item_t *l_message_item=NULL, *l_message_tmp=NULL;
    HASH_ITER(hh, a_session->old_round.messages_items, l_message_item, l_message_tmp) {
        HASH_DEL(a_session->old_round.messages_items, l_message_item);
        DAP_DELETE(l_message_item->message);
        DAP_DELETE(l_message_item);
    }

    if ( a_session->old_round.validators_start ) {
		dap_list_free(a_session->old_round.validators_start);
		a_session->old_round.validators_start = NULL;
	}

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

	a_session->old_round.validators_start = a_session->cur_round.validators_start;
	a_session->cur_round.validators_start = NULL;

	a_session->old_round.validators_start_count = a_session->cur_round.validators_start_count;
	a_session->old_round.last_message_hash = a_session->cur_round.last_message_hash;
	a_session->cur_round.last_message_hash = NULL;
	a_session->old_round.messages_count = a_session->cur_round.messages_count;

	a_session->old_round.my_candidate_hash = a_session->cur_round.my_candidate_hash;
	a_session->cur_round.my_candidate_hash = NULL;

	// a_session->last_message_hash = NULL;
	// a_session->messages_count = 0;

	return false;
}

// must change to validator list 
static dap_chain_node_addr_t * s_session_get_validator_by_addr(
					dap_chain_cs_block_ton_items_t * a_session, dap_chain_node_addr_t * a_addr) {
	dap_list_t* l_list_validator = dap_list_first(a_session->validators_list);
	while(l_list_validator) {
		dap_list_t *l_list_validator_next = l_list_validator->next;
		if ( ((dap_chain_node_addr_t *)l_list_validator->data)->uint64 == a_addr->uint64 )
			return l_list_validator->data;
		l_list_validator = l_list_validator_next;
	}
	return NULL;
}

static void s_session_packet_in(void * a_arg, dap_chain_node_addr_t * a_sender_node_addr, 
								dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size) {


	dap_chain_cs_block_ton_items_t * l_session = (dap_chain_cs_block_ton_items_t *)a_arg;
	dap_chain_time_t l_time = (dap_chain_time_t)time(NULL);
	// dap_chain_cs_block_ton_message_t * l_message = (dap_chain_cs_block_ton_message_t *)a_data;

	dap_chain_cs_block_ton_message_t * l_message =
			(dap_chain_cs_block_ton_message_t *)DAP_DUP_SIZE(a_data, a_data_size);

	l_message->hdr.is_verified=false;

printf("---!!! s_session_packet_in() TEST PACKET 0 my_addr:%llu\n", l_session->my_addr->uint64);
printf("---!!! s_session_packet_in() TEST PACKET 1 type:%x addr:%llu\n", l_message->hdr.type, a_sender_node_addr->uint64);

	dap_chain_node_addr_t * l_validator = s_session_get_validator_by_addr(l_session, a_sender_node_addr);
	if (!l_validator) {
		goto handler_finish;
	}

printf("---!!! s_session_packet_in() TEST PACKET 2 \n");

	//char * l_message_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_message->hdr.message_hash);

	if ( l_session->attempt_current_number != 1 ) {
		switch (l_message->hdr.type) { // this types allow only in first attempt
			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT:
			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
				goto handler_finish;
			}
		}
	}

printf("---!!! s_session_packet_in() TEST PACKET 3 \n");

    dap_chain_hash_fast_t l_data_hash;
    dap_hash_fast(a_data, a_data_size, &l_data_hash);

    if (l_message->hdr.chain_id.uint64 != l_session->chain->id.uint64 ) {
    	goto handler_finish;
    }

printf("---!!! s_session_packet_in() TEST PACKET 4 \n");

    if (memcmp(a_data_hash, &l_data_hash, sizeof(dap_chain_hash_fast_t)) != 0) {
		goto handler_finish;
    }

printf("---!!! s_session_packet_in() TEST PACKET 5 \n");

	// consensus start sync
	if ( l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC ) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC \n");
		// check time offset
		dap_chain_cs_block_ton_message_startsync_t * l_startsync =
							(dap_chain_cs_block_ton_message_startsync_t *)&l_message->message;

printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC my_time:%llu, me_time:%llu\n", l_time, l_startsync->ts);
		if ( 
			(l_time>l_startsync->ts && (l_time-l_startsync->ts) > l_session->allowed_clock_offset )
				|| (l_time<l_startsync->ts && (l_startsync->ts-l_time) > l_session->allowed_clock_offset )
					) {
			// offset is more than allowed_clock_offset
			// skip this validator 
			goto handler_finish;
		}
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC 2 \n");

		// add check&save sender addr
		dap_list_t* l_list_temp = dap_list_first(l_session->cur_round.validators_start);
		while(l_list_temp) {
			dap_list_t *l_list_next = l_list_temp->next;
			if (((dap_chain_node_addr_t *)l_list_temp->data)->uint64 == l_validator->uint64)
				goto handler_finish;
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

printf("---!!! s_session_packet_in() TEST PACKET 6 \n");

	if ( l_session->state != DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC
			&& l_session->state != DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS ) {
		goto handler_finish;
	}

printf("---!!! s_session_packet_in() TEST PACKET 7 \n");

	
	// round check
	uint64_t l_round_id =
				((dap_chain_cs_block_ton_message_getinfo_t *)l_message->message)->round_id.uint64;
	if ( l_message->hdr.type != DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN ) {
		if ( l_round_id != l_session->cur_round.id.uint64) {
			goto handler_finish;
		}
	} else {
		if ( l_round_id != l_session->cur_round.id.uint64
					&& l_round_id != l_session->old_round.id.uint64 ) {
			goto handler_finish;
		}
	}

	dap_chain_cs_block_ton_message_item_t * l_messages_items = NULL;
	l_messages_items = l_round_id == l_session->cur_round.id.uint64 ?
						l_session->cur_round.messages_items : l_session->old_round.messages_items;

	// check hash message dup
	dap_chain_cs_block_ton_message_item_t * l_message_item_temp = NULL;
	HASH_FIND(hh, l_messages_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_message_item_temp);
	if (l_message_item_temp) {
		goto handler_finish;
	}

	// check validator index in queue for event Submit
	if ( l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT ) {
		dap_list_t* l_validators_list = dap_list_first(l_session->cur_round.validators_start);
		int l_validator_number = 0;
		int i = 0;
		while(l_validators_list) {
			if( ((dap_chain_node_addr_t*)l_validators_list->data)->uint64 == a_sender_node_addr->uint64) {
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
    			uint8_t l_chain_msg_type = l_chain_message->message->hdr.type;
    			if ( l_chain_message->message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT )
    				l_submit_count++;
    		}
    		if ( l_validator_number < l_submit_count ) {
    			goto handler_finish; // Skip this SUBMIT. Validator must wait its queue.
    		}
		}
	}

printf("---!!! s_session_packet_in() TEST PACKET 8 \n");

    uint32_t l_approve_count = 0, l_vote_count = 0, l_precommit_count = 0;
	// check messages chain
    dap_chain_cs_block_ton_message_item_t *l_chain_message=NULL, *l_chain_message_tmp=NULL;
    HASH_ITER(hh, l_messages_items, l_chain_message, l_chain_message_tmp) {
    	if (l_chain_message->message->hdr.sender_node_addr.uint64 == a_sender_node_addr->uint64) {
    		dap_chain_hash_fast_t * l_candidate_hash_cur = 
    			&((dap_chain_cs_block_ton_message_getinfo_t *)l_message->message)->candidate_hash;

    		dap_chain_hash_fast_t * l_candidate_hash = 
    			&((dap_chain_cs_block_ton_message_getinfo_t *)l_chain_message->message->message)->candidate_hash;

    		bool l_candidate_hash_match = (memcmp(l_candidate_hash_cur, l_candidate_hash,
															sizeof(dap_chain_hash_fast_t)) == 0);

    		uint8_t l_chain_msg_type = l_chain_message->message->hdr.type;

printf("---!!! s_session_packet_in() TEST PACKET 8-1 \n");

    		// search & check messages from this validator 
    		switch (l_chain_msg_type) {
    			// check dup messages VOTE, APPROVE, REJECT for one candidate
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
    				// if (l_candidate_hash_match)
    				// 	l_approve_count++;
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
printf("---!!! s_session_packet_in() TEST PACKET 8-2 \n");
    				switch (l_message->hdr.type) {
    					//case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE:
    					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
    					case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT:
	    					if (l_candidate_hash_match) {
								goto handler_finish;
							}
    				}
    			} break;
    			//check dup messages VOTE for one candidate in this attempt
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
    				dap_chain_cs_block_ton_message_vote_t * l_vote = 
    								(dap_chain_cs_block_ton_message_vote_t *)&l_message->message;
    				dap_chain_cs_block_ton_message_vote_t * l_vote_item = 
    								(dap_chain_cs_block_ton_message_vote_t *)&l_chain_message->message->message;
    				if ( l_chain_msg_type == l_message->hdr.type
    						&& l_vote->attempt_number == l_vote_item->attempt_number ) {
    					goto handler_finish;
    				}
    			} break;
					// if ( l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE
					// 		|| l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE
					// 		|| l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT ) {
					// 	if (l_candidate_hash_match) {
					// 		goto handler_finish;
					// 	}
					// }
    			// this messages should only appear once per round //attempt
    			// case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: 
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT:{
printf("---!!! s_session_packet_in() TEST PACKET 8-3 \n");
    				if ( l_chain_msg_type == l_message->hdr.type ){
    					goto handler_finish;
    				}
    			}
    		}

printf("---!!! s_session_packet_in() TEST PACKET 8-4 \n");

    		// count messages in chain for this candidate
    		if (l_candidate_hash_match) {
	    		switch (l_chain_msg_type) {
	    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE: {
	    				l_approve_count++;
	    			} break;
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

printf("---!!! s_session_packet_in() TEST PACKET 9 \n");

	// check message chain is correct
	switch (l_message->hdr.type) {
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
			if (!l_approve_count) { // if this validator not sent Approve for this candidate
    			goto handler_finish;
    		}
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT: {
			if (!l_vote_count) { // if this validator not sent Vote for this candidate
    			goto handler_finish;
    		}
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
			if (!l_precommit_count) { // if this validator not sent PreCommit for this candidate
    			goto handler_finish;
    		}
		} break;
	}

printf("---!!! s_session_packet_in() TEST PACKET 10 \n");

	// save to messages chain
	dap_chain_hash_fast_t l_message_hash;
	s_message_chain_add(l_session, a_sender_node_addr, l_message, a_data_size, &l_message_hash);

	dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_session->chain);

	// uint8_t* l_message_data = (uint8_t*)&l_message->message;
	// size_t l_message_data_size = l_message->hdr.message_size;	
	// dap_chain_hash_fast_t l_message_data_hash;
	// dap_hash_fast(l_message_data, l_message_data_size, &l_message_data_hash);
	// char * l_message_data_hash_str = dap_chain_hash_fast_to_str_new(&l_message_data_hash);

	switch (l_message->hdr.type) {
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT: {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT \n");
			int ret = 0;
			dap_chain_cs_block_ton_message_submit_t * l_submit =
										(dap_chain_cs_block_ton_message_submit_t *)&l_message->message;

			size_t l_candidate_size = l_submit->candidate_size;
			if (!l_candidate_size) { // null candidate - save chain and exit
				goto handler_finish;
			}


			dap_chain_block_t * l_candidate = (dap_chain_block_t *)l_submit->candidate;

			dap_chain_hash_fast_t l_candidate_hash;
			dap_hash_fast(l_candidate, l_candidate_size, &l_candidate_hash);
			
			// check candidate hash
			if (memcmp(&l_submit->candidate_hash, &l_candidate_hash,
											sizeof(dap_chain_hash_fast_t)) != 0) {
				goto handler_finish;				
			}

			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_candidate_hash);

			// check block exist in store
			size_t l_store_temp_size = 0;
			dap_chain_cs_block_ton_store_t * l_store_temp = 
											(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_temp_size, l_session->gdb_group_store);
			if (l_store_temp) {
				DAP_DELETE(l_store_temp);
				DAP_DELETE(l_candidate_hash_str);
				goto handler_finish;
			}

			pthread_rwlock_rdlock(&l_session->rwlock);

			// save to messages chain
			// dap_chain_hash_fast_t l_message_hash;
			// s_message_chain_add(l_session, a_sender_node_addr, l_message, a_data_size, &l_message_hash);

			dap_chain_net_t * l_net = dap_chain_net_by_id(l_session->chain->net_id);	
			
			// dap_chain_block_t * l_candidate = (dap_chain_block_t *)l_message_data;

		    // stor for new candidate
		    size_t l_store_size = sizeof(dap_chain_cs_block_ton_store_hdr_t)+a_data_size;
		    dap_chain_cs_block_ton_store_t * l_store = 
		    						DAP_NEW_Z_SIZE(dap_chain_cs_block_ton_store_t, l_store_size);
		    l_store->hdr.sign_count = 0;
		    l_store->hdr.approve_count = 0;
		    l_store->hdr.reject_count = 0;
		    l_store->hdr.vote_count = 0;
		    l_store->hdr.candidate_size = l_candidate_size;
		    l_store->hdr.ts_candidate_submit = l_time;
		    l_store->hdr.round_id.uint64 = l_session->cur_round.id.uint64;
		    // l_store->hdr.approve_count = 1; candidate_hash
		    memcpy( &l_store->hdr.candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
			memcpy( &l_store->candidate_n_signs, l_candidate, l_candidate_size);

			// save new block candidate
			if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
													l_store_size, l_session->gdb_group_store) ) {
				if ( !(ret = s_session_datums_validation(l_blocks, l_candidate, l_candidate_size)) ) {
					// validation - OK, gen event Approve
				    if (l_session->blocks_sign_key) {
						size_t l_candidate_size = l_store->hdr.candidate_size;
					    dap_sign_t *l_hash_sign = dap_sign_create(l_session->blocks_sign_key,
					    								&l_candidate_hash, sizeof(dap_chain_hash_fast_t), 0);

					    size_t l_hash_sign_size = dap_sign_get_size(l_hash_sign);
						size_t l_approve_size = sizeof(dap_chain_cs_block_ton_message_approve_t)+l_hash_sign_size;

						dap_chain_cs_block_ton_message_approve_t * l_approve =
												DAP_NEW_SIZE(dap_chain_cs_block_ton_message_approve_t, l_approve_size);
						l_approve->round_id.uint64 = l_session->cur_round.id.uint64;
						memcpy(&l_approve->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
						memcpy(l_approve->candidate_hash_sign, l_hash_sign, l_hash_sign_size);

						s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE,
															(uint8_t*)l_approve, l_approve_size);
						DAP_DELETE(l_approve);
					}
					else
						log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-ton] section");	
				}
				else {
					// validation - fail, gen event Reject
					dap_chain_cs_block_ton_message_reject_t * l_reject =
															DAP_NEW_Z(dap_chain_cs_block_ton_message_reject_t);
					l_reject->round_id.uint64 = l_session->cur_round.id.uint64;
					memcpy(&l_reject->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
					s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT,
							(uint8_t*)l_reject, sizeof(dap_chain_cs_block_ton_message_reject_t));
					DAP_DELETE(l_reject);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store_temp);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT \n");

			dap_chain_cs_block_ton_message_reject_t * l_reject =
										(dap_chain_cs_block_ton_message_reject_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_reject->candidate_hash;
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
		
			pthread_rwlock_rdlock(&l_session->rwlock);
			size_t l_store_size = 0;
			dap_chain_cs_block_ton_store_t * l_store = 
											(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				l_store->hdr.reject_count++;
				// don't save block if 2/3 validators say reject 
				if ( ((float)l_store->hdr.reject_count/l_session->validators_count) < ((float)2/3) ) {
					dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
													l_store_size, l_session->gdb_group_store);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE: {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE \n");

			dap_chain_cs_block_ton_message_approve_t * l_approve =
										(dap_chain_cs_block_ton_message_approve_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_approve->candidate_hash;

			// size_t l_sign_size = dap_sign_get_size(l_approve->candidate_hash_sign);
			// dap_sign_t *l_hash_sign = DAP_NEW_SIZE(dap_sign_t, l_sign_size);
			// memcpy(l_hash_sign, l_approve->candidate_hash_sign, l_sign_size);

			int l_sign_verified=0;
			// check candidate hash sign
			if ( (l_sign_verified=dap_sign_verify( (dap_sign_t*)l_approve->candidate_hash_sign, 
													l_candidate_hash, sizeof(dap_chain_hash_fast_t))) == 1 ) {
				l_message->hdr.is_verified=true;
				pthread_rwlock_rdlock(&l_session->rwlock);
				char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
				size_t l_store_size = 0;
				dap_chain_cs_block_ton_store_t * l_store = 
												(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
															l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
				if (l_store) {
					dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
					l_store->hdr.approve_count++;

					dap_chain_cs_block_ton_store_t * l_store_gdb = 
									(dap_chain_cs_block_ton_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
														l_store_size, l_session->gdb_group_store) )
						if ( l_session->attempt_current_number == 1 ) { // if this first attempt then send Vote event
							if ( ((float)l_store->hdr.approve_count/l_session->validators_count) >= ((float)2/3) ) {
								// event Vote
								dap_chain_cs_block_ton_message_vote_t * l_vote =
																	DAP_NEW_Z(dap_chain_cs_block_ton_message_vote_t);
								l_vote->round_id.uint64 = l_session->cur_round.id.uint64;
								memcpy(&l_vote->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
								l_vote->attempt_number = l_session->attempt_current_number;
								s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE,
								 					(uint8_t*)l_vote, sizeof(dap_chain_cs_block_ton_message_vote_t));
								DAP_DELETE(l_vote);
							}
						}
				}
				pthread_rwlock_unlock(&l_session->rwlock);
				DAP_DELETE(l_store);
				DAP_DELETE(l_candidate_hash_str);
			} else {
				// l_message->hdr.is_verified=false;
				log_it(L_WARNING, "Candidate hash sign is incorrect: code %d", l_sign_verified);
			}
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR: { // start NEW attempt
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR \n");

			dap_chain_cs_block_ton_message_votefor_t * l_votefor =
										(dap_chain_cs_block_ton_message_votefor_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_votefor->candidate_hash;
			
			if ( l_votefor->attempt_number != l_session->attempt_current_number) {
				goto handler_finish; // wrong attempt number in message
			}

char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 1 mes_hash:%s\n", l_candidate_hash_str);

			// dap_chain_node_addr_t *l_coordinator_cur-> = 
			// 		(dap_chain_node_addr_t *)dap_list_nth_data(l_session->validators_start,
			// 											(l_session->attempt_current_number-1));

			if ( a_sender_node_addr->uint64 != l_session->attempt_coordinator->uint64 ) {
				goto handler_finish; // wrong coordinator addr
			}

printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 2 \n");

			// search candidate with 2/3 vote
            //dap_list_t* l_list_candidate = NULL;
			pthread_rwlock_rdlock(&l_session->rwlock);

			size_t l_objs_size = 0;
			dap_chain_cs_block_ton_store_t * l_found_best = NULL;
			dap_chain_cs_block_ton_store_t * l_found_vote = NULL;
			dap_chain_cs_block_ton_store_t * l_found_approve_vf = NULL;
			dap_chain_cs_block_ton_store_t * l_found_approve = NULL;
            dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_objs_size);
            if (l_objs_size) {

printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 3 \n");
                for (size_t i = 0; i < l_objs_size; i++) {
                    if (!l_objs[i].value_len)
                        continue;
					dap_chain_cs_block_ton_store_t * l_store = 
							(dap_chain_cs_block_ton_store_t *)l_objs[i].value;
					if ( l_store->hdr.round_id.uint64 != l_session->cur_round.id.uint64 )
						continue;
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 3-1 db_hash:%s\n", l_objs[i].key);
					if ( ((float)l_store->hdr.vote_count/l_session->validators_count) >= ((float)2/3) ) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 4\n");
						// best choice :-) 2/3 vote (i.e. PreCommit) and VoteFor candidate
						if (memcmp(l_candidate_hash, &l_store->hdr.candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 5 \n");
							l_found_best = (dap_chain_cs_block_ton_store_t *)l_objs[i].value;
							break;
						}

						// other PreCommit candidate (ignore VoteFor)
						if ( !l_found_vote
								|| l_found_vote->hdr.ts_candidate_submit<l_store->hdr.ts_candidate_submit ) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 6 \n");
							l_found_vote = (dap_chain_cs_block_ton_store_t *)l_objs[i].value;
						}
                   	}
                   	if ( ((float)l_store->hdr.approve_count/l_session->validators_count) >= ((float)2/3) ) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 7 \n");
                   		// 2/3 Approve & VoteFor
						if (memcmp(l_candidate_hash, &l_store->hdr.candidate_hash, sizeof(dap_chain_hash_fast_t)) == 0) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 8 \n");
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

                dap_chain_cs_block_ton_store_t * l_found_candidate = NULL;
                if (l_found_best) {
                	l_found_candidate = l_found_best;
                }
                else if (l_found_vote) {
                	l_found_candidate = l_found_vote;
                }
                else if (l_found_approve_vf) {
                	l_found_candidate = l_found_approve_vf;
                }
                else if (l_found_approve) {
                	l_found_candidate = l_found_approve;
                }

                if (l_found_candidate) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR 9 \n");
    				// candidate found, gen event Vote
					dap_chain_cs_block_ton_message_vote_t * l_vote =
														DAP_NEW_Z(dap_chain_cs_block_ton_message_vote_t);
					memcpy(&l_vote->candidate_hash, &l_found_candidate->hdr.candidate_hash, sizeof(dap_chain_hash_fast_t));
					l_vote->round_id.uint64 = l_session->cur_round.id.uint64;
					l_vote->attempt_number = l_session->attempt_current_number;
					s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE,
					 					(uint8_t*)l_vote, sizeof(dap_chain_cs_block_ton_message_vote_t));
					DAP_DELETE(l_vote);
                }
                dap_chain_global_db_objs_delete(l_objs, l_objs_size);
            }
            pthread_rwlock_unlock(&l_session->rwlock);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE \n");

			dap_chain_cs_block_ton_message_vote_t * l_vote =
										(dap_chain_cs_block_ton_message_vote_t *)&l_message->message;

			if ( l_vote->attempt_number != l_session->attempt_current_number) {
				goto handler_finish;
			}

			dap_chain_hash_fast_t * l_candidate_hash = &l_vote->candidate_hash;
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);

printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE 1 hash:%s\n", l_candidate_hash_str );
	
			pthread_rwlock_rdlock(&l_session->rwlock);
			size_t l_store_size = 0;
			dap_chain_cs_block_ton_store_t * l_store = 
											(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			size_t l_obj_size = 0;
 			dap_global_db_obj_t* l_obj = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_obj_size);

			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				l_store->hdr.vote_count++;
				dap_chain_cs_block_ton_store_t * l_store_gdb = 
									(dap_chain_cs_block_ton_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
				dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
												l_store_size, l_session->gdb_group_store);
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE 2\n");
				if ( ((float)l_store->hdr.vote_count/l_session->validators_count) >= ((float)2/3) ) {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE 3\n");
					// Delete other candidates - ? dont delete if multi-rounds
	                // size_t l_objs_size = 0;
	                // dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_objs_size);
	                // if (l_objs_size) {
	                //     for (size_t i = 0; i < l_objs_size; i++) {
	                //         if (!l_objs[i].value_len)
	                //             continue;
	                //         if ( strcmp(l_candidate_hash_str, l_objs[i].key) != 0 ) {
	                //             dap_chain_global_db_gr_del(dap_strdup(l_objs[i].key), l_session->gdb_group_store);
	                //         }
	                //     }
	                //     dap_chain_global_db_objs_delete(l_objs, l_objs_size);
	                // }
	                // Send PreCommit
					dap_chain_cs_block_ton_message_precommit_t * l_precommit =
														DAP_NEW_Z(dap_chain_cs_block_ton_message_precommit_t);
					l_precommit->round_id.uint64 = l_session->cur_round.id.uint64;
					memcpy(&l_precommit->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
					l_precommit->attempt_number = l_session->attempt_current_number;
					s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT,
					 					(uint8_t*)l_precommit, sizeof(dap_chain_cs_block_ton_message_precommit_t));
					DAP_DELETE(l_precommit);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT: {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT \n");

			dap_chain_cs_block_ton_message_precommit_t * l_precommit =
										(dap_chain_cs_block_ton_message_precommit_t *)&l_message->message;

			if ( l_precommit->attempt_number != l_session->attempt_current_number) {
				goto handler_finish;
			}

			dap_chain_hash_fast_t * l_candidate_hash = &l_precommit->candidate_hash;
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);

			pthread_rwlock_rdlock(&l_session->rwlock);
			size_t l_store_size = 0;
			dap_chain_cs_block_ton_store_t * l_store = 
											(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				l_store->hdr.precommit_count++;
				
				dap_chain_cs_block_ton_store_t * l_store_gdb = 
								(dap_chain_cs_block_ton_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
				if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
													l_store_size, l_session->gdb_group_store) ) {
					if ( ((float)l_store->hdr.precommit_count/l_session->validators_count) >= ((float)2/3) ) {
						// event CommitSign
					    if (l_session->blocks_sign_key) {
							size_t l_candidate_size = l_store->hdr.candidate_size;
							dap_chain_block_t * l_candidate = 
									(dap_chain_block_t * )DAP_DUP_SIZE(&l_store->candidate_n_signs, l_candidate_size);
							size_t l_offset = dap_chain_block_get_sign_offset(l_candidate, l_candidate_size);
						    dap_sign_t *l_candidate_sign = dap_sign_create(l_session->blocks_sign_key,
						    								l_candidate, l_offset + sizeof(l_candidate->hdr), 0);
						    size_t l_candidate_sign_size = dap_sign_get_size(l_candidate_sign);
							
							size_t l_commitsign_size = sizeof(dap_chain_cs_block_ton_message_commitsign_t)+l_candidate_sign_size;
							dap_chain_cs_block_ton_message_commitsign_t * l_commitsign =
													DAP_NEW_SIZE(dap_chain_cs_block_ton_message_commitsign_t, l_commitsign_size);
							l_commitsign->round_id.uint64 = l_session->cur_round.id.uint64;
							memcpy(&l_commitsign->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
							memcpy(l_commitsign->candidate_sign, l_candidate_sign, l_candidate_sign_size);
							s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN,
							 					(uint8_t*)l_commitsign, l_commitsign_size);
							DAP_DELETE(l_commitsign);
							DAP_DELETE(l_candidate);
							DAP_DELETE(l_candidate_sign);
							
							l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS;
							l_session->ts_round_state_commit = (dap_chain_time_t)time(NULL);
						}
						else
							log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-ton] section");	
					}
				}	
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store);
			DAP_DELETE(l_candidate_hash_str);

		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
printf("---!!! s_session_packet_in() DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN \n");

			dap_chain_cs_block_ton_message_commitsign_t * l_commitsign =
										(dap_chain_cs_block_ton_message_commitsign_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_commitsign->candidate_hash;

			pthread_rwlock_unlock(&l_session->rwlock);
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
			size_t l_store_size = 0;
			dap_chain_cs_block_ton_store_t * l_store = 
											(dap_chain_cs_block_ton_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				size_t l_candidate_size = l_store->hdr.candidate_size;
				dap_chain_block_t * l_candidate = 
						(dap_chain_block_t * )DAP_DUP_SIZE(&l_store->candidate_n_signs, l_candidate_size);
				size_t l_offset = dap_chain_block_get_sign_offset(l_candidate, l_candidate_size);

				int l_sign_verified=0;
				// check candidate hash sign
				if ( (l_sign_verified=dap_sign_verify((dap_sign_t*)l_commitsign->candidate_sign,
												l_candidate, l_offset+sizeof(l_candidate->hdr))) == 1 ) {
					l_message->hdr.is_verified = true;

					// size_t l_candidate_sign_size = dap_sign_get_size((dap_sign_t*)l_commitsign->candidate_sign);
					// size_t l_store_size_new = l_store_size+l_candidate_sign_size;
					// l_store = DAP_REALLOC(l_store, l_store_size_new);
					// memcpy(((byte_t *)l_store)+l_store_size, l_commitsign->candidate_sign, l_candidate_sign_size);
					l_store->hdr.sign_count++;

					// dap_chain_cs_block_ton_store_t * l_store_gdb = 
					// 			(dap_chain_cs_block_ton_store_t *)DAP_DUP_SIZE(l_store, l_store_size_new);
					// if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
					// 						l_store_size_new, l_session->gdb_group_store)){
					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
											l_store_size, l_session->gdb_group_store)){
						if ( ((float)l_store->hdr.sign_count/l_session->validators_count) >= ((float)2/3) ) {
							//l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS;
							//s_session_candidate_to_chain(l_session);
							s_session_round_finish(l_session);
						}
					}

				} else {
					// l_message->hdr.is_verified = false;
					log_it(L_WARNING, "Candidate hash sign is incorrect: code %d", l_sign_verified);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store);
			DAP_DELETE(l_candidate_hash_str);

		} break;
		default:
			break;
	}

handler_finish:
	return;
}


static void s_message_send(dap_chain_cs_block_ton_items_t * a_session,
							uint8_t a_message_type, uint8_t *a_data, size_t a_data_size) {
	
	size_t l_message_size = sizeof(dap_chain_cs_block_ton_message_hdr_t)+a_data_size;

	dap_chain_cs_block_ton_message_t * l_message =
										DAP_NEW_Z_SIZE(dap_chain_cs_block_ton_message_t, l_message_size);

	l_message->hdr.id.uint64 = (uint64_t)a_session->cur_round.messages_count;
	l_message->hdr.chain_id.uint64 = a_session->chain->id.uint64;
	l_message->hdr.ts_created = (dap_chain_time_t)time(NULL);
	l_message->hdr.type = a_message_type;
	memcpy(&l_message->message, a_data, a_data_size);
	l_message->hdr.message_size = a_data_size;
	//a_session->messages_count++;

	//dap_chain_cs_block_ton_message_item_t * l_message_items = DAP_NEW_Z(dap_chain_cs_block_ton_message_item_t);
	//l_message_items->message = l_message;

	// save to messages chain
	// dap_chain_hash_fast_t l_message_hash;
	// s_message_chain_add(a_session, NULL, l_message, l_message_size, &l_message_hash);

	//dap_hash_fast(l_message, l_message_size, l_message_hash);
	// dap_hash_fast(l_message, l_message_size, &l_message_items->message_hash);
	// a_session->last_message_hash = &l_message_items->message_hash;

	//HASH_ADD(hh, a_session->messages_items, message_hash, sizeof(l_message_items->message_hash), l_message_items);
	
	dap_chain_net_t * l_net = dap_chain_net_by_id(a_session->chain->net_id);

	memcpy(&l_message->hdr.sender_node_addr,
				dap_chain_net_get_cur_addr(l_net), sizeof(dap_chain_node_addr_t));

	dap_chain_hash_fast_t l_message_hash;
	dap_hash_fast(l_message, l_message_size, &l_message_hash);

	dap_stream_ch_chain_voting_message_write(l_net, a_session->validators_list, &l_message_hash, l_message, l_message_size);
}


static void s_message_chain_add(dap_chain_cs_block_ton_items_t * a_session, dap_chain_node_addr_t * a_sender_node_addr, 
									dap_chain_cs_block_ton_message_t * a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash) {
	
	pthread_rwlock_rdlock(&a_session->rwlock);

	// dap_chain_cs_block_ton_message_t * l_message =
	// 		(dap_chain_cs_block_ton_message_t *)DAP_DUP_SIZE(a_message, a_message_size);
	dap_chain_cs_block_ton_message_t *l_message = a_message;

	l_message->hdr.is_genesis = !a_session->cur_round.last_message_hash ? true : false;
	if (!l_message->hdr.is_genesis) {
		memcpy(&l_message->hdr.prev_message_hash, a_session->cur_round.last_message_hash, sizeof(dap_hash_fast_t));
		//DAP_DELETE(a_session->last_message_hash);
	}
	// if (a_link_hash) {
	// 	memcpy( &l_message->hdr.link_message_hash, a_link_hash, sizeof(dap_chain_hash_fast_t));
	// }

	// if (a_sender_node_addr) {
	// 	// memcpy( &l_message->hdr.sender_node_addr, a_sender_node_addr, sizeof(dap_chain_node_addr_t));
	// 	l_message->hdr.sender_node_addr.uint64 = a_sender_node_addr->uint64;
	// }

	dap_chain_hash_fast_t l_message_hash;
	dap_hash_fast(a_message, a_message_size, &l_message_hash);

	dap_chain_cs_block_ton_message_item_t * l_message_items = DAP_NEW_Z(dap_chain_cs_block_ton_message_item_t);
	l_message_items->message = l_message;

	memcpy( &l_message_items->message_hash, &l_message_hash, sizeof(dap_chain_hash_fast_t));
	a_session->cur_round.last_message_hash = 
			(dap_chain_hash_fast_t*)DAP_DUP_SIZE(&l_message_hash, sizeof(dap_chain_hash_fast_t));
	HASH_ADD(hh, a_session->cur_round.messages_items, message_hash, sizeof(l_message_items->message_hash), l_message_items);

	char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_message_hash);
	// dap_chain_global_db_gr_set(dap_strdup(l_hash_str), (uint8_t *)a_message, a_message_size, a_session->gdb_group_message);

	a_session->cur_round.messages_count++;
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
        log_it(L_CRITICAL,"Ledger is NULL can't check PoS on this chain %s", a_blocks->chain->name);
        return -3;
    }

    if (sizeof(a_block->hdr) >= a_block_size) {
        log_it(L_WARNING,"Incorrect size with block %p on chain %s", a_block, a_blocks->chain->name);
        return  -7;
    }

    size_t l_signs_count = dap_chain_block_get_signs_count(a_block, a_block_size);
    if (l_signs_count < l_ton_pvt->confirmations_minimum) {
        log_it(L_WARNING,"Wrong signature number with block %p on chain %s", a_block, a_blocks->chain->name);
        return -2; // Wrong signatures number
    }

    uint16_t l_verified_num = 0;
    for (size_t l_sig_ton = 0; l_sig_ton < l_signs_count; l_sig_ton++) {
        dap_sign_t *l_sign = dap_chain_block_sign_get(a_block, a_block_size, l_sig_ton);
        if (l_sign == NULL) {
            log_it(L_WARNING, "Block isn't signed with anything: sig ton %zu, event size %zu", l_sig_ton, a_block_size);
            return -4;
        }

        bool l_sign_size_correct = dap_sign_verify_size(l_sign, a_block_size);
        if (!l_sign_size_correct) {
            log_it(L_WARNING, "Block's sign #%zu size is incorrect", l_sig_ton);
            return -44;
        }
        size_t l_block_data_size = dap_chain_block_get_sign_offset(a_block, a_block_size)+sizeof(a_block->hdr);
        if (l_block_data_size == a_block_size) {
            log_it(L_WARNING,"Block has nothing except sign, nothing to verify so I pass it (who knows why we have it?)");
            return 0;
        }

        int l_sign_verified = dap_sign_verify(l_sign, a_block, l_block_data_size);
        if (l_sign_verified != 1) {
            log_it(L_WARNING, "Block's sign is incorrect: code %d", l_sign_verified);
            return -41;
        }

        if (l_sig_ton == 0) {
            dap_chain_addr_t l_addr = {};
            dap_chain_hash_fast_t l_pkey_hash;
            dap_sign_get_pkey_hash(l_sign, &l_pkey_hash);
            dap_chain_addr_fill(&l_addr, l_sign->header.type, &l_pkey_hash, a_blocks->chain->net_id);
            size_t l_datums_count = 0;
            dap_chain_datum_t **l_datums = dap_chain_block_get_datums(a_block, a_block_size, &l_datums_count);
            if (!l_datums || !l_datums_count) {
                log_it(L_WARNING, "No datums in block %p on chain %s", a_block, a_blocks->chain->name);
                return -7;
            }
            for (size_t i = 0; i < l_datums_count; i++) {
                if (!dap_chain_net_srv_stake_validator(&l_addr, l_datums[i])) {
                    log_it(L_WARNING, "Not passed stake validator datum %zu with block %p on chain %s", i, a_block, a_blocks->chain->name);
                    DAP_DELETE(l_datums);
                    return -6;
                }
            }
            DAP_DELETE(l_datums);
        }
    }

    // Check number
    if (l_verified_num >= l_ton_pvt->confirmations_minimum) {
        // Passed all checks
        return 0;
    } else {
        log_it(L_WARNING, "Wrong block: only %hu/%hu signs are valid", l_verified_num, l_ton_pvt->confirmations_minimum);
        return -2;
    }
}




