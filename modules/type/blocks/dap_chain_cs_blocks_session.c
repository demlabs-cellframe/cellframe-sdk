
#include "dap_timerfd.h"
#include "utlist.h"
#include "dap_chain_net.h"
#include "dap_chain_cell.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_blocks_session.h"
#include "dap_stream_ch_chain_voting.h"

#define LOG_TAG "dap_chain_cs_blocks_session"

static void s_session_packet_in(void * a_arg, dap_chain_node_addr_t * a_sender_node_addr, 
								dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size);
static bool s_session_block_submit(dap_chain_cs_blocks_session_items_t *a_session);
static bool s_session_timer();
static int s_session_datums_validation(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);

static void s_message_send(dap_chain_cs_blocks_session_items_t * a_session,
							uint8_t a_message_type, uint8_t *a_data, size_t a_data_size);
static void s_message_chain_add(dap_chain_cs_blocks_session_items_t * a_session, dap_chain_node_addr_t * a_sender_node_addr, 
									dap_chain_cs_blocks_session_message_t * a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash);
static bool s_session_finish(dap_chain_cs_blocks_session_items_t *a_session);
static bool s_session_finish_notstart(dap_chain_cs_blocks_session_items_t *a_session);
// static int s_message_block_sign_add(dap_chain_cs_blocks_session_items_t * a_session,
// 										dap_chain_hash_fast_t *a_block_hash, dap_sign_t *a_sign);

// static char * s_gdb_group_session_store;
// dap_chain_hash_fast_t * s_prev_message_hash = NULL;
static dap_chain_cs_blocks_session_items_t * s_session_items; // double-linked list of chains
static dap_timerfd_t * s_session_cs_timer = NULL; 

int dap_chain_cs_blocks_session_init(dap_chain_t *a_chain, dap_enc_key_t *a_blocks_sign_key)
{

// HASH_ADD(chain); 
// DL_APPEND(l_net->pub.chains, l_chain);

	dap_chain_cs_blocks_session_items_t * l_session = DAP_NEW_Z(dap_chain_cs_blocks_session_items_t);
// l_session->gdb_group_store = dap_strdup_printf("local.ton.setup");

// time session
// attempts in round
// attempt time
// rounds count -> max round -> change validator

	l_session->round_id.uint64 = 1;
	l_session->gdb_group_store = dap_strdup_printf("local.ton.%s.%s.round.%llu.store", 
										a_chain->net_name, a_chain->name, l_session->round_id.uint64);
	l_session->gdb_group_message = dap_strdup_printf("local.ton.%s.%s.round.%llu.message",
										a_chain->net_name, a_chain->name, l_session->round_id.uint64);
	l_session->chain = a_chain;
	l_session->last_message_hash = NULL;
	l_session->messages_count = 0;
	
	l_session->consensus_start = 2; // hint: if((time()/10) % consensus_start)==0
	l_session->startsync_count = 0;
	l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE;

	
	l_session->validators_count = 2; // conf
	l_session->blocks_sign_key = a_blocks_sign_key;

	// l_session->cs_timer = dap_timerfd_start(60*1000, 
	// 					                        (dap_timerfd_callback_t)s_session_check, 
	// 					                        	l_session);

	pthread_rwlock_init(&l_session->rwlock, NULL);

	DL_APPEND(s_session_items, l_session);
	if (!s_session_cs_timer) {
		s_session_cs_timer = dap_timerfd_start(10*1000, 
                        (dap_timerfd_callback_t)s_session_timer, 
                        NULL);
	}
	dap_stream_ch_chain_voting_in_callback_add(l_session, s_session_packet_in);
	return 0;
}

static bool s_session_timer() {
	dap_chain_time_t l_time = (dap_chain_time_t)time(NULL);
	dap_chain_cs_blocks_session_items_t * l_session = NULL;
	DL_FOREACH(s_session_items, l_session) {
		if ( ((l_time/10) % l_session->consensus_start) == 0 ) {
			if ( l_session->state == DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE ) {
				l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START;
				dap_chain_cs_blocks_session_message_startsync_t * l_startsync =
														DAP_NEW_Z(dap_chain_cs_blocks_session_message_startsync_t);
				l_startsync->ts = (dap_chain_time_t)time(NULL);
				s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC, 
										(uint8_t*)l_startsync, sizeof(dap_chain_cs_blocks_session_message_startsync_t));
			}
		}
	}

	return true;
}

// static void s_session_start (dap_chain_cs_blocks_session_items_t * a_session) {
// 	dap_chain_time_t l_time = (dap_chain_time_t)time(NULL);
// }

static bool s_session_block_submit(dap_chain_cs_blocks_session_items_t *a_session){

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

    if (!l_blocks->block_new)
    	return false; // for timer

	size_t l_submit_size = sizeof(dap_chain_cs_blocks_session_message_submit_t)+l_blocks->block_new_size;
	dap_chain_cs_blocks_session_message_submit_t * l_submit =
							DAP_NEW_SIZE(dap_chain_cs_blocks_session_message_submit_t, l_submit_size);
	
	dap_chain_hash_fast_t l_candidate_hash;
	dap_hash_fast(l_blocks->block_new, l_blocks->block_new_size, &l_candidate_hash);

	l_submit->candidate_size = l_blocks->block_new_size;
	memcpy(&l_submit->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
	memcpy(l_submit->candidate, l_blocks->block_new, l_blocks->block_new_size);

	s_message_send(a_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT, (uint8_t*)l_submit, l_submit_size);

	DAP_DELETE(l_blocks->block_new);
	l_blocks->block_new = NULL;
	l_blocks->block_new_size = 0;

    //return true;
    return false; // for timer
}


static int s_session_datums_validation(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size){
	// a_blocks->chain->ledger
	// dap_chain_ledger_tx_add_check(dap_ledger_t *a_ledger, dap_chain_datum_tx_t *a_tx);

	return 0;

	size_t l_datums_count = 0;
	dap_chain_datum_t **l_datums = dap_chain_block_get_datums(a_block, a_block_size, &l_datums_count);

    if (!l_datums || !l_datums_count) {
        //log_it(L_WARNING, "No datums in block %p on chain %s", a_block, a_blocks->chain->name);
        return -2;
    }

    for(size_t i=0; i<l_datums_count; i++){
    	dap_chain_datum_t *l_datum = l_datums[i];
    	switch (l_datum->header.type_id) {
    		case DAP_CHAIN_DATUM_TX: {
    			dap_chain_datum_tx_t *l_tx = (dap_chain_datum_tx_t*) l_datum->data;
    			int ret = dap_chain_ledger_tx_add_check(a_blocks->chain->ledger, l_tx);
    			if (ret != 0) {
    				return -1;
    			}
    		}
    	}
    }

    return 0;
}

static bool s_session_finish_notstart(dap_chain_cs_blocks_session_items_t *a_session) {
	if ( a_session->state == DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START ) {
		s_session_finish(a_session);
	}
	return false;
}

static bool s_session_finish(dap_chain_cs_blocks_session_items_t *a_session) {

	if ( a_session->state == DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC ){
		// {...} if exists candidate check sign and save to chain
	}

	a_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE;
	a_session->last_message_hash = NULL;
	a_session->messages_count = 0;
	a_session->startsync_count = 0;

    size_t l_objs_size = 0;
    dap_global_db_obj_t *l_objs;
	// delete all candidate
    l_objs = dap_chain_global_db_gr_load(a_session->gdb_group_store, &l_objs_size);
    if (l_objs_size) {
        for (size_t i = 0; i < l_objs_size; i++) {
            if (!l_objs[i].value_len)
                continue;
        }
        dap_chain_global_db_objs_delete(l_objs, l_objs_size);
    }

	// delete messages chain
    l_objs = dap_chain_global_db_gr_load(a_session->gdb_group_message, &l_objs_size);
    if (l_objs_size) {
        for (size_t i = 0; i < l_objs_size; i++) {
            if (!l_objs[i].value_len)
                continue;
        }
        dap_chain_global_db_objs_delete(l_objs, l_objs_size);
    }

    dap_chain_cs_blocks_session_message_item_t *l_message_item=NULL, *l_message_tmp=NULL;
    HASH_ITER(hh, a_session->messages_items, l_message_item, l_message_tmp) {
        HASH_DEL(a_session->messages_items, l_message_item);
        DAP_DELETE(l_message_item->message);
        DAP_DELETE(l_message_item);
    }
	return false;
}

static void s_session_packet_in(void * a_arg, dap_chain_node_addr_t * a_sender_node_addr, 
								dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size) {

	dap_chain_cs_blocks_session_items_t * l_session = (dap_chain_cs_blocks_session_items_t *)a_arg;

	dap_chain_cs_blocks_session_message_t * l_message = (dap_chain_cs_blocks_session_message_t *)a_data;
	//char * l_message_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_message->hdr.message_hash);

    dap_chain_hash_fast_t l_data_hash;
    dap_hash_fast(a_data, a_data_size, &l_data_hash);
	
    if (l_message->hdr.chain_id.uint64 != l_session->chain->id.uint64 )
    	goto handler_finished;

	if (memcmp(a_data_hash, &l_data_hash, sizeof(dap_chain_hash_fast_t)) != 0)
		goto handler_finished;

	if ( l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC ) {
		// add check&save sender addr
		l_session->startsync_count++;
		if ( ((float)l_session->startsync_count/l_session->validators_count) >= ((float)2/3) ) {
			l_session->state = DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC;
			dap_timerfd_start(3*1000, // pause before candidate submit
                    (dap_timerfd_callback_t)s_session_block_submit, 
                    	l_session);

			dap_timerfd_start((3+30)*1000, // consensus timeout
                    (dap_timerfd_callback_t)s_session_finish, 
                    	l_session);
		}
		dap_timerfd_start( 10*1000, // timer chancel consensus 
                (dap_timerfd_callback_t)s_session_finish_notstart, 
                	l_session);
		goto handler_finished;
	}


	if ( l_session->state != DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC )
		goto handler_finished;

	// check hash message dup
	dap_chain_cs_blocks_session_message_item_t * l_message_item_temp = NULL;
	HASH_FIND(hh, l_session->messages_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_message_item_temp);
	if (l_message_item_temp)
		goto handler_finished;

    uint32_t l_approve_count = 0, l_vote_count = 0, l_precommit_count = 0;
	// check messages chain
    dap_chain_cs_blocks_session_message_item_t *l_message_item=NULL, *l_message_tmp=NULL;
    HASH_ITER(hh, l_session->messages_items, l_message_item, l_message_tmp) {
    	if (l_message_item->message->hdr.sender_node_addr.uint64 == a_sender_node_addr->uint64) {
    		dap_chain_hash_fast_t * l_candidate_hash_cur = 
    			&((dap_chain_cs_blocks_session_message_gethash_t *)l_message->message)->candidate_hash;

    		dap_chain_hash_fast_t * l_candidate_hash = 
    			&((dap_chain_cs_blocks_session_message_gethash_t *)l_message_item->message->message)->candidate_hash;

    		bool l_candidate_hash_match = (memcmp(l_candidate_hash_cur, l_candidate_hash,
															sizeof(dap_chain_hash_fast_t)) == 0);

    		uint8_t l_msg_type = l_message_item->message->hdr.type;

    		// search & check messages from this validator 
    		switch (l_msg_type) {
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
    				// if (l_candidate_hash_match)
    				// 	l_approve_count++;
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
					if ( l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE ||
							l_message->hdr.type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT ) {
						// check dup message APPROVE or REJECT for one candidate
						if (l_candidate_hash_match) {
							goto handler_finished;
						}
					}
    			} break;
    			// this messages should only appear once per attempt
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: 
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT:{
    				if ( l_msg_type == l_message->hdr.type ){
    					goto handler_finished;
    				}
    			}
    		}

    		// count messages in chain for this candidate
    		if (l_candidate_hash_match)
	    		switch (l_msg_type) {
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

	// check message chain is correct
	switch (l_message->hdr.type) {
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
			if (!l_approve_count) // if this validator not sent Approve for this candidate
    			goto handler_finished;
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT: {
			if (!l_vote_count) // if this validator not sent Vote for this candidate
    			goto handler_finished;
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
			if (!l_precommit_count) // if this validator not sent PreCommit for this candidate
    			goto handler_finished;
		} break;
	}

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
			int ret = 0;
			dap_chain_cs_blocks_session_message_submit_t * l_submit =
										(dap_chain_cs_blocks_session_message_submit_t *)&l_message->message;

			size_t l_candidate_size = l_submit->candidate_size;
			dap_chain_block_t * l_candidate = (dap_chain_block_t *)l_submit->candidate;

			dap_chain_hash_fast_t l_candidate_hash;
			dap_hash_fast(l_candidate, l_candidate_size, &l_candidate_hash);
			
			// check candidate hash
			if (memcmp(&l_submit->candidate_hash, &l_candidate_hash,
											sizeof(dap_chain_hash_fast_t)) != 0) {
				goto handler_finished;				
			}

			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_candidate_hash);

			// check block exist in store
			size_t l_store_temp_size = 0;
			dap_chain_cs_blocks_session_store_t * l_store_temp = 
											(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_temp_size, l_session->gdb_group_store);
			if (l_store_temp) {
				DAP_DELETE(l_store_temp);
				DAP_DELETE(l_candidate_hash_str);
				goto handler_finished;
			}

			pthread_rwlock_rdlock(&l_session->rwlock);

			// save to messages chain
			// dap_chain_hash_fast_t l_message_hash;
			// s_message_chain_add(l_session, a_sender_node_addr, l_message, a_data_size, &l_message_hash);

			dap_chain_net_t * l_net = dap_chain_net_by_id( l_session->chain->net_id);	
			
			// dap_chain_block_t * l_candidate = (dap_chain_block_t *)l_message_data;

			if ( !(ret = s_session_datums_validation(l_blocks, l_candidate, l_candidate_size)) ) {
			    size_t l_store_size = sizeof(dap_chain_cs_blocks_session_store_hdr_t)+a_data_size;
			    dap_chain_cs_blocks_session_store_t * l_store = 
			    						DAP_NEW_Z_SIZE(dap_chain_cs_blocks_session_store_t, l_store_size);
			    l_store->hdr.sign_count = 0;
			    l_store->hdr.approve_count = 0;
			    l_store->hdr.reject_count = 0;
			    l_store->hdr.vote_count = 0;
			    l_store->hdr.candidate_size = l_candidate_size;
			    // l_store->hdr.approve_count = 1;

			    memcpy( &l_store->candidate_n_signs, l_candidate, l_candidate_size);
				if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
														l_store_size, l_session->gdb_group_store) ) {
					// event Approve
				    if (l_session->blocks_sign_key) {
						size_t l_candidate_size = l_store->hdr.candidate_size;
					    dap_sign_t *l_hash_sign = dap_sign_create(l_session->blocks_sign_key,
					    								&l_candidate_hash, sizeof(dap_chain_hash_fast_t), 0);

					    size_t l_hash_sign_size = dap_sign_get_size(l_hash_sign);
						size_t l_approve_size = sizeof(dap_chain_cs_blocks_session_message_approve_t)+l_hash_sign_size;

						dap_chain_cs_blocks_session_message_approve_t * l_approve =
												DAP_NEW_SIZE(dap_chain_cs_blocks_session_message_approve_t, l_approve_size);
					
						memcpy(&l_approve->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
						memcpy(l_approve->candidate_hash_sign, l_hash_sign, l_hash_sign_size);

						s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE,
															(uint8_t*)l_approve, l_approve_size);
					}
					else
						log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-pos] section");	
				}
			}
			else {
				// event Reject
				dap_chain_cs_blocks_session_message_reject_t * l_reject =
														DAP_NEW_Z(dap_chain_cs_blocks_session_message_reject_t);
				memcpy(&l_reject->candidate_hash, &l_candidate_hash, sizeof(dap_chain_hash_fast_t));
				s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT,
						(uint8_t*)l_reject, sizeof(dap_chain_cs_blocks_session_message_reject_t));
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store_temp);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {

			dap_chain_cs_blocks_session_message_reject_t * l_reject =
										(dap_chain_cs_blocks_session_message_reject_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_reject->candidate_hash;
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
		
			pthread_rwlock_rdlock(&l_session->rwlock);
			size_t l_store_size = 0;
			dap_chain_cs_blocks_session_store_t * l_store = 
											(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				l_store->hdr.reject_count++;
				if ( ((float)l_store->hdr.reject_count/l_session->validators_count) < ((float)2/3) ) {
					dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
													l_store_size, l_session->gdb_group_store);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE: {	
			dap_chain_cs_blocks_session_message_approve_t * l_approve =
										(dap_chain_cs_blocks_session_message_approve_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_approve->candidate_hash;

			// size_t l_sign_size = dap_sign_get_size(l_approve->candidate_hash_sign);
			// dap_sign_t *l_hash_sign = DAP_NEW_SIZE(dap_sign_t, l_sign_size);
			// memcpy(l_hash_sign, l_approve->candidate_hash_sign, l_sign_size);

			int l_sign_verified=0;
			// check candidate hash sign
			if ( (l_sign_verified=dap_sign_verify( (dap_sign_t*)l_approve->candidate_hash_sign, l_candidate_hash, sizeof(dap_chain_hash_fast_t))) == 1 ) {
				pthread_rwlock_rdlock(&l_session->rwlock);
				char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
				size_t l_store_size = 0;
				dap_chain_cs_blocks_session_store_t * l_store = 
												(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
															l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
				if (l_store) {
					dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
					l_store->hdr.approve_count++;

					dap_chain_cs_blocks_session_store_t * l_store_gdb = 
									(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
														l_store_size, l_session->gdb_group_store) )
						if ( ((float)l_store->hdr.approve_count/l_session->validators_count) >= ((float)2/3) ) {
							// event Vote
							dap_chain_cs_blocks_session_message_vote_t * l_vote =
																DAP_NEW_Z(dap_chain_cs_blocks_session_message_vote_t);
							memcpy(&l_vote->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
							s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE,
							 					(uint8_t*)l_vote, sizeof(dap_chain_cs_blocks_session_message_vote_t));
						}
				}
				pthread_rwlock_unlock(&l_session->rwlock);
				DAP_DELETE(l_store);
				DAP_DELETE(l_candidate_hash_str);
			} else {
				log_it(L_WARNING, "Candidate hash sign is incorrect: code %d", l_sign_verified);
			}
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
			dap_chain_cs_blocks_session_message_vote_t * l_vote =
										(dap_chain_cs_blocks_session_message_vote_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_vote->candidate_hash;
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
			
			pthread_rwlock_rdlock(&l_session->rwlock);
			size_t l_store_size = 0;
			dap_chain_cs_blocks_session_store_t * l_store = 
											(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			
			size_t l_obj_size = 0;
 			dap_global_db_obj_t* l_obj = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_obj_size);

			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				l_store->hdr.vote_count++;
				dap_chain_cs_blocks_session_store_t * l_store_gdb = 
									(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
				dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
												l_store_size, l_session->gdb_group_store);
				
				if ( ((float)l_store->hdr.vote_count/l_session->validators_count) >= ((float)2/3) ) {
					// Delete other candidates - ? dont delete if multi-rounds
	                size_t l_objs_size = 0;
	                dap_global_db_obj_t *l_objs = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_objs_size);
	                if (l_objs_size) {
	                    for (size_t i = 0; i < l_objs_size; i++) {
	                        if (!l_objs[i].value_len)
	                            continue;
	                        if ( strcmp(l_candidate_hash_str, l_objs[i].key) != 0 ) {
	                            dap_chain_global_db_gr_del(dap_strdup(l_objs[i].key), l_session->gdb_group_store);
	                        }
	                    }
	                    dap_chain_global_db_objs_delete(l_objs, l_objs_size);
	                }
	                // Send PreCommit
					dap_chain_cs_blocks_session_message_precommit_t * l_precommit =
														DAP_NEW_Z(dap_chain_cs_blocks_session_message_precommit_t);
					memcpy(&l_precommit->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
					s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT,
					 					(uint8_t*)l_precommit, sizeof(dap_chain_cs_blocks_session_message_precommit_t));
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT: {
			dap_chain_cs_blocks_session_message_precommit_t * l_precommit =
										(dap_chain_cs_blocks_session_message_precommit_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_precommit->candidate_hash;
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);

			pthread_rwlock_rdlock(&l_session->rwlock);
			size_t l_store_size = 0;
			dap_chain_cs_blocks_session_store_t * l_store = 
											(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				l_store->hdr.precommit_count++;
				
				dap_chain_cs_blocks_session_store_t * l_store_gdb = 
								(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
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
							
							size_t l_commitsign_size = sizeof(dap_chain_cs_blocks_session_message_commitsign_t)+l_candidate_sign_size;
							dap_chain_cs_blocks_session_message_commitsign_t * l_commitsign =
													DAP_NEW_SIZE(dap_chain_cs_blocks_session_message_commitsign_t, l_commitsign_size);
						
							memcpy(&l_commitsign->candidate_hash, l_candidate_hash, sizeof(dap_chain_hash_fast_t));
							memcpy(l_commitsign->candidate_sign, l_candidate_sign, l_candidate_sign_size);
							s_message_send(l_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN,
							 					(uint8_t*)l_commitsign, l_commitsign_size);
							DAP_DELETE(l_candidate);
							DAP_DELETE(l_candidate_sign);
						}
						else
							log_it(L_WARNING, "Can't sign block with blocks-sign-cert in [block-pos] section");	
					}
				}	
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store);
			DAP_DELETE(l_candidate_hash_str);

		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
			dap_chain_cs_blocks_session_message_commitsign_t * l_commitsign =
										(dap_chain_cs_blocks_session_message_commitsign_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_commitsign->candidate_hash;

			pthread_rwlock_unlock(&l_session->rwlock);
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);
			size_t l_store_size = 0;
			dap_chain_cs_blocks_session_store_t * l_store = 
											(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
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

					size_t l_candidate_sign_size = dap_sign_get_size((dap_sign_t*)l_commitsign->candidate_sign);
					size_t l_store_size_new = l_store_size+l_candidate_sign_size;
					l_store = DAP_REALLOC(l_store, l_store_size_new);
					memcpy(((byte_t *)l_store)+l_store_size, l_commitsign->candidate_sign, l_candidate_sign_size);
					l_store->hdr.sign_count++;

					dap_chain_cs_blocks_session_store_t * l_store_gdb = 
								(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size_new);

					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
											l_store_size_new, l_session->gdb_group_store)){

					}

				} else {
					log_it(L_WARNING, "Candidate hash sign is incorrect: code %d", l_sign_verified);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_store);
			DAP_DELETE(l_candidate_hash_str);

		} break;
		// case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR: {
		// } break;
		default:
			break;
	}

handler_finished:
	DAP_DELETE(a_sender_node_addr);
	DAP_DELETE(a_data_hash);
	DAP_DELETE(a_data);
}


static void s_message_send(dap_chain_cs_blocks_session_items_t * a_session,
							uint8_t a_message_type, uint8_t *a_data, size_t a_data_size) {
	
	size_t l_message_size = sizeof(dap_chain_cs_blocks_session_message_hdr_t)+a_data_size;

	dap_chain_cs_blocks_session_message_t * l_message =
										DAP_NEW_Z_SIZE(dap_chain_cs_blocks_session_message_t, l_message_size);

	l_message->hdr.id.uint64 = (uint64_t)a_session->messages_count;
	l_message->hdr.chain_id.uint64 = a_session->chain->id.uint64;
	l_message->hdr.ts_created = (dap_chain_time_t)time(NULL);
	l_message->hdr.type = a_message_type;
	memcpy(&l_message->message, a_data, a_data_size);
	l_message->hdr.message_size = a_data_size;
	//a_session->messages_count++;

	//dap_chain_cs_blocks_session_message_item_t * l_message_items = DAP_NEW_Z(dap_chain_cs_blocks_session_message_item_t);
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

	dap_stream_ch_chain_voting_message_write(l_net, &l_message_hash, l_message, l_message_size);

	DAP_DELETE(a_data);
}


static void s_message_chain_add(dap_chain_cs_blocks_session_items_t * a_session, dap_chain_node_addr_t * a_sender_node_addr, 
									dap_chain_cs_blocks_session_message_t * a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash) {
	
	pthread_rwlock_rdlock(&a_session->rwlock);

	dap_chain_cs_blocks_session_message_t * l_message =
			(dap_chain_cs_blocks_session_message_t *)DAP_DUP_SIZE(a_message, a_message_size);

	l_message->hdr.is_genesis = !a_session->last_message_hash ? true : false;
	if (!l_message->hdr.is_genesis) {
		memcpy(&l_message->hdr.prev_message_hash, a_session->last_message_hash, sizeof(dap_hash_fast_t));
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

	dap_chain_cs_blocks_session_message_item_t * l_message_items = DAP_NEW_Z(dap_chain_cs_blocks_session_message_item_t);
	l_message_items->message = l_message;

	memcpy( &l_message_items->message_hash, &l_message_hash, sizeof(dap_chain_hash_fast_t));
	a_session->last_message_hash = &l_message_hash;
	HASH_ADD(hh, a_session->messages_items, message_hash, sizeof(l_message_items->message_hash), l_message_items);

	char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_message_hash);
	// dap_chain_global_db_gr_set(dap_strdup(l_hash_str), (uint8_t *)a_message, a_message_size, a_session->gdb_group_message);

	a_session->messages_count++;
	memcpy( a_message_hash, &l_message_hash, sizeof(dap_chain_hash_fast_t));

	pthread_rwlock_unlock(&a_session->rwlock);
}


// static int s_message_block_sign_add(dap_chain_cs_blocks_session_items_t * a_session,
// 										dap_chain_hash_fast_t *a_block_hash, dap_sign_t *a_sign){

// 	int ret = -1;
// 	size_t l_session_store_size = 0;
// 	char * l_block_hash_str = dap_chain_hash_fast_to_str_new(a_block_hash);
//     dap_chain_cs_blocks_session_store_t *l_store = 
//                 (dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(l_block_hash_str, 
//                 									&l_session_store_size, a_session->gdb_group_store );
//     if (l_store) {
//     	dap_chain_global_db_gr_del(dap_strdup(l_block_hash_str), a_session->gdb_group_store);
//     }

//     // size_t l_sign_offset = l_session_store->hdr.candidate_size;
//     size_t l_sign_size = dap_sign_get_size(a_sign);
//     // dap_chain_hash_fast_t l_pkey_hash = {};
//     // dap_sign_get_pkey_hash(a_sign, &l_pkey_hash);
//     // dap_chain_addr_t l_addr = {};
//     // dap_chain_addr_fill(&l_addr, a_sign->header.type, &l_pkey_hash, l_session->chain->net_id);

// 	l_store = DAP_REALLOC(l_store, l_session_store_size+l_sign_size);
// 	memcpy(((byte_t *)l_store)+l_session_store_size, a_sign, l_sign_size);
// 	l_store->hdr.sign_count = 0;

// 	if (dap_chain_global_db_gr_set(dap_strdup(l_block_hash_str), l_store,
// 										l_session_store_size+l_sign_size, a_session->gdb_group_store) ) {
// 		ret = 0;
// 	}

// 	return ret;
// }






