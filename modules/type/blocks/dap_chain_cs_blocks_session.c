
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
static bool s_session_check(dap_chain_cs_blocks_session_items_t *a_session);
static bool s_session_timer();
static int s_session_datums_validation(dap_chain_cs_blocks_t *a_blocks, dap_chain_block_t *a_block, size_t a_block_size);

static void s_message_send(dap_chain_cs_blocks_session_items_t * a_session,
							uint8_t a_message_type, uint8_t *a_data, size_t a_data_size);
static void s_message_chain_add(dap_chain_cs_blocks_session_items_t * a_session, dap_chain_node_addr_t * a_sender_node_addr, 
									dap_chain_cs_blocks_session_message_t * a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash);
// static int s_message_block_sign_add(dap_chain_cs_blocks_session_items_t * a_session,
// 										dap_chain_hash_fast_t *a_block_hash, dap_sign_t *a_sign);

// messages
typedef struct dap_chain_cs_blocks_session_message_approve {
	dap_chain_hash_fast_t candidate_hash;
	uint8_t candidate_hash_sign[];
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_approve_t;

typedef struct dap_chain_cs_blocks_session_message_reject {
	dap_chain_hash_fast_t candidate_hash;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_reject_t;

typedef struct dap_chain_cs_blocks_session_message_votefor {
	dap_chain_hash_fast_t candidate_hash;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_votefor_t;

typedef struct dap_chain_cs_blocks_session_message_vote {
	dap_chain_hash_fast_t candidate_hash;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_vote_t;

typedef struct dap_chain_cs_blocks_session_message_precommit {
	dap_chain_hash_fast_t candidate_hash;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_precommit_t;

typedef struct dap_chain_cs_blocks_session_message_commitsign {
	dap_chain_hash_fast_t candidate_hash;
	uint8_t candidate_sign[];
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_commitsign_t;

// static char * s_gdb_group_session_store;
// dap_chain_hash_fast_t * s_prev_message_hash = NULL;
static dap_chain_cs_blocks_session_items_t * s_session_items; // double-linked list of chains
static dap_timerfd_t * s_session_cs_timer = NULL; 

int dap_chain_cs_blocks_session_init(dap_chain_t *a_chain, dap_enc_key_t *a_blocks_sign_key)
{
    printf("---!!! dap_chain_cs_blocks_session_init() 1 \n");

// HASH_ADD(chain); // список текущих консенсусов по чейнам (session)
// DL_APPEND(l_net->pub.chains, l_chain);

	dap_chain_cs_blocks_session_items_t * l_session = DAP_NEW_Z(dap_chain_cs_blocks_session_items_t);
	l_session->gdb_group_store = dap_strdup_printf("local.%s.%s.cs.block.store", a_chain->net_name, a_chain->name );
	l_session->gdb_group_message = dap_strdup_printf("local.%s.%s.cs.block.message", a_chain->net_name, a_chain->name );
	l_session->chain = a_chain;
	l_session->last_message_hash = NULL;
	l_session->messages_count = 0;
	l_session->validators_count = 2;
	l_session->blocks_sign_key = a_blocks_sign_key;
	// l_session->cs_timer = dap_timerfd_start(60*1000, 
	// 					                        (dap_timerfd_callback_t)s_session_check, 
	// 					                        	l_session);

	pthread_rwlock_init(&l_session->rwlock, NULL);

	DL_APPEND(s_session_items, l_session);
	if (!s_session_cs_timer) {
		s_session_cs_timer = dap_timerfd_start(20*1000, 
                        (dap_timerfd_callback_t)s_session_timer, 
                        NULL);
	}
	dap_stream_ch_chain_voting_in_callback_add(l_session, s_session_packet_in);
	return 0;
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
// printf("---!!! test_V s_session_datums_validation() ~~~ ret:%d\n", ret);
    			if (ret != 0) {
    				return -1;
    			}
    		}
    	}
    }

    return 0;
}

static void s_session_packet_in(void * a_arg, dap_chain_node_addr_t * a_sender_node_addr, 
								dap_chain_hash_fast_t *a_data_hash, uint8_t *a_data, size_t a_data_size) {

	dap_chain_cs_blocks_session_items_t * l_session = (dap_chain_cs_blocks_session_items_t *)a_arg;

	dap_chain_cs_blocks_session_message_t * l_message = (dap_chain_cs_blocks_session_message_t *)a_data;
	//char * l_message_hash_hex_str = dap_chain_hash_fast_to_str_new(&l_message->hdr.message_hash);

    dap_chain_hash_fast_t l_data_hash;
    dap_hash_fast(a_data, a_data_size, &l_data_hash);

printf("---!!! s_session_packet_in() TEST PACKET 1 %d type:%d \n", DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE, l_message->hdr.type);
	
    if (l_message->hdr.chain_id.uint64 != l_session->chain->id.uint64 )
    	goto check_err;

printf("---!!! s_session_packet_in() TEST PACKET 2\n");

	if (memcmp(a_data_hash, &l_data_hash, sizeof(dap_chain_hash_fast_t)) != 0)
		goto check_err;

printf("---!!! s_session_packet_in() TEST PACKET 3\n");

	// check hash message dup
	dap_chain_cs_blocks_session_message_item_t * l_message_item_temp = NULL;
	HASH_FIND(hh, l_session->messages_items, a_data_hash, sizeof(dap_chain_hash_fast_t), l_message_item_temp);
	if (l_message_item_temp)
		goto check_err;

printf("---!!! s_session_packet_in() TEST PACKET 4\n");
	// check message dup
    dap_chain_cs_blocks_session_message_item_t *l_message_item=NULL, *l_message_tmp=NULL;
    HASH_ITER(hh, l_session->messages_items, l_message_item, l_message_tmp) {
    	if (l_message_item->message->hdr.sender_node_addr.uint64 == a_sender_node_addr->uint64) {
    		uint8_t l_msg_type = l_message_item->message->hdr.type;
    		switch (l_msg_type) {
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT: {
					dap_chain_cs_blocks_session_message_approve_t * l_approve =
											(dap_chain_cs_blocks_session_message_approve_t *)&l_message->message;
					dap_chain_cs_blocks_session_message_approve_t * l_approve_new =
											(dap_chain_cs_blocks_session_message_approve_t *)&l_message_item->message->message;
					if ( l_msg_type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE ||
							l_msg_type == DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT ) {
						// check dup message APPROVE or REJECT for one candidate
						if (memcmp(&l_approve->candidate_hash, &l_approve_new->candidate_hash,
																sizeof(dap_chain_hash_fast_t)) == 0)
							goto check_err;
					}
    			} break;
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT:
    			case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN: {
    				if ( l_msg_type == l_message->hdr.type ){
    					goto check_err;
    				}
    			}
    		}
    	}
    }

printf("---!!! s_session_packet_in() TEST PACKET 5\n");

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
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT addr:%llu \n", a_sender_node_addr->uint64);
			int ret = 0;

			dap_chain_block_t * l_candidate = (dap_chain_block_t *)&l_message->message;
			size_t l_candidate_size = l_message->hdr.message_size;	
			dap_chain_hash_fast_t l_candidate_hash;
			dap_hash_fast(l_candidate, l_candidate_size, &l_candidate_hash);
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(&l_candidate_hash);

			// check block exist in store
			size_t l_store_temp_size = 0;
			dap_chain_cs_blocks_session_store_t * l_store_temp = 
											(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_temp_size, l_session->gdb_group_store);
			if (l_store_temp) {
				DAP_DELETE(l_store_temp);
				DAP_DELETE(l_candidate_hash_str);
				break;
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
			    l_store->hdr.signs_count = 0;
			    l_store->hdr.approves_count = 0;
			    l_store->hdr.rejects_count = 0;
			    l_store->hdr.votes_count = 0;
			    l_store->hdr.candidate_size = l_candidate_size;
			    // l_store->hdr.approve_count = 1;

printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT 1 approves_count:%u rejects_count:%u votes_count:%u \n",
										l_store->hdr.approves_count, l_store->hdr.rejects_count, l_store->hdr.votes_count);

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
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT addr:%llu \n", a_sender_node_addr->uint64);

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
				l_store->hdr.rejects_count++;
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT approves_count:%u rejects_count:%u votes_count:%u \n",
										l_store->hdr.approves_count, l_store->hdr.rejects_count, l_store->hdr.votes_count);
				if ( ((float)l_store->hdr.rejects_count/l_session->validators_count) < ((float)2/3) ) {
					dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store,
													l_store_size, l_session->gdb_group_store);
				}
			}
			pthread_rwlock_unlock(&l_session->rwlock);
			DAP_DELETE(l_candidate_hash_str);
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE: {
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE addr:%llu \n", a_sender_node_addr->uint64);
			
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
					l_store->hdr.approves_count++;
	printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE approves_count:%u rejects_count:%u votes_count:%u \n",
											l_store->hdr.approves_count, l_store->hdr.rejects_count, l_store->hdr.votes_count);
					
					dap_chain_cs_blocks_session_store_t * l_store_gdb = 
									(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
														l_store_size, l_session->gdb_group_store) )
						if ( ((float)l_store->hdr.approves_count/l_session->validators_count) >= ((float)2/3) ) {
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
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE sign is incorrect: code %d ssize:%d\n", 
	l_sign_verified, dap_sign_get_size( (dap_sign_t*)l_approve->candidate_hash_sign ) );
				log_it(L_WARNING, "Candidate hash sign is incorrect: code %d", l_sign_verified);
			}
		} break;
		case DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE: {
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE addr:%llu \n", a_sender_node_addr->uint64);
			dap_chain_cs_blocks_session_message_vote_t * l_vote =
										(dap_chain_cs_blocks_session_message_vote_t *)&l_message->message;
			dap_chain_hash_fast_t * l_candidate_hash = &l_vote->candidate_hash;
			char * l_candidate_hash_str = dap_chain_hash_fast_to_str_new(l_candidate_hash);

//printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE hash:%s| \n", l_candidate_hash_str);
			
			pthread_rwlock_rdlock(&l_session->rwlock);
			size_t l_store_size = 0;
			dap_chain_cs_blocks_session_store_t * l_store = 
											(dap_chain_cs_blocks_session_store_t *)dap_chain_global_db_gr_get(
														l_candidate_hash_str, &l_store_size, l_session->gdb_group_store);
			
			size_t l_obj_size = 0;
 			dap_global_db_obj_t* l_obj = dap_chain_global_db_gr_load(l_session->gdb_group_store, &l_obj_size);
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE objs:%d| gdb:%s \n", l_obj_size, l_session->gdb_group_store);

			if (l_store) {
				dap_chain_global_db_gr_del(dap_strdup(l_candidate_hash_str), l_session->gdb_group_store);
				l_store->hdr.votes_count++;
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE approves_count:%u rejects_count:%u votes_count:%u \n",
										l_store->hdr.approves_count, l_store->hdr.rejects_count, l_store->hdr.votes_count);
				dap_chain_cs_blocks_session_store_t * l_store_gdb = 
									(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
				dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
												l_store_size, l_session->gdb_group_store);
				
				if ( ((float)l_store->hdr.votes_count/l_session->validators_count) >= ((float)2/3) ) {
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE 2/3 PASSED\n");
					// Delete other candidates
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
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT addr:%llu \n", a_sender_node_addr->uint64);
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
				l_store->hdr.precommits_count++;
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT approves_count:%u rejects_count:%u votes_count:%u precommits_count:%d \n",
						l_store->hdr.approves_count, l_store->hdr.rejects_count, l_store->hdr.votes_count, l_store->hdr.precommits_count );
				
				dap_chain_cs_blocks_session_store_t * l_store_gdb = 
								(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size);
				if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
													l_store_size, l_session->gdb_group_store) ) {
					if ( ((float)l_store->hdr.precommits_count/l_session->validators_count) >= ((float)2/3) ) {
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT 2/3 PASSED\n");
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
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN addr:%llu \n", a_sender_node_addr->uint64);
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
					l_store->hdr.signs_count++;

					dap_chain_cs_blocks_session_store_t * l_store_gdb = 
								(dap_chain_cs_blocks_session_store_t *)DAP_DUP_SIZE(l_store, l_store_size_new);

					if (dap_chain_global_db_gr_set(dap_strdup(l_candidate_hash_str), l_store_gdb,
											l_store_size_new, l_session->gdb_group_store)){

printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN signs_count:%d store_size:%d\n",
						l_store->hdr.signs_count, l_store_size_new);

					}

printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN sign valid\n");

				} else {
printf("---!!! s_session_packet_in() ~~~~ DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN sign is incorrect: code %d ssize:%d\n", 
		l_sign_verified, dap_sign_get_size(l_commitsign->candidate_sign) );
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

check_err:
	DAP_DELETE(a_sender_node_addr);
	DAP_DELETE(a_data_hash);
	DAP_DELETE(a_data);
}

static bool s_session_timer() {
printf("---!!! s_session_timer_start() 1 \n");
	dap_chain_cs_blocks_session_items_t * l_session = NULL;
	DL_FOREACH(s_session_items, l_session ) {
		s_session_check(l_session);
	}
printf("---!!! s_session_timer_start() 2 \n");

    // if ((s_session_cs_timer = dap_timerfd_start(60*1000, 
    //                     (dap_timerfd_callback_t)s_session_timer_start, 
    //                     NULL)) == NULL) {
    //     printf("---!!! dap_chain_cs_blocks_session s_session_start 1 \n");
    // } else {
    //     printf("---!!! dap_chain_cs_blocks_session s_session_start 2 \n");
    // }

	return true;
}

static bool s_session_check(dap_chain_cs_blocks_session_items_t *a_session){

printf("---!!! s_session_check() 1 \n");
//	uint16_t l_net_list_size = 0;
// 	dap_chain_net_t **l_net_list = dap_chain_net_list(&l_net_list_size);
// 	for (int i=0; i<l_net_list_size; i++) {
// printf("---!!! dap_chain_cs_blocks_session s_session_start 4 net_id:%llu, net_name:%s \n",
// 				l_net_list[i]->pub.id.uint64, l_net_list[i]->pub.name);
// 		dap_chain_t *l_chain;
// 	    DL_FOREACH(l_net_list[i]->pub.chains, l_chain) {
// 	        if (!l_chain) {
// 	            continue;
// 	        }
// printf("---!!! dap_chain_cs_blocks_session s_session_start 5 chain_id:%llu, chain_name:%s\n", //cell_id:%llu\n",
// 				a_chain->id.uint64, a_chain->name); //a_chain->cells->id.uint64);
// 		}
// 	}

	dap_chain_t * l_chain = a_session->chain;
	// dap_chain_net_t * l_net = dap_chain_net_by_id(l_chain->net_id);
    dap_chain_cs_blocks_t *l_blocks = DAP_CHAIN_CS_BLOCKS(l_chain);

printf("---!!! dap_chain_cs_blocks_session s_session_check 5 chain_id:%llu, chain_name:%s\n", //cell_id:%llu\n",
				l_chain->id.uint64, l_chain->name); //a_chain->cells->id.uint64);

    if (!l_blocks->block_new)
    	return true;

printf("---!!! s_session_packet_in() ~~~~ s_session_check() block_size:%d \n", l_blocks->block_new_size);  

	s_message_send(a_session, DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT, (uint8_t*)l_blocks->block_new, l_blocks->block_new_size);

	l_blocks->block_new = NULL;
	l_blocks->block_new_size = 0;

    return true;
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
	memcpy( &l_message->message, a_data, a_data_size);
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
	dap_chain_hash_fast_t l_message_hash;
	dap_hash_fast(l_message, l_message_size, &l_message_hash);

	dap_chain_net_t * l_net = dap_chain_net_by_id(a_session->chain->net_id);
	dap_stream_ch_chain_voting_message_write(l_net, &l_message_hash, l_message, l_message_size);
}


static void s_message_chain_add(dap_chain_cs_blocks_session_items_t * a_session, dap_chain_node_addr_t * a_sender_node_addr, 
									dap_chain_cs_blocks_session_message_t * a_message,
									size_t a_message_size, dap_chain_hash_fast_t *a_message_hash) {
	
	pthread_rwlock_rdlock(&a_session->rwlock);

	a_message->hdr.is_genesis = !a_session->last_message_hash ? true : false;
	if (!a_message->hdr.is_genesis) {
		memcpy(&a_message->hdr.prev_message_hash, a_session->last_message_hash, sizeof(dap_hash_fast_t));
		//DAP_DELETE(a_session->last_message_hash);
	}
	// if (a_link_hash) {
	// 	memcpy( &l_message->hdr.link_message_hash, a_link_hash, sizeof(dap_chain_hash_fast_t));
	// }

	if (a_sender_node_addr) {
		memcpy( &a_message->hdr.sender_node_addr, a_sender_node_addr, sizeof(dap_chain_node_addr_t));
	}

	dap_chain_hash_fast_t l_message_hash;
	dap_hash_fast(a_message, a_message_size, &l_message_hash);

	dap_chain_cs_blocks_session_message_item_t * l_message_items = DAP_NEW_Z(dap_chain_cs_blocks_session_message_item_t);
	l_message_items->message = a_message;

	memcpy( &l_message_items->message_hash, &l_message_hash, sizeof(dap_chain_hash_fast_t));
	a_session->last_message_hash = &l_message_hash;
	HASH_ADD(hh, a_session->messages_items, message_hash, sizeof(l_message_items->message_hash), l_message_items);

	char * l_hash_str = dap_chain_hash_fast_to_str_new(&l_message_hash);
	//bool ret = dap_chain_global_db_gr_set(dap_strdup(l_hash_str), (uint8_t *)a_message, a_message_size, a_session->gdb_group_message);

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
// 	l_store->hdr.signs_count = 0;

// 	if (dap_chain_global_db_gr_set(dap_strdup(l_block_hash_str), l_store,
// 										l_session_store_size+l_sign_size, a_session->gdb_group_store) ) {
// 		ret = 0;
// 	}

// 	return ret;
// }






