
#include "dap_chain.h"
#include "dap_chain_block.h"


// • Submit(round, candidate) — suggest a new block candidate
// • Approve(round, candidate, signature) — a block candidate has passed local validation
// • Reject(round, candidate) — a block candidate has failed local valida- tion
// • CommitSign(round,candidate,signature)—ablockcandidatehasbeen accepted and signed
// • Vote(round, candidate) — a vote for a block candidate
// • VoteFor(round, candidate) — this block candidate must be voted for
// in this round (even if the current process has another opinion)
// • PreCommit(round,candidate)—a preliminary commitment to a block candidate (used in three-phase commit scheme)

#define DAP_STREAM_CH_CHAIN_SESSION_STATE_IDLE			0x04
#define DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_START	0x08
#define DAP_STREAM_CH_CHAIN_SESSION_STATE_CS_PROC		0x12
#define DAP_STREAM_CH_CHAIN_SESSION_STATE_WAIT_SIGNS	0x16

#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_START_SYNC		0x32

#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_SUBMIT         0x04
#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_APPROVE        0x08
#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_REJECT        	0x12
#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_COMMIT_SIGN    0x16
#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE        	0x20
#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_VOTE_FOR       0x24
#define DAP_STREAM_CH_CHAIN_MESSAGE_TYPE_PRE_COMMIT     0x28

#define DAP_CHAIN_BLOCKS_SESSION_ROUND_ID_SIZE		8
#define DAP_CHAIN_BLOCKS_SESSION_MESSAGE_ID_SIZE	8

typedef struct dap_chain_cs_blocks_session_message dap_chain_cs_blocks_session_message_t;
typedef struct dap_chain_cs_blocks_session_message_item dap_chain_cs_blocks_session_message_item_t;

typedef union dap_chain_blocks_session_round_id {
    uint8_t raw[DAP_CHAIN_BLOCKS_SESSION_ROUND_ID_SIZE];
    uint64_t uint64;
} DAP_ALIGN_PACKED dap_chain_blocks_session_round_id_t;

typedef struct dap_chain_cs_blocks_session_items {
	dap_chain_t *chain;
	dap_chain_hash_fast_t * last_message_hash;
	//dap_chain_cs_blocks_session_message_t * messages;
	dap_chain_cs_blocks_session_message_item_t * messages_items;
	uint16_t messages_count;

	dap_list_t *validators_list; // dap_chain_node_addr_t 
	uint16_t validators_count;
	dap_chain_node_addr_t * attempt_coordinator; // валидатор-координатор в текущей попытки

	//uint16_t startsync_count;
	dap_list_t *validators_start; // dap_chain_node_addr_t
	uint16_t consensus_start_period;

	// dap_timerfd_t* timer_consensus_finish;
	// dap_timerfd_t* timer_consensus_cancel;

	dap_chain_time_t ts_round_start_sync; // time in last sync message
	dap_chain_time_t ts_round_start;
	dap_chain_time_t ts_round_state_commit;
	dap_chain_time_t ts_round_finish;

	dap_chain_blocks_session_round_id_t round_id;
	uint8_t state;

	char * gdb_group_setup;
	char * gdb_group_store;
	char * gdb_group_message;

	dap_enc_key_t *blocks_sign_key;
	// dap_timerfd_t *cs_timer;

    struct dap_chain_cs_blocks_session_items * next;
    struct dap_chain_cs_blocks_session_items * prev;

	uint32_t session_idle_min; // время между раундами (минимальное в нашем случае + округление времени ) - заменить consensus_start_period
	uint16_t round_candidates_max; // всего кандидатов участвующих в раунде
	uint16_t next_candidate_delay; // задежка предложения следующего кандидата (в зависимости от приоритетов валидатора)
	uint16_t round_attempts_max; // всего попыток в раунде
	uint16_t round_attempt_duration; // длительность попытки

    pthread_rwlock_t rwlock;

} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_items_t;

typedef struct dap_chain_cs_blocks_session_message_hdr {
	uint8_t type;

	union {
		uint8_t raw[DAP_CHAIN_BLOCKS_SESSION_MESSAGE_ID_SIZE];
    	uint64_t uint64;
	} DAP_ALIGN_PACKED id;

	size_t message_size;

	dap_chain_time_t ts_created;
	dap_chain_blocks_session_round_id_t round_id;

	dap_chain_node_addr_t sender_node_addr;

    // dap_chain_hash_fast_t block_candidate_hash;
    // char* block_candidate_hash_str;
    // size_t block_candidate_size;

	bool is_genesis;

	//dap_chain_hash_fast_t genesis_message_hash;
	//dap_chain_hash_fast_t message_hash;
	dap_chain_hash_fast_t prev_message_hash; 
	//dap_chain_hash_fast_t link_message_hash; 

    dap_chain_id_t chain_id;
    //dap_chain_cell_id_t cell_id;

} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_hdr_t;


typedef struct dap_chain_cs_blocks_session_message {
    dap_chain_cs_blocks_session_message_hdr_t hdr;
    // UT_hash_handle hh;
    uint8_t message[];
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_t;


typedef struct dap_chain_cs_blocks_session_message_item {
    dap_chain_cs_blocks_session_message_t * message;
    dap_chain_hash_fast_t message_hash;
    UT_hash_handle hh;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_item_t;


// struct for get hash from any messages
typedef struct dap_chain_cs_blocks_session_message_gethash {
	dap_chain_hash_fast_t candidate_hash;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_gethash_t;

// technical messages
typedef struct dap_chain_cs_blocks_session_message_startsync {
	dap_chain_time_t ts;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_startsync_t;

// consensus messages
typedef struct dap_chain_cs_blocks_session_message_submit {
	dap_chain_hash_fast_t candidate_hash;
	size_t candidate_size;
	uint8_t candidate[];
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_message_submit_t;

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


typedef struct dap_chain_cs_blocks_session_store_hdr {
	uint16_t sign_count;
	uint16_t approve_count;
	uint16_t reject_count;
	uint16_t vote_count;
	uint16_t precommit_count;
	size_t candidate_size;
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_store_hdr_t;

typedef struct dap_chain_cs_blocks_session_store {
	dap_chain_cs_blocks_session_store_hdr_t hdr;
    uint8_t candidate_n_signs[];
} DAP_ALIGN_PACKED dap_chain_cs_blocks_session_store_t;



int dap_chain_cs_blocks_session_init(dap_chain_t *a_chain, dap_enc_key_t *a_blocks_sign_key);
