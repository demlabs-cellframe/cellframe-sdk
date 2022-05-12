
#include "dap_chain.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"
#include "dap_cert.h"

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

enum    {
    DAP_TON$ROUND_CUR  = 'c',
    DAP_TON$ROUND_OLD  = 'o',
};

typedef struct dap_chain_cs_block_ton_message dap_chain_cs_block_ton_message_t;
typedef struct dap_chain_cs_block_ton_message_item dap_chain_cs_block_ton_message_item_t;

typedef struct dap_chain_cs_block_ton
{
    dap_chain_t *chain;
    dap_chain_cs_blocks_t *blocks;
    void *_pvt;
} dap_chain_cs_block_ton_t;

typedef union dap_chain_cs_block_ton_round_id {
    uint8_t raw[DAP_CHAIN_BLOCKS_SESSION_ROUND_ID_SIZE];
    uint64_t uint64;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_round_id_t;

typedef struct dap_chain_cs_block_ton_round {
	dap_chain_cs_block_ton_round_id_t id;
	dap_list_t *validators_start; // dap_chain_node_addr_t
	uint16_t validators_start_count;
	dap_chain_hash_fast_t *last_message_hash;
	dap_chain_cs_block_ton_message_item_t *messages_items;
	bool submit;
	uint16_t messages_count;
	dap_chain_hash_fast_t *my_candidate_hash;
	dap_list_t *validators_list; // dap_chain_node_addr_t 
	uint16_t validators_count;
	uint16_t candidates_count;
} dap_chain_cs_block_ton_round_t;

typedef struct dap_chain_cs_block_ton_items {
	dap_chain_t *chain;
	dap_chain_cs_block_ton_t *ton;

	dap_chain_node_addr_t *my_addr;

    dap_chain_block_t *my_candidate;
    size_t my_candidate_size;
   	uint16_t my_candidate_attempts_count;

	uint8_t state; // session state
	dap_chain_cs_block_ton_round_t cur_round;
	dap_chain_cs_block_ton_round_t old_round; 
	
	dap_chain_node_addr_t *attempt_coordinator; // validator-coordinator in current attempt
	uint16_t attempt_current_number;

	dap_time_t ts_round_sync_start; // time start sync
	dap_time_t ts_round_start; // time round-start
	dap_time_t ts_round_state_commit;
	dap_time_t ts_round_finish;

	char * gdb_group_setup;
	char * gdb_group_store;
	char * gdb_group_message;

	dap_enc_key_t *blocks_sign_key;

    struct dap_chain_cs_block_ton_items *next;
    struct dap_chain_cs_block_ton_items *prev;

	bool time_proc_lock; // flag - skip check if prev check is not finish

    pthread_rwlock_t rwlock;

} dap_chain_cs_block_ton_items_t;

typedef struct dap_chain_cs_block_ton_message_hdr {
	uint8_t type;

	union {
		uint8_t raw[DAP_CHAIN_BLOCKS_SESSION_MESSAGE_ID_SIZE];
    	uint64_t uint64;
	} DAP_ALIGN_PACKED id;

	size_t sign_size;
	size_t message_size;

	dap_time_t ts_created;
	//dap_chain_cs_block_ton_round_id_t round_id;

	dap_chain_node_addr_t sender_node_addr;

	bool is_genesis;
	bool is_verified;
	dap_chain_hash_fast_t prev_message_hash; 
    dap_chain_id_t chain_id;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_hdr_t;

typedef struct dap_chain_cs_block_ton_message {
    dap_chain_cs_block_ton_message_hdr_t hdr;
    uint8_t sign_n_message[];
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_t;

typedef struct dap_chain_cs_block_ton_message_item {
    dap_chain_cs_block_ton_message_t *message;
    dap_chain_hash_fast_t message_hash;
    UT_hash_handle hh;
} dap_chain_cs_block_ton_message_item_t;

// struct for get info from any messages
typedef struct dap_chain_cs_block_ton_message_getinfo {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
	uint16_t attempt_number;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_getinfo_t;

// technical messages
typedef struct dap_chain_cs_block_ton_message_startsync {
	dap_time_t ts;
	dap_chain_cs_block_ton_round_id_t round_id;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_startsync_t;

/*
consensus messages
• Submit(round, candidate) — suggest a new block candidate
• Approve(round, candidate, signature) — a block candidate has passed local validation
• Reject(round, candidate) — a block candidate has failed local valida- tion
• CommitSign(round,candidate,signature) — a block candidate has been accepted and signed
• Vote(round, candidate) — a vote for a block candidate
• VoteFor(round, candidate) — this block candidate must be voted for
in this round (even if the current process has another opinion)
• PreCommit(round,candidate) — a preliminary commitment to a block candidate (used in three-phase commit scheme)
*/

typedef struct dap_chain_cs_block_ton_message_submit {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
	size_t candidate_size;
	uint8_t candidate[];
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_submit_t;

typedef struct dap_chain_cs_block_ton_message_approve {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
	uint8_t candidate_hash_sign[];
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_approve_t;

typedef struct dap_chain_cs_block_ton_message_reject {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_reject_t;

typedef struct dap_chain_cs_block_ton_message_votefor {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
	uint16_t attempt_number;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_votefor_t;

typedef struct dap_chain_cs_block_ton_message_vote {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
	uint16_t attempt_number;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_vote_t;

typedef struct dap_chain_cs_block_ton_message_precommit {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
	uint16_t attempt_number;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_precommit_t;

typedef struct dap_chain_cs_block_ton_message_commitsign {
	dap_chain_hash_fast_t candidate_hash;
	dap_chain_cs_block_ton_round_id_t round_id;
	uint8_t candidate_sign[];
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_message_commitsign_t;

typedef struct dap_chain_cs_block_ton_store_hdr {
	bool sign_collected; // cellect 2/3 min 
	bool approve_collected;
	// bool reject_done;
	bool vote_collected;
	bool precommit_collected;
	size_t candidate_size;
	dap_chain_cs_block_ton_round_id_t round_id;
	dap_chain_hash_fast_t candidate_hash;
	dap_time_t ts_candidate_submit;
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_store_hdr_t;

typedef struct dap_chain_cs_block_ton_store {
	dap_chain_cs_block_ton_store_hdr_t hdr;
    uint8_t candidate_n_signs[];
} DAP_ALIGN_PACKED dap_chain_cs_block_ton_store_t;

#define DAP_CHAIN_CS_BLOCK_TON(a) ((dap_chain_cs_block_ton_t *)(a)->_inheritor)
int dap_chain_cs_block_ton_init();
void dap_chain_cs_block_ton_deinit(void);
