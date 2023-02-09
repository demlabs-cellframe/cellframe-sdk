
#include "dap_chain.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"
#include "dap_cert.h"

#define DAP_STREAM_CH_VOTE_SESSION_STATE_WAIT_START     0x08
#define DAP_STREAM_CH_VOTE_SESSION_STATE_CS_PROC        0x12
#define DAP_STREAM_CH_VOTE_SESSION_STATE_WAIT_SIGNS     0x16

#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_START_SYNC      0x32
#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_SUBMIT          0x04
#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_APPROVE         0x08
#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_REJECT          0x12
#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_COMMIT_SIGN     0x16
//#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_VOTE            0x20
//#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_VOTE_FOR        0x24
#define DAP_STREAM_CH_VOTE_MESSAGE_TYPE_PRE_COMMIT      0x28

#define DAP_CHAIN_BLOCKS_SESSION_ROUND_ID_SIZE		8
#define DAP_CHAIN_BLOCKS_SESSION_MESSAGE_ID_SIZE	8

/* consensus messages
• Submit(round, candidate, body) — suggest a new block candidate *** candiate body in data section
• Approve(round, candidate) — a block candidate has passed local validation
• Reject(round, candidate) — a block candidate has failed local validation
• CommitSign(round, candidate, signature) — a block candidate has been accepted and signed *** sign in data section
• Vote(round, candidate) — a vote for a block candidate in this round (even if the current process has another opinion)
• PreCommit(round, candidate) — a preliminary commitment to a block candidate (used in three-phase commit scheme)
*/
typedef struct dap_chain_esbocs_message_hdr {
    uint8_t version;
    uint8_t padding;
    uint8_t type;
    uint8_t attempt_num;
    uint64_t round_id;
    uint64_t sign_size;
    uint64_t message_size;
    dap_time_t ts_created;
    dap_chain_net_id_t net_it;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
    dap_chain_hash_fast_t candidate_hash;
} DAP_ALIGN_PACKED dap_chain_esbocs_message_hdr_t;

typedef struct dap_chain_esbocs_message {
    dap_chain_esbocs_message_hdr_t hdr;
    uint8_t msg_n_sign[];
} DAP_ALIGN_PACKED dap_chain_esbocs_message_t;

typedef struct dap_chain_esbocs_message_item {
    dap_chain_hash_fast_t message_hash;
    dap_chain_esbocs_message_t *message;
    dap_chain_addr_t signing_addr;
    bool is_verified;
    UT_hash_handle hh;
} dap_chain_esbocs_message_item_t;

typedef struct dap_chain_esbocs_sync_item {
    dap_chain_hash_fast_t last_block_hash;
    dap_list_t *messages;
    UT_hash_handle hh;
} dap_chain_esbocs_sync_item_t;

typedef struct dap_chain_esbocs_store {
    dap_chain_hash_fast_t candidate_hash;
    dap_chain_block_t *candidate;
    dap_list_t *candidate_signs;
    size_t candidate_size;
    uint16_t approve_count;
    uint16_t reject_count;
    uint16_t vote_count;
    uint16_t precommit_count;
    UT_hash_handle hh;
} dap_chain_esbocs_store_t;

typedef struct dap_chain_esbocs {
    dap_chain_t *chain;
    dap_chain_cs_blocks_t *blocks;
    void *_pvt;
} dap_chain_esbocs_t;

typedef struct dap_chain_esbocs_round {
    uint64_t id;
    uint8_t attempt_num;
    dap_chain_esbocs_store_t *store_items;
    dap_chain_esbocs_message_item_t *messages_items;
    dap_chain_hash_fast_t last_block_hash;
    dap_chain_hash_fast_t attempt_candidate_hash;
    dap_chain_hash_fast_t precommit_candidate_hash;
    uint16_t validators_count;
    dap_list_t *validators_list;
} dap_chain_esbocs_round_t;

typedef struct dap_chain_esbocs_validator {
    dap_chain_node_addr_t node_addr;
    dap_chain_addr_t signing_addr;
    uint256_t weight;
} dap_chain_esbocs_validator_t;

typedef struct dap_chain_esbocs_session {
    dap_chain_t *chain;
    dap_chain_esbocs_t *esbocs;
    dap_interval_timer_t session_timer;

    dap_chain_node_addr_t my_addr;

    uint8_t state; // session state
    dap_chain_esbocs_round_t cur_round;

    dap_time_t ts_round_sync_start; // time of start sync
    dap_time_t ts_attempt_start; // time of current attempt start

    dap_chain_esbocs_sync_item_t *sync_items;

    dap_enc_key_t *blocks_sign_key;
    dap_chain_addr_t my_signing_addr;

    struct dap_chain_esbocs_session *next;
    struct dap_chain_esbocs_session *prev;

    dap_worker_t *worker; // Worker where it was processed last time
    pthread_rwlock_t rwlock;
} dap_chain_esbocs_session_t;

#define DAP_CHAIN_ESBOCS(a) ((dap_chain_esbocs_t *)(a)->_inheritor)
int dap_chain_esbocs_init();
void dap_chain_esbocs_deinit(void);
