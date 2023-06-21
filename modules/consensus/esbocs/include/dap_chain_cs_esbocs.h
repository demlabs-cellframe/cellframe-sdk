#pragma once

#include "dap_timerfd.h"
#include "dap_chain.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"
#include "dap_cert.h"

#define DAP_CHAIN_ESBOCS_PROTOCOL_VERSION           5

#define DAP_STREAM_CH_VOTING_MSG_TYPE_SUBMIT        0x04
#define DAP_STREAM_CH_VOTING_MSG_TYPE_APPROVE       0x08
#define DAP_STREAM_CH_VOTING_MSG_TYPE_REJECT        0x12
#define DAP_STREAM_CH_VOTING_MSG_TYPE_COMMIT_SIGN   0x16
#define DAP_STREAM_CH_VOTING_MSG_TYPE_PRE_COMMIT    0x28
#define DAP_STREAM_CH_VOTING_MSG_TYPE_VOTE          0x20
#define DAP_STREAM_CH_VOTING_MSG_TYPE_DIRECTIVE     0x24
#define DAP_STREAM_CH_VOTING_MSG_TYPE_START_SYNC    0x32

#define DAP_CHAIN_BLOCKS_SESSION_ROUND_ID_SIZE		8
#define DAP_CHAIN_BLOCKS_SESSION_MESSAGE_ID_SIZE	8

typedef struct dap_chain_esbocs_session dap_chain_esbocs_session_t;

/* consensus messages
• Sync(round, last block, sync attempt) - try to synchronize validators before first round attempt start
• Submit(round, candidate, body) — suggest a new block candidate *** candiate body in data section
• Approve(round, candidate) — a block candidate has passed local validation
• Reject(round, candidate) — a block candidate has failed local validation
• CommitSign(round, candidate, signature) — a block candidate has been accepted and signed *** sign in data section
• PreCommit(round, candidate, final_hash) — a preliminary commitment to a block candidate *** candidate with signs hash in data section
• Directive(round, body) — a directive to change consensus parameters *** directive body in data section
• Vote(round, directive) — a vote for a directive in this round
*/
typedef struct dap_chain_esbocs_message_hdr {
    uint16_t version;
    uint8_t type;
    uint8_t attempt_num;
    uint64_t round_id;
    uint64_t sign_size;
    uint64_t message_size;
    dap_time_t ts_created;
    dap_chain_net_id_t net_it;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
    dap_hash_fast_t candidate_hash;
} DAP_ALIGN_PACKED dap_chain_esbocs_message_hdr_t;

typedef struct dap_chain_esbocs_message {
    dap_chain_esbocs_message_hdr_t hdr;
    uint8_t msg_n_sign[];
} DAP_ALIGN_PACKED dap_chain_esbocs_message_t;

typedef struct dap_chain_esbocs_message_item {
    dap_hash_fast_t message_hash;
    dap_chain_esbocs_message_t *message;
    dap_chain_addr_t signing_addr;
    UT_hash_handle hh;
} dap_chain_esbocs_message_item_t;

typedef struct dap_chain_esbocs_sync_item {
    dap_hash_fast_t last_block_hash;
    dap_list_t *messages;
    UT_hash_handle hh;
} dap_chain_esbocs_sync_item_t;

typedef struct dap_chain_esbocs_store {
    dap_hash_fast_t candidate_hash;
    dap_hash_fast_t precommit_candidate_hash;
    dap_chain_block_t *candidate;
    size_t candidate_size;
    dap_list_t *candidate_signs;
    uint16_t approve_count;
    uint16_t reject_count;
    uint16_t precommit_count;
    bool decide_reject;
    bool decide_approve;
    bool decide_commit;
    UT_hash_handle hh;
} dap_chain_esbocs_store_t;

typedef struct dap_chain_esbocs {
    dap_chain_t *chain;
    dap_chain_cs_blocks_t *blocks;
    dap_chain_esbocs_session_t *session;
    void *_pvt;
} dap_chain_esbocs_t;

typedef struct dap_chain_esbocs_directive {
    uint8_t version;
    uint8_t type;
    uint16_t size;
    byte_t tsd[];
} DAP_ALIGN_PACKED dap_chain_esbocs_directive_t;

typedef struct dap_chain_esbocs_round {
    // Base fields
    uint64_t id;
    uint8_t attempt_num;
    dap_hash_fast_t last_block_hash;
    // Round ancillary
    dap_chain_esbocs_store_t *store_items;
    dap_chain_esbocs_message_item_t *message_items;
    // Round directive
    dap_chain_esbocs_directive_t *directive;
    uint16_t votes_count;
    // Attempt dependent fields
    dap_chain_addr_t attempt_submit_validator;
    dap_hash_fast_t attempt_candidate_hash;
    // Validators section
    uint16_t validators_synced_count;
    dap_list_t *validators_list;
    uint64_t sync_attempt;
    bool sync_sent;
    uint16_t total_validators_count;
} dap_chain_esbocs_round_t;

typedef struct dap_chain_esbocs_validator {
    dap_chain_node_addr_t node_addr;
    dap_chain_addr_t signing_addr;
    uint256_t weight;
    bool is_synced;
    bool is_chosen;
} dap_chain_esbocs_validator_t;

typedef struct dap_chain_esbocs_session {
    pthread_mutex_t mutex;
    dap_chain_block_t *processing_candidate;

    dap_chain_t *chain;
    dap_chain_esbocs_t *esbocs;

    dap_chain_node_addr_t my_addr;
    uint8_t state; // session state
    dap_chain_esbocs_round_t cur_round;
    bool round_fast_forward;

    dap_time_t ts_round_sync_start; // time of start sync
    dap_time_t ts_attempt_start; // time of current attempt start

    dap_chain_esbocs_sync_item_t *sync_items;
    dap_timerfd_t *sync_timer;

    dap_enc_key_t *blocks_sign_key;
    dap_chain_addr_t my_signing_addr;

    struct dap_chain_esbocs_session *next;
    struct dap_chain_esbocs_session *prev;
} dap_chain_esbocs_session_t;

#define DAP_CHAIN_ESBOCS(a) ((dap_chain_esbocs_t *)(a)->_inheritor)
int dap_chain_cs_esbocs_init();
void dap_chain_cs_esbocs_deinit(void);

