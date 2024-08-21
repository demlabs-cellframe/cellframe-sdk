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
#pragma once

#include "dap_timerfd.h"
#include "dap_chain.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"
#include "dap_global_db_driver.h"

#define DAP_STREAM_CH_ESBOCS_ID                     'E'

#define DAP_CHAIN_ESBOCS_PROTOCOL_VERSION           8
#define DAP_CHAIN_ESBOCS_CS_TYPE_STR                "esbocs"
#define DAP_CHAIN_ESBOCS_GDB_GROUPS_PREFIX          DAP_CHAIN_ESBOCS_CS_TYPE_STR
#define DAP_CHAIN_CLUSTER_ID_ESBOCS                 0x8000

#define DAP_CHAIN_ESBOCS_MSG_TYPE_SUBMIT            0x04
#define DAP_CHAIN_ESBOCS_MSG_TYPE_APPROVE           0x08
#define DAP_CHAIN_ESBOCS_MSG_TYPE_REJECT            0x12
#define DAP_CHAIN_ESBOCS_MSG_TYPE_COMMIT_SIGN       0x16
#define DAP_CHAIN_ESBOCS_MSG_TYPE_PRE_COMMIT        0x28
#define DAP_CHAIN_ESBOCS_MSG_TYPE_DIRECTIVE         0x20
#define DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_FOR          0x22
#define DAP_CHAIN_ESBOCS_MSG_TYPE_VOTE_AGAINST      0x24
#define DAP_CHAIN_ESBOCS_MSG_TYPE_START_SYNC        0x32

#define DAP_CHAIN_BLOCKS_SESSION_ROUND_ID_SIZE		8
#define DAP_CHAIN_BLOCKS_SESSION_MESSAGE_ID_SIZE	8

#define DAP_CHAIN_CS_ESBOCS_DIRECTIVE_SUPPORT     // Uncomment it for enable directve supporting
#define DAP_CHAIN_ESBOCS_DIRECTIVE_VERSION          1
#define DAP_CHAIN_ESBOCS_DIRECTIVE_KICK             0x10
#define DAP_CHAIN_ESBOCS_DIRECTIVE_LIFT             0x11

#define DAP_CHAIN_ESBOCS_DIRECTIVE_TSD_TYPE_ADDR    0x01

#define PKT_SIGN_N_HDR_OVERHEAD (15 * 1024)

typedef struct dap_chain_esbocs_session dap_chain_esbocs_session_t;

/* consensus messages
• Sync(round, last block, sync attempt) - try to synchronize validators before first round attempt start
• Submit(round, candidate, body) — suggest a new block candidate *** candiate body in data section
• Approve(round, candidate) — a block candidate has passed local validation
• Reject(round, candidate) — a block candidate has failed local validation
• CommitSign(round, candidate, signature) — a block candidate has been accepted and signed *** sign in data section
• PreCommit(round, candidate, final_hash) — a preliminary commitment to a block candidate *** candidate with signs hash in data section
• Directive(round, body) — a directive to change consensus parameters *** directive body in data section
• VoteFor(round, directive) — a vote for a directive in this round
• VoteAgainst(round, directive) — a vote against a directive in this round
*/
typedef struct dap_chain_esbocs_message_hdr {
    uint16_t version;
    uint8_t type;
    uint8_t attempt_num;
    uint64_t round_id;
    uint64_t sign_size;
    uint64_t message_size;
    dap_time_t ts_created;
    dap_chain_net_id_t net_id;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
    dap_stream_node_addr_t recv_addr;
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
    bool unprocessed;   // Do not count one message twice
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
    uint16_t pad;
    uint32_t size;
    dap_nanotime_t timestamp;
    byte_t tsd[];
} DAP_ALIGN_PACKED dap_chain_esbocs_directive_t;

typedef struct dap_chain_esbocs_round {
    uint64_t id;
    uint64_t sync_attempt;

    dap_hash_fast_t last_block_hash;
    dap_hash_fast_t directive_hash;
    dap_hash_fast_t attempt_candidate_hash;
    dap_chain_addr_t attempt_submit_validator;

    dap_list_t *all_validators;
    dap_chain_esbocs_store_t *store_items;
    dap_chain_esbocs_message_item_t *message_items;
    dap_chain_esbocs_directive_t *directive;
    uint16_t *excluded_list;
    dap_list_t *validators_list;


    uint16_t votes_for_count;
    uint16_t votes_against_count;
    uint16_t validators_synced_count;
    uint16_t total_validators_synced;

    bool directive_applied;
    bool sync_sent;
    uint8_t attempt_num;
} dap_chain_esbocs_round_t;

typedef struct dap_chain_esbocs_validator {
    dap_chain_node_addr_t node_addr;
    dap_chain_addr_t signing_addr;
    uint256_t weight;
    bool is_synced;
    bool is_chosen;
} dap_chain_esbocs_validator_t;

typedef struct dap_chain_esbocs_penalty_item {
        dap_chain_addr_t signing_addr;
        uint16_t miss_count;
        UT_hash_handle hh;
} dap_chain_esbocs_penalty_item_t;

#define DAP_CHAIN_ESBOCS_PENALTY_KICK   3U      // Number of missed rounds to kick

typedef struct dap_chain_esbocs_session {
    pthread_mutex_t mutex;
    bool cs_timer;
    dap_chain_block_t *processing_candidate;

    dap_chain_t *chain;
    dap_chain_esbocs_t *esbocs;

    dap_chain_node_addr_t my_addr;
    uint8_t state; // session state
    uint8_t old_state; // for previous state return
    dap_chain_esbocs_round_t cur_round;
    bool round_fast_forward;
    unsigned int listen_ensure;
    bool sync_failed;
    bool new_round_enqueued;

    dap_time_t ts_round_sync_start; // time of start sync
    dap_time_t ts_stage_entry; // time of current stage entrance

    dap_chain_esbocs_sync_item_t *sync_items;
    dap_timerfd_t *sync_timer;

    dap_chain_addr_t my_signing_addr;

    dap_chain_esbocs_penalty_item_t *penalty;
    dap_global_db_cluster_t *db_cluster;
    dap_global_db_driver_hash_t db_hash;

    struct dap_chain_esbocs_session *prev, *next;
} dap_chain_esbocs_session_t;

typedef struct dap_chain_esbocs_block_collect{
    uint256_t collecting_level;
    uint256_t minimum_fee;
    dap_chain_t *chain;
    dap_enc_key_t * blocks_sign_key;
    dap_pkey_t * block_sign_pkey;
    dap_chain_addr_t * collecting_addr;
    dap_chain_cell_id_t cell_id;
}dap_chain_esbocs_block_collect_t;

typedef enum s_com_esbocs_err{
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_OK = 0,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_PARAM_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_CHAIN_TYPE_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_CERT_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_PVT_KEY_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_UNREC_COM_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_MINVALSET_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_CHECKING_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_HASH_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_HASH_FORMAT_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_ADD_DEL_ERR,
    DAP_CHAIN_NODE_CLI_COM_ESBOCS_SUB_ERR,

    /* add custom codes here */

    DAP_CHAIN_NODE_CLI_COM_ESBOCS_UNKNOWN /* MAX */
} s_com_esbocs_err_t;

#define DAP_CHAIN_ESBOCS(a) ((dap_chain_esbocs_t *)(a)->_inheritor)

typedef enum dap_chain_block_autocollect_type {
    DAP_CHAIN_BLOCK_COLLECT_BOTH,
    DAP_CHAIN_BLOCK_COLLECT_FEES,
    DAP_CHAIN_BLOCK_COLLECT_REWARDS
} dap_chain_block_autocollect_type_t;

int dap_chain_cs_esbocs_init();
void dap_chain_cs_esbocs_deinit(void);

bool dap_chain_esbocs_started(dap_chain_net_id_t a_net_id);
void dap_chain_esbocs_stop_timer(dap_chain_net_id_t a_net_id);
void dap_chain_esbocs_start_timer(dap_chain_net_id_t a_net_id);

dap_pkey_t *dap_chain_esbocs_get_sign_pkey(dap_chain_net_id_t a_net_id);
uint256_t dap_chain_esbocs_get_fee(dap_chain_net_id_t a_net_id);
bool dap_chain_esbocs_get_autocollect_status(dap_chain_net_id_t a_net_id);
void dap_chain_esbocs_add_block_collect(dap_chain_block_cache_t *a_block_cache,
                                        dap_chain_esbocs_block_collect_t *a_block_collect_params,
                                        dap_chain_block_autocollect_type_t a_type);
bool dap_chain_esbocs_add_validator_to_clusters(dap_chain_net_id_t a_net_id, dap_stream_node_addr_t *a_validator_addr);
bool dap_chain_esbocs_remove_validator_from_clusters(dap_chain_net_id_t a_net_id, dap_stream_node_addr_t *a_validator_addr);

uint256_t dap_chain_esbocs_get_collecting_level(dap_chain_t *a_chain);
dap_enc_key_t *dap_chain_esbocs_get_sign_key(dap_chain_t *a_chain);
int dap_chain_esbocs_set_min_validators_count(dap_chain_t *a_chain, uint16_t a_new_value);
int dap_chain_esbocs_set_emergency_validator(dap_chain_t *a_chain, bool a_add, uint32_t a_sign_type, dap_hash_fast_t *a_validator_hash);
int dap_chain_esbocs_set_signs_struct_check(dap_chain_t *a_chain, bool a_enable);
