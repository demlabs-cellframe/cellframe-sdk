/*
 * Authors:
 * Development Team
 * DeM Labs Inc.   https://demlabs.net
 * Cellframe Network https://cellframe.net
 * Copyright  (c) 2024
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_chain_net_srv_voting.h"
#include "dap_chain_node_cli_cmd.h"
#include "dap_json_rpc_response.h"
#include "dap_proc_thread.h"
#include "dap_chain_tx_out_cond.h"
#include "json_object.h"

// Monitoring command type (only monitoring)
typedef enum {
    DAP_AUCTION_CMD_MONITOR = 1
} dap_auction_cmd_type_t;

// Auction status
typedef enum {
    DAP_AUCTION_STATUS_CREATED = 0,
    DAP_AUCTION_STATUS_ACTIVE = 1,
    DAP_AUCTION_STATUS_VOTING = 2,     // Community voting phase
    DAP_AUCTION_STATUS_ENDED = 3,
    DAP_AUCTION_STATUS_FINALIZED = 4
} dap_auction_status_t;

// Bid information for monitoring
typedef struct dap_auction_bid_info {
    dap_hash_fast_t bid_hash;          // хеш ставки
    uint256_t bid_amount;              // размер ставки
    dap_time_t bid_time;               // время ставки/голоса
    dap_chain_addr_t bidder_addr;      // адрес делающего ставку
    uint64_t vote_count;               // количество голосов за эту ставку
} dap_auction_bid_info_t;

// Winner information
typedef struct dap_auction_winner_info {
    dap_chain_addr_t winner_addr;      // адрес победителя
    uint256_t winning_amount;          // выигрыш
    uint64_t total_votes;              // общее количество голосов
} dap_auction_winner_info_t;

// Auction monitoring data structure
typedef struct dap_auction_monitor_data {
    dap_hash_fast_t auction_hash;
    dap_chain_net_id_t net_id;
    dap_auction_status_t status;
    
    // Основные данные аукциона
    char *item_description;
    dap_time_t start_time;
    dap_time_t end_time;
    dap_time_t voting_end_time;
    
    // Мониторинг данные
    uint64_t total_votes_count;        // общая сумма голосов
    dap_list_t *bids_list;             // ставки - хеши/размер/время голоса
    dap_auction_winner_info_t winner;  // победитель - адрес/выигрыш
    uint256_t predicted_income;        // прогнозируемый доход (предложение шефа)
    
    // Voting integration (reuse existing voting system)
    dap_hash_fast_t voting_hash;       // Hash of associated voting poll
    bool voting_enabled;               // Whether community voting is enabled
    
    UT_hash_handle hh;
} dap_auction_monitor_data_t;

// Service monitoring structure - only for monitoring
typedef struct dap_auction_service_monitor {
    bool is_active;
    uint64_t total_auctions;
    uint64_t active_auctions;
    uint64_t completed_auctions;
    uint64_t total_bids;
    uint64_t total_votes;
    dap_time_t last_update;
    pthread_rwlock_t rwlock;
} dap_auction_service_monitor_t;

// Function declarations - ONLY MONITORING FUNCTIONS

// Initialization and cleanup
int dap_chain_net_srv_auction_monitor_init(void);
void dap_chain_net_srv_auction_monitor_deinit(void);

// Monitoring procedures
int dap_auction_service_monitor_init(void);
void dap_auction_service_monitor_deinit(void);
void dap_auction_service_monitor_update(void);
dap_auction_service_monitor_t *dap_auction_service_monitor_get(void);

// Monitoring command handler
int dap_auction_cmd_monitor_handler(int argc, char **argv, void **str_reply, int version);

// Monitoring data collection functions
dap_auction_monitor_data_t *dap_auction_monitor_collect_data(dap_chain_net_t *a_net, dap_hash_fast_t a_auction_hash);
dap_list_t *dap_auction_monitor_get_all_auctions(dap_chain_net_t *a_net);

// Monitoring analysis functions
uint64_t dap_auction_monitor_get_total_votes(dap_hash_fast_t a_auction_hash);
dap_list_t *dap_auction_monitor_get_bids_with_votes(dap_hash_fast_t a_auction_hash);
dap_auction_winner_info_t *dap_auction_monitor_get_winner(dap_hash_fast_t a_auction_hash);
uint256_t dap_auction_monitor_calculate_predicted_income(dap_hash_fast_t a_auction_hash);

// JSON output for monitoring
json_object *dap_auction_monitor_data_to_json(dap_auction_monitor_data_t *a_data);
json_object *dap_auction_service_status_to_json(dap_auction_service_monitor_t *a_monitor);
json_object *dap_auction_bid_info_to_json(dap_auction_bid_info_t *a_bid);
json_object *dap_auction_winner_info_to_json(dap_auction_winner_info_t *a_winner);

// Timer callback for monitoring
void dap_auction_monitor_timer_callback(void *a_arg);

// Global variables declarations
extern dap_auction_service_monitor_t *g_auction_service_monitor;
extern dap_auction_monitor_data_t *g_auction_monitor_data;
extern pthread_rwlock_t g_auction_monitor_data_rwlock; 