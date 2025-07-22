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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "dap_chain_net_srv_voting_cmd.h"
#include "dap_chain_net_srv_voting.h"
#include "dap_chain_net.h"
#include "dap_cli_server.h"
#include "dap_json_rpc_response.h"
#include "dap_string.h"
#include "dap_list.h"
#include "dap_hash.h"
#include "json_object.h"

#define LOG_TAG "auction_monitor_handlers"

// External references
extern dap_auction_service_monitor_t *g_auction_service_monitor;
extern dap_auction_monitor_data_t *g_auction_monitor_data;
extern pthread_rwlock_t g_auction_monitor_data_rwlock;

/**
 * @brief Monitor auctions handler - единственный обработчик команд
 * Показывает:
 * - общая сумма голосов
 * - ставки - хеши/размер/время голоса
 * - победитель - адрес/выигрыш
 * - прогнозируемый доход (предложение шефа)
 */
int dap_auction_cmd_monitor_handler(int argc, char **argv, void **str_reply, int version)
{
    json_object **json_arr_reply = (json_object **)str_reply;
    
    const char *l_net_str = NULL, *l_hash_str = NULL, *l_format = NULL;
    
    // Parse parameters
    dap_cli_server_cmd_find_option_val(argv, 1, argc, "-net", &l_net_str);
    dap_cli_server_cmd_find_option_val(argv, 1, argc, "-hash", &l_hash_str);
    dap_cli_server_cmd_find_option_val(argv, 1, argc, "-format", &l_format);
    
    if (!l_net_str) {
        dap_json_rpc_error_add(*json_arr_reply, -1, "Network parameter (-net) is required");
        return -1;
    }
    
    dap_chain_net_t *l_net = dap_chain_net_by_name(l_net_str);
    if (!l_net) {
        dap_json_rpc_error_add(*json_arr_reply, -2, "Invalid network name");
        return -2;
    }
    
    json_object *l_result = json_object_new_object();
    
    if (l_hash_str) {
        // Monitor specific auction
        dap_hash_fast_t l_auction_hash;
        if (dap_chain_hash_fast_from_hex_str(l_hash_str, &l_auction_hash)) {
            dap_json_rpc_error_add(*json_arr_reply, -3, "Invalid auction hash");
            json_object_put(l_result);
            return -3;
        }
        
        // Collect monitoring data for specific auction
        dap_auction_monitor_data_t *l_auction_data = dap_auction_monitor_collect_data(l_net, l_auction_hash);
        if (!l_auction_data) {
            dap_json_rpc_error_add(*json_arr_reply, -4, "Failed to collect auction data");
            json_object_put(l_result);
            return -4;
        }
        
        // Add auction monitoring data
        json_object_object_add(l_result, "auction_hash", json_object_new_string(l_hash_str));
        json_object_object_add(l_result, "network", json_object_new_string(l_net_str));
        
        // общая сумма голосов
        json_object_object_add(l_result, "total_votes_count", 
                              json_object_new_int64(l_auction_data->total_votes_count));
        
        // ставки - хеши/размер/время голоса
        if (l_auction_data->bids_list) {
            json_object *l_bids_array = json_object_new_array();
            for (dap_list_t *l_iter = l_auction_data->bids_list; l_iter; l_iter = l_iter->next) {
                dap_auction_bid_info_t *l_bid = (dap_auction_bid_info_t *)l_iter->data;
                if (l_bid) {
                    json_object *l_bid_json = dap_auction_bid_info_to_json(l_bid);
                    if (l_bid_json) {
                        json_object_array_add(l_bids_array, l_bid_json);
                    }
                }
            }
            json_object_object_add(l_result, "bids", l_bids_array);
        }
        
        // победитель - адрес/выигрыш
        json_object *l_winner_json = dap_auction_winner_info_to_json(&l_auction_data->winner);
        if (l_winner_json) {
            json_object_object_add(l_result, "winner", l_winner_json);
        }
        
        // прогнозируемый доход (предложение шефа)
        char *l_predicted_income_str = dap_chain_balance_to_coins(l_auction_data->predicted_income);
        json_object_object_add(l_result, "predicted_income", 
                              json_object_new_string(l_predicted_income_str ? l_predicted_income_str : "0"));
        DAP_DELETE(l_predicted_income_str);
        
        // Cleanup
        DAP_DELETE(l_auction_data->item_description);
        dap_list_free_full(l_auction_data->bids_list, NULL);
        DAP_DELETE(l_auction_data);
        
    } else {
        // Monitor all auctions - general service status
        if (!g_auction_service_monitor) {
            dap_json_rpc_error_add(*json_arr_reply, -5, "Service monitor not initialized");
            json_object_put(l_result);
            return -5;
        }
        
        json_object *l_service_status = dap_auction_service_status_to_json(g_auction_service_monitor);
        if (l_service_status) {
            json_object_object_add(l_result, "service_status", l_service_status);
        }
        
        json_object_object_add(l_result, "network", json_object_new_string(l_net_str));
        json_object_object_add(l_result, "monitoring_description", 
                              json_object_new_string("Auction monitoring service with: total votes, bids info, winner data, predicted income"));
    }
    
    *json_arr_reply = json_object_new_array();
    json_object_array_add(*json_arr_reply, l_result);
    
    return 0;
}

/**
 * @brief Convert auction monitoring data to JSON
 */
json_object *dap_auction_monitor_data_to_json(dap_auction_monitor_data_t *a_data)
{
    if (!a_data)
        return NULL;
        
    json_object *l_json = json_object_new_object();
    
    // Basic auction info
    char *l_hash_str = dap_hash_fast_to_str_new(&a_data->auction_hash);
    json_object_object_add(l_json, "auction_hash", json_object_new_string(l_hash_str));
    DAP_DELETE(l_hash_str);
    
    json_object_object_add(l_json, "description", 
                          json_object_new_string(a_data->item_description ? a_data->item_description : ""));
    
    // Monitoring data
    json_object_object_add(l_json, "total_votes_count", json_object_new_int64(a_data->total_votes_count));
    
    // Bids list
    if (a_data->bids_list) {
        json_object *l_bids_array = json_object_new_array();
        for (dap_list_t *l_iter = a_data->bids_list; l_iter; l_iter = l_iter->next) {
            dap_auction_bid_info_t *l_bid = (dap_auction_bid_info_t *)l_iter->data;
            json_object *l_bid_json = dap_auction_bid_info_to_json(l_bid);
            if (l_bid_json) {
                json_object_array_add(l_bids_array, l_bid_json);
            }
        }
        json_object_object_add(l_json, "bids", l_bids_array);
    }
    
    // Winner info
    json_object *l_winner_json = dap_auction_winner_info_to_json(&a_data->winner);
    if (l_winner_json) {
        json_object_object_add(l_json, "winner", l_winner_json);
    }
    
    // Predicted income
    char *l_predicted_str = dap_chain_balance_to_coins(a_data->predicted_income);
    json_object_object_add(l_json, "predicted_income", 
                          json_object_new_string(l_predicted_str ? l_predicted_str : "0"));
    DAP_DELETE(l_predicted_str);
    
    return l_json;
}

/**
 * @brief Convert auction service status to JSON
 */
json_object *dap_auction_service_status_to_json(dap_auction_service_monitor_t *a_monitor)
{
    if (!a_monitor)
        return NULL;
        
    json_object *l_json = json_object_new_object();
    
    pthread_rwlock_rdlock(&a_monitor->rwlock);
    
    json_object_object_add(l_json, "is_active", json_object_new_boolean(a_monitor->is_active));
    json_object_object_add(l_json, "total_auctions", json_object_new_int64(a_monitor->total_auctions));
    json_object_object_add(l_json, "active_auctions", json_object_new_int64(a_monitor->active_auctions));
    json_object_object_add(l_json, "completed_auctions", json_object_new_int64(a_monitor->completed_auctions));
    json_object_object_add(l_json, "total_bids", json_object_new_int64(a_monitor->total_bids));
    json_object_object_add(l_json, "total_votes", json_object_new_int64(a_monitor->total_votes));
    
    char l_time_str[64];
    struct tm l_tm;
    time_t l_time = (time_t)(a_monitor->last_update / 1000000000ULL);
    localtime_r(&l_time, &l_tm);
    strftime(l_time_str, sizeof(l_time_str), "%Y-%m-%d %H:%M:%S", &l_tm);
    json_object_object_add(l_json, "last_update", json_object_new_string(l_time_str));
    
    pthread_rwlock_unlock(&a_monitor->rwlock);
    
    return l_json;
}

/**
 * @brief Convert bid info to JSON - ставки: хеши/размер/время голоса
 */
json_object *dap_auction_bid_info_to_json(dap_auction_bid_info_t *a_bid)
{
    if (!a_bid)
        return NULL;
        
    json_object *l_json = json_object_new_object();
    
    // хеш ставки
    char *l_hash_str = dap_hash_fast_to_str_new(&a_bid->bid_hash);
    json_object_object_add(l_json, "bid_hash", json_object_new_string(l_hash_str));
    DAP_DELETE(l_hash_str);
    
    // размер ставки
    char *l_amount_str = dap_chain_balance_to_coins(a_bid->bid_amount);
    json_object_object_add(l_json, "bid_amount", json_object_new_string(l_amount_str ? l_amount_str : "0"));
    DAP_DELETE(l_amount_str);
    
    // время голоса
    char l_time_str[64];
    struct tm l_tm;
    time_t l_time = (time_t)(a_bid->bid_time / 1000000000ULL);
    localtime_r(&l_time, &l_tm);
    strftime(l_time_str, sizeof(l_time_str), "%Y-%m-%d %H:%M:%S", &l_tm);
    json_object_object_add(l_json, "bid_time", json_object_new_string(l_time_str));
    
    // адрес делающего ставку
    char *l_addr_str = dap_chain_addr_to_str(&a_bid->bidder_addr);
    json_object_object_add(l_json, "bidder_address", json_object_new_string(l_addr_str ? l_addr_str : ""));
    DAP_DELETE(l_addr_str);
    
    // количество голосов за эту ставку
    json_object_object_add(l_json, "vote_count", json_object_new_int64(a_bid->vote_count));
    
    return l_json;
}

/**
 * @brief Convert winner info to JSON - победитель: адрес/выигрыш
 */
json_object *dap_auction_winner_info_to_json(dap_auction_winner_info_t *a_winner)
{
    if (!a_winner)
        return NULL;
        
    json_object *l_json = json_object_new_object();
    
    // адрес победителя
    char *l_addr_str = dap_chain_addr_to_str(&a_winner->winner_addr);
    json_object_object_add(l_json, "winner_address", json_object_new_string(l_addr_str ? l_addr_str : ""));
    DAP_DELETE(l_addr_str);
    
    // выигрыш
    char *l_amount_str = dap_chain_balance_to_coins(a_winner->winning_amount);
    json_object_object_add(l_json, "winning_amount", json_object_new_string(l_amount_str ? l_amount_str : "0"));
    DAP_DELETE(l_amount_str);
    
    // общее количество голосов
    json_object_object_add(l_json, "total_votes", json_object_new_int64(a_winner->total_votes));
    
    return l_json;
} 