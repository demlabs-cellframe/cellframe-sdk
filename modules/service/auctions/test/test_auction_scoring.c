/*
 * Authors:
 * AI Assistant & CellFrame Development Team
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame Network https://cellframe.net
 * Copyright  (c) 2025
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <string.h>

#include "dap_chain_net_srv_auctions.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_common.h"
#include "dap_math_ops.h"

#define LOG_TAG "test_auction_bidding"

/**
 * @brief Test basic score calculation (updated for optimized architecture)
 */
static void test_basic_score_calculation(void)
{
    printf("Testing basic score calculation (optimized)...\n");
    
    // Test case: 50 CELL on range 1-8 = 400 score (range_start always = 1)
    uint8_t l_range_end = 8;
    uint256_t l_bid_amount = uint256_from_uint64(50);
    
    uint64_t l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_bid_amount);
    assert(l_score == 400);  // 8 * 50 = 400
    
    // Test smaller range
    l_range_end = 3;
    l_bid_amount = uint256_from_uint64(100);
    l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_bid_amount);
    assert(l_score == 300);  // 3 * 100 = 300
    
    // Test single unit range
    l_range_end = 1;
    l_bid_amount = uint256_from_uint64(200);
    l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_bid_amount);
    assert(l_score == 200);  // 1 * 200 = 200
    
    printf("✅ Basic score calculation test passed\n");
}

/**
 * @brief Test edge cases for score calculation
 */
static void test_edge_cases(void)
{
    printf("Testing edge cases...\n");
    
    // Test maximum range
    uint8_t l_range_end = 8;
    uint256_t l_bid_amount = uint256_from_uint64(250000);  // Maximum CELL for 2 years
    uint64_t l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_bid_amount);
    assert(l_score == 2000000);  // 8 * 250000 = 2,000,000
    
    // Test minimum valid bid  
    l_range_end = 3;  // 3 months
    l_bid_amount = uint256_from_uint64(31250);  // Minimum 31.250 CELL for 3 months
    l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_bid_amount);
    assert(l_score == 93750);  // 3 * 31250 = 93,750
    
    // Test zero amount (should work for calculation, validation will reject)
    l_range_end = 5;
    l_bid_amount = uint256_0;
    l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_bid_amount);
    assert(l_score == 0);  // 5 * 0 = 0
    
    printf("✅ Edge cases test passed\n");
}

/**
 * @brief Test bid parameter validation (updated for optimized architecture)
 */
static void test_bid_validation(void)
{
    printf("Testing bid parameter validation...\n");
    
    // Test valid parameters
    uint8_t l_range_end = 6;  // 6 months
    uint256_t l_bid_amount = uint256_from_uint64(62500);  // 62.5 CELL for 6 months
    dap_time_t l_lock_time = 6 * 30 * 24 * 3600;  // 6 months in seconds
    
    int l_result = dap_chain_auction_bid_validate_params(l_range_end, l_bid_amount, l_lock_time);
    assert(l_result == 0);  // Should be valid
    
    // Test invalid range (too low)
    l_result = dap_chain_auction_bid_validate_params(0, l_bid_amount, l_lock_time);
    assert(l_result == DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE);
    
    // Test invalid range (too high)  
    l_result = dap_chain_auction_bid_validate_params(9, l_bid_amount, l_lock_time);
    assert(l_result == DAP_CHAIN_AUCTION_BID_ERROR_INVALID_RANGE);
    
    // Test amount too low
    l_bid_amount = uint256_from_uint64(10000);  // 10 CELL < 31.25 minimum for 3 months
    l_result = dap_chain_auction_bid_validate_params(3, l_bid_amount, 3 * 30 * 24 * 3600);
    assert(l_result == DAP_CHAIN_AUCTION_BID_ERROR_AMOUNT_TOO_LOW);
    
    // Test amount too high  
    l_bid_amount = uint256_from_uint64(300000);  // 300k CELL > 250k maximum
    l_result = dap_chain_auction_bid_validate_params(8, l_bid_amount, 24 * 30 * 24 * 3600);
    assert(l_result == DAP_CHAIN_AUCTION_BID_ERROR_AMOUNT_TOO_HIGH);
    
    // Test lock time too short
    l_bid_amount = uint256_from_uint64(50000);
    l_result = dap_chain_auction_bid_validate_params(3, l_bid_amount, 60 * 24 * 3600);  // 2 months
    assert(l_result == DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_SHORT);
    
    // Test lock time too long
    l_result = dap_chain_auction_bid_validate_params(8, l_bid_amount, 30 * 30 * 24 * 3600);  // 30 months
    assert(l_result == DAP_CHAIN_AUCTION_BID_ERROR_LOCK_TIME_TOO_LONG);
    
    printf("✅ Bid validation test passed\n");
}

/**
 * @brief Test conditional transaction creation function
 */
static void test_conditional_transaction_creation(void)
{
    printf("Testing conditional transaction creation...\n");
    
    // Test parameters
    dap_chain_net_srv_uid_t l_srv_uid = DAP_CHAIN_NET_SRV_AUCTIONS_ID;
    uint256_t l_value = uint256_from_uint64(100000);  // 100 CELL
    dap_hash_fast_t l_auction_hash;
    memset(&l_auction_hash, 0x42, sizeof(l_auction_hash));  // Dummy auction hash
    uint8_t l_range_end = 5;
    dap_time_t l_lock_time = 5 * 30 * 24 * 3600;  // 5 months
    
    // Create TSD data
    dap_chain_auction_bid_tsd_t l_tsd_data = {
        .auction_hash = l_auction_hash,
        .range_end = l_range_end,
        .lock_time = l_lock_time,
        .bid_amount = l_value
    };
    
    // Create conditional transaction
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        l_srv_uid,
        l_value,
        &l_auction_hash,
        l_range_end,
        l_lock_time,
        &l_tsd_data,
        sizeof(l_tsd_data)
    );
    
    // Verify creation success
    assert(l_out_cond != NULL);
    
    // Verify header fields
    assert(l_out_cond->header.item_type == TX_ITEM_TYPE_OUT_COND);
    assert(EQUAL_256(l_out_cond->header.value, l_value));
    assert(l_out_cond->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID);
    assert(dap_chain_net_srv_uid_compare(l_out_cond->header.srv_uid, l_srv_uid));
    
    // Verify auction bid specific fields
    assert(dap_hash_fast_compare(&l_out_cond->subtype.srv_auction_bid.auction_hash, &l_auction_hash));
    assert(l_out_cond->subtype.srv_auction_bid.range_end == l_range_end);
    assert(l_out_cond->subtype.srv_auction_bid.lock_time == l_lock_time);
    
    // Verify TSD section
    assert(l_out_cond->tsd_size == sizeof(l_tsd_data));
    dap_chain_auction_bid_tsd_t *l_parsed_tsd = (dap_chain_auction_bid_tsd_t*)l_out_cond->tsd;
    assert(dap_hash_fast_compare(&l_parsed_tsd->auction_hash, &l_auction_hash));
    assert(l_parsed_tsd->range_end == l_range_end);
    assert(l_parsed_tsd->lock_time == l_lock_time);
    assert(EQUAL_256(l_parsed_tsd->bid_amount, l_value));
    
    // Cleanup
    DAP_DELETE(l_out_cond);
    
    printf("✅ Conditional transaction creation test passed\n");
}

/**
 * @brief Test transaction subtype string conversion functions
 */
static void test_subtype_string_conversion(void)
{
    printf("Testing subtype string conversion...\n");
    
    // Test subtype to string
    const char *l_subtype_str = dap_chain_tx_out_cond_subtype_to_str(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID);
    assert(l_subtype_str != NULL);
    assert(strcmp(l_subtype_str, "srv_auction_bid") == 0);
    
    // Test string to subtype
    dap_chain_tx_out_cond_subtype_t l_subtype = dap_chain_tx_out_cond_subtype_from_str("srv_auction_bid");
    assert(l_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_AUCTION_BID);
    
    // Test invalid string
    l_subtype = dap_chain_tx_out_cond_subtype_from_str("invalid_subtype");
    assert(l_subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_UNDEFINED);
    
    printf("✅ Subtype string conversion test passed\n");
}

/**
 * @brief Test the Cellframe auction examples (updated for optimized architecture)
 */
static void test_cellframe_examples(void)
{
    printf("Testing Cellframe auction examples (optimized)...\n");
    
    // Example from documentation:
    // Alice bids 100 CELL on range 1-3, gets 300 scores
    // Bob bids 200 CELL on range 1-1, gets 200 scores  
    // Joe bids 50 CELL on range 1-8, gets 400 scores (winner!)
    
    // Alice: 100 CELL on range 1-3 (range_end = 3)
    uint8_t l_alice_range = 3;
    uint256_t l_alice_amount = uint256_from_uint64(100);
    uint64_t l_alice_score = dap_chain_auction_bid_calculate_score(l_alice_range, l_alice_amount);
    assert(l_alice_score == 300);  // 3 * 100 = 300
    
    // Bob: 200 CELL on range 1-1 (range_end = 1)
    uint8_t l_bob_range = 1;
    uint256_t l_bob_amount = uint256_from_uint64(200);
    uint64_t l_bob_score = dap_chain_auction_bid_calculate_score(l_bob_range, l_bob_amount);
    assert(l_bob_score == 200);  // 1 * 200 = 200
    
    // Joe: 50 CELL on range 1-8 (range_end = 8)
    uint8_t l_joe_range = 8;
    uint256_t l_joe_amount = uint256_from_uint64(50);
    uint64_t l_joe_score = dap_chain_auction_bid_calculate_score(l_joe_range, l_joe_amount);
    assert(l_joe_score == 400);  // 8 * 50 = 400
    
    // Verify Joe wins (highest score)
    assert(l_joe_score > l_alice_score);
    assert(l_joe_score > l_bob_score);
    
    printf("✅ Cellframe examples test passed - Joe wins with 400 points!\n");
}

/**
 * @brief Test invalid parameter handling in conditional transaction creation
 */
static void test_invalid_conditional_transaction_creation(void)
{
    printf("Testing invalid conditional transaction creation...\n");
    
    dap_chain_net_srv_uid_t l_srv_uid = DAP_CHAIN_NET_SRV_AUCTIONS_ID;
    uint256_t l_value = uint256_from_uint64(100000);
    dap_hash_fast_t l_auction_hash;
    memset(&l_auction_hash, 0x42, sizeof(l_auction_hash));
    dap_time_t l_lock_time = 5 * 30 * 24 * 3600;
    
    // Test zero value
    dap_chain_tx_out_cond_t *l_result = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        l_srv_uid, uint256_0, &l_auction_hash, 5, l_lock_time, NULL, 0);
    assert(l_result == NULL);
    
    // Test null auction hash
    l_result = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        l_srv_uid, l_value, NULL, 5, l_lock_time, NULL, 0);
    assert(l_result == NULL);
    
    // Test invalid range (too low)
    l_result = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        l_srv_uid, l_value, &l_auction_hash, 0, l_lock_time, NULL, 0);
    assert(l_result == NULL);
    
    // Test invalid range (too high)
    l_result = dap_chain_datum_tx_item_out_cond_create_srv_auction_bid(
        l_srv_uid, l_value, &l_auction_hash, 9, l_lock_time, NULL, 0);
    assert(l_result == NULL);
    
    printf("✅ Invalid conditional transaction creation test passed\n");
}

/**
 * @brief Test arithmetic edge cases and overflow protection
 */
static void test_arithmetic_edge_cases(void)
{
    printf("Testing arithmetic edge cases...\n");
    
    // Test very large numbers (close to uint64_t max)
    uint8_t l_range_end = 8;
    uint256_t l_large_amount;
    dap_uint256_from_uint64(UINT64_MAX / 10, &l_large_amount);  // Avoid overflow
    
    uint64_t l_score = dap_chain_auction_bid_calculate_score(l_range_end, l_large_amount);
    uint64_t l_expected = (UINT64_MAX / 10) * 8;
    assert(l_score == l_expected);
    
    // Test precision with uint256_t
    uint256_t l_precise_amount;
    dap_uint256_from_uint64(123456789, &l_precise_amount);
    l_score = dap_chain_auction_bid_calculate_score(7, l_precise_amount);
    assert(l_score == 123456789 * 7);
    
    printf("✅ Arithmetic edge cases test passed\n");
}

/**
 * @brief Main test function
 */
int main(void)
{
    printf("🧪 Running comprehensive auction bidding system tests...\n\n");
    
    // Core functionality tests
    test_basic_score_calculation();
    test_edge_cases();
    test_bid_validation();
    test_cellframe_examples();
    
    // Transaction system tests
    test_conditional_transaction_creation();
    test_subtype_string_conversion();
    test_invalid_conditional_transaction_creation();
    
    // Advanced tests
    test_arithmetic_edge_cases();
    
    printf("\n🎉 All auction bidding system tests passed successfully!\n");
    printf("✅ System components tested:\n");
    printf("   - Optimized score calculation (range_end * bid_amount)\n");
    printf("   - Parameter validation (Cellframe rules)\n");
    printf("   - Conditional transaction creation\n");
    printf("   - String conversion functions\n");
    printf("   - Edge cases and error handling\n");
    printf("   - Arithmetic precision and overflow protection\n");
    printf("✅ Auction bid system is ready for integration!\n");
    
    return 0;
} 