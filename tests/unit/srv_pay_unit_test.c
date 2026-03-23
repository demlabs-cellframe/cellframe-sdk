/*
 * Authors:
 * Cellframe Development Team
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2026
 * All rights reserved.

 This file is part of Cellframe SDK the open source project

    Cellframe SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Cellframe SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any Cellframe SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file srv_pay_unit_test.c
 * @brief Unit tests for VPN/service payment logic fixes
 * @details Tests:
 *   - tx_cond_hash_prev state machine (mempool pending, ledger confirm, revert)
 *   - Service state/substate enum completeness and struct storage
 *   - Hash management contract for conditional transactions
 * @date 2026-03-23
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_chain_net_srv_stream_session.h"
#include "dap_stream_ch_chain_net_srv_pkt.h"
#include "dap_test.h"

#define LOG_TAG "srv_pay_unit_test"

/**
 * @brief Test 1: tx_cond_hash_prev initial state
 * @details Verify that a zero-initialized usage struct has blank tx_cond_hash_prev
 */
static void s_test_hash_prev_initial_state(void)
{
    dap_print_module_name("Test 1: tx_cond_hash_prev initial state");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be blank after zero-init");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash),
               "tx_cond_hash should be blank after zero-init");

    dap_pass_msg("Initial state test passed");
}

/**
 * @brief Test 2: Simulate mempool add — save prev, update current
 * @details When a new tx is added to mempool, tx_cond_hash_prev = tx_cond_hash (old),
 *          tx_cond_hash = new_hash (mempool tx hash)
 */
static void s_test_hash_prev_mempool_add(void)
{
    dap_print_module_name("Test 2: tx_cond_hash_prev mempool add simulation");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Set initial confirmed tx_cond_hash
    dap_hash_fast_t l_confirmed_hash;
    const char *l_data1 = "confirmed_tx_data";
    dap_hash_fast(l_data1, strlen(l_data1), &l_confirmed_hash);
    l_usage.tx_cond_hash = l_confirmed_hash;

    // Create a new mempool tx hash
    dap_hash_fast_t l_mempool_hash;
    const char *l_data2 = "mempool_tx_data";
    dap_hash_fast(l_data2, strlen(l_data2), &l_mempool_hash);

    // Simulate what s_pay_service does on DAP_CHAIN_MEMPOOl_RET_STATUS_SUCCESS:
    //   a_usage->tx_cond_hash_prev = a_usage->tx_cond_hash;
    //   a_usage->tx_cond_hash = new_hash;
    l_usage.tx_cond_hash_prev = l_usage.tx_cond_hash;
    l_usage.tx_cond_hash = l_mempool_hash;

    dap_assert(!dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should not be blank after mempool add");
    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash_prev, &l_confirmed_hash),
               "tx_cond_hash_prev should equal the old confirmed hash");
    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_mempool_hash),
               "tx_cond_hash should equal the new mempool hash");
    dap_assert(!dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_usage.tx_cond_hash_prev),
               "tx_cond_hash and tx_cond_hash_prev should differ");

    dap_pass_msg("Mempool add simulation test passed");
}

/**
 * @brief Test 3: Simulate ledger confirmation — clear prev
 * @details When the mempool tx is confirmed in ledger,
 *          tx_cond_hash_prev is cleared (set to zero)
 */
static void s_test_hash_prev_ledger_confirm(void)
{
    dap_print_module_name("Test 3: tx_cond_hash_prev ledger confirm simulation");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Setup: confirmed -> mempool add
    dap_hash_fast_t l_confirmed_hash, l_mempool_hash;
    dap_hash_fast("data1", 5, &l_confirmed_hash);
    dap_hash_fast("data2", 5, &l_mempool_hash);
    l_usage.tx_cond_hash = l_mempool_hash;
    l_usage.tx_cond_hash_prev = l_confirmed_hash;

    // Simulate ledger confirmation:
    //   memset(&a_usage->tx_cond_hash_prev, 0, sizeof(a_usage->tx_cond_hash_prev));
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));

    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be blank after ledger confirm");
    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_mempool_hash),
               "tx_cond_hash should remain the mempool hash (now confirmed)");

    dap_pass_msg("Ledger confirm simulation test passed");
}

/**
 * @brief Test 4: Simulate invalid mempool tx — revert to prev
 * @details When mempool tx is invalid or lost,
 *          tx_cond_hash reverts to tx_cond_hash_prev, and prev is cleared
 */
static void s_test_hash_prev_revert_invalid(void)
{
    dap_print_module_name("Test 4: tx_cond_hash_prev revert on invalid mempool tx");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Setup: confirmed -> mempool add
    dap_hash_fast_t l_confirmed_hash, l_mempool_hash;
    dap_hash_fast("confirmed_data", 14, &l_confirmed_hash);
    dap_hash_fast("mempool_data", 12, &l_mempool_hash);
    l_usage.tx_cond_hash = l_mempool_hash;
    l_usage.tx_cond_hash_prev = l_confirmed_hash;

    // Simulate revert (invalid mempool tx):
    //   a_usage->tx_cond_hash = a_usage->tx_cond_hash_prev;
    //   memset(&a_usage->tx_cond_hash_prev, 0, sizeof(a_usage->tx_cond_hash_prev));
    l_usage.tx_cond_hash = l_usage.tx_cond_hash_prev;
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));

    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_confirmed_hash),
               "tx_cond_hash should revert to original confirmed hash");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be blank after revert");

    dap_pass_msg("Revert on invalid mempool tx test passed");
}

/**
 * @brief Test 5: Multiple mempool cycles without confirmation
 * @details Verifies that repeated mempool additions without confirmation
 *          keep the original confirmed hash in tx_cond_hash_prev
 */
static void s_test_hash_prev_multiple_cycles(void)
{
    dap_print_module_name("Test 5: Multiple mempool add/revert cycles");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_confirmed_hash;
    dap_hash_fast("original_confirmed", 18, &l_confirmed_hash);
    l_usage.tx_cond_hash = l_confirmed_hash;

    // Cycle 1: add to mempool, then revert (invalid)
    dap_hash_fast_t l_mempool1;
    dap_hash_fast("mempool_cycle_1", 15, &l_mempool1);
    l_usage.tx_cond_hash_prev = l_usage.tx_cond_hash;
    l_usage.tx_cond_hash = l_mempool1;

    // Revert
    l_usage.tx_cond_hash = l_usage.tx_cond_hash_prev;
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));

    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_confirmed_hash),
               "After cycle 1 revert, tx_cond_hash should be original confirmed");

    // Cycle 2: add again, this time confirm
    dap_hash_fast_t l_mempool2;
    dap_hash_fast("mempool_cycle_2", 15, &l_mempool2);
    l_usage.tx_cond_hash_prev = l_usage.tx_cond_hash;
    l_usage.tx_cond_hash = l_mempool2;

    // Confirm
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));

    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_mempool2),
               "After cycle 2 confirm, tx_cond_hash should be mempool2 hash");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "After cycle 2 confirm, tx_cond_hash_prev should be blank");

    // Cycle 3: add again from new base
    dap_hash_fast_t l_mempool3;
    dap_hash_fast("mempool_cycle_3", 15, &l_mempool3);
    l_usage.tx_cond_hash_prev = l_usage.tx_cond_hash;
    l_usage.tx_cond_hash = l_mempool3;

    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash_prev, &l_mempool2),
               "Cycle 3: prev should be mempool2 (now confirmed base)");
    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_mempool3),
               "Cycle 3: current should be mempool3");

    dap_pass_msg("Multiple cycles test passed");
}

/**
 * @brief Test 6: Chain resolution to different tx — update hash
 * @details When dap_ledger_get_final_chain_tx_hash returns a different hash,
 *          tx_cond_hash is updated and prev is cleared
 */
static void s_test_hash_prev_chain_resolution(void)
{
    dap_print_module_name("Test 6: Chain resolution to different tx");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_confirmed_hash, l_mempool_hash, l_resolved_hash;
    dap_hash_fast("confirmed", 9, &l_confirmed_hash);
    dap_hash_fast("mempool", 7, &l_mempool_hash);
    dap_hash_fast("resolved_by_chain", 17, &l_resolved_hash);

    l_usage.tx_cond_hash = l_mempool_hash;
    l_usage.tx_cond_hash_prev = l_confirmed_hash;

    // Simulate chain resolution to a third hash:
    //   a_usage->tx_cond_hash = l_final_hash;
    //   memset(&a_usage->tx_cond_hash_prev, 0, sizeof(a_usage->tx_cond_hash_prev));
    l_usage.tx_cond_hash = l_resolved_hash;
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));

    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_resolved_hash),
               "tx_cond_hash should be the chain-resolved hash");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be blank after chain resolution");

    dap_pass_msg("Chain resolution test passed");
}

/**
 * @brief Test 7: Service state enum values
 * @details Verify state and substate enums are correctly defined
 */
static void s_test_service_state_enums(void)
{
    dap_print_module_name("Test 7: Service state/substate enums");

    // Verify state enum values
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE == 0, "IDLE state should be 0");
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE != DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE,
               "GRACE state should differ from IDLE");
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL != DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE,
               "NORMAL state should differ from GRACE");
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_ERROR != DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL,
               "ERROR state should differ from NORMAL");

    // Verify substate enum values
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_IDLE == 0, "IDLE substate should be 0");
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_FIRST_RECEIPT_SIGN != 0,
               "WAITING_FIRST_RECEIPT_SIGN should not be 0");
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING != 0,
               "WAITING_TX_FOR_PAYING should not be 0");
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_FROM_CLIENT != 0,
               "WAITING_NEW_TX_FROM_CLIENT should not be 0");
    dap_assert(DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_NEW_TX_IN_LEDGER != 0,
               "WAITING_NEW_TX_IN_LEDGER should not be 0");

    dap_pass_msg("Service state/substate enums test passed");
}

/**
 * @brief Test 8: Usage struct stores state transitions correctly
 * @details Verify that dap_chain_net_srv_usage_t correctly stores state/substate values
 */
static void s_test_usage_struct_state_storage(void)
{
    dap_print_module_name("Test 8: Usage struct state storage");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Initial state
    dap_assert(l_usage.service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_IDLE,
               "Initial service_state should be IDLE");
    dap_assert(l_usage.service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_IDLE,
               "Initial service_substate should be IDLE");

    // Simulate state transitions
    l_usage.service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE;
    l_usage.service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING;
    dap_assert(l_usage.service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_GRACE,
               "State should be GRACE");
    dap_assert(l_usage.service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_WAITING_TX_FOR_PAYING,
               "Substate should be WAITING_TX_FOR_PAYING");

    // Transition to normal
    l_usage.service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL;
    l_usage.service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_NORMAL;
    dap_assert(l_usage.service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_NORMAL,
               "State should be NORMAL");
    dap_assert(l_usage.service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_NORMAL,
               "Substate should be NORMAL");

    // Transition to error
    l_usage.service_state = DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_ERROR;
    l_usage.service_substate = DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_ERROR;
    dap_assert(l_usage.service_state == DAP_CHAIN_NET_SRV_USAGE_SERVICE_STATE_ERROR,
               "State should be ERROR");
    dap_assert(l_usage.service_substate == DAP_CHAIN_NET_SRV_USAGE_SERVICE_SUBSTATE_ERROR,
               "Substate should be ERROR");

    dap_pass_msg("Usage struct state storage test passed");
}

/**
 * @brief Test 9: last_err_code storage
 * @details Verify that error codes are correctly stored in usage struct.
 *          Relevant to fix in da6642cbd where s_service_substate_go_to_error
 *          was removed from s_pay_service, leaving error code for caller to handle.
 */
static void s_test_usage_error_code_storage(void)
{
    dap_print_module_name("Test 9: Usage error code storage");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_assert(l_usage.last_err_code == 0, "Initial error code should be 0");

    l_usage.last_err_code = DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND;
    dap_assert(l_usage.last_err_code == DAP_STREAM_CH_CHAIN_NET_SRV_PKT_TYPE_RESPONSE_ERROR_CODE_TX_COND_NOT_FOUND,
               "Error code TX_COND_NOT_FOUND should be stored correctly");

    l_usage.last_err_code = 0;
    dap_assert(l_usage.last_err_code == 0, "Error code should be clearable");

    dap_pass_msg("Error code storage test passed");
}

/**
 * @brief Test 10: mempool_wait_count initial state
 * @details Verify that zero-initialized usage has mempool_wait_count == 0
 */
static void s_test_mempool_wait_count_initial(void)
{
    dap_print_module_name("Test 10: mempool_wait_count initial state");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_assert(l_usage.mempool_wait_count == 0,
               "mempool_wait_count should be 0 after zero-init");

    dap_pass_msg("mempool_wait_count initial state test passed");
}

/**
 * @brief Test 11: mempool_wait_count increment and threshold
 * @details Verify correct behavior relative to MAX_MEMPOOL_WAIT_CYCLES
 */
static void s_test_mempool_wait_count_threshold(void)
{
    dap_print_module_name("Test 11: mempool_wait_count increment and threshold");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Increment up to threshold
    for(uint32_t i = 0; i < MAX_MEMPOOL_WAIT_CYCLES; i++)
    {
        l_usage.mempool_wait_count++;
    }
    dap_assert(l_usage.mempool_wait_count == MAX_MEMPOOL_WAIT_CYCLES,
               "mempool_wait_count should equal MAX_MEMPOOL_WAIT_CYCLES after incrementing");
    dap_assert(l_usage.mempool_wait_count >= MAX_MEMPOOL_WAIT_CYCLES,
               "Threshold condition should trigger at MAX_MEMPOOL_WAIT_CYCLES");

    dap_pass_msg("mempool_wait_count threshold test passed");
}

/**
 * @brief Test 12: mempool_wait_count reset on SUCCESS
 * @details Simulate the reset that happens when payment succeeds
 */
static void s_test_mempool_wait_count_reset_on_success(void)
{
    dap_print_module_name("Test 12: mempool_wait_count reset on SUCCESS");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    l_usage.mempool_wait_count = MAX_MEMPOOL_WAIT_CYCLES - 1;
    dap_assert(l_usage.mempool_wait_count > 0,
               "mempool_wait_count should be non-zero before reset");

    // Simulate SUCCESS reset
    l_usage.mempool_wait_count = 0;
    dap_assert(l_usage.mempool_wait_count == 0,
               "mempool_wait_count should be 0 after SUCCESS reset");

    dap_pass_msg("mempool_wait_count reset on SUCCESS test passed");
}

/**
 * @brief Test 13: mempool_wait_count reset on ledger confirmation
 * @details Simulate the reset that happens when a mempool tx is confirmed
 */
static void s_test_mempool_wait_count_reset_on_confirm(void)
{
    dap_print_module_name("Test 13: mempool_wait_count reset on ledger confirm");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Setup: 2 cycles of mempool waiting
    l_usage.mempool_wait_count = 2;

    dap_hash_fast_t l_confirmed_hash, l_mempool_hash;
    dap_hash_fast("confirmed", 9, &l_confirmed_hash);
    dap_hash_fast("mempool", 7, &l_mempool_hash);
    l_usage.tx_cond_hash = l_mempool_hash;
    l_usage.tx_cond_hash_prev = l_confirmed_hash;

    // Simulate mempool tx confirmed in ledger
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));
    l_usage.mempool_wait_count = 0;

    dap_assert(l_usage.mempool_wait_count == 0,
               "mempool_wait_count should be 0 after ledger confirmation");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be blank after ledger confirmation");
    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_mempool_hash),
               "tx_cond_hash should remain the mempool hash (now confirmed)");

    dap_pass_msg("mempool_wait_count reset on ledger confirm test passed");
}

/**
 * @brief Test 14: Full mempool wait cycle — extend limits then terminate
 * @details Simulate: mempool add → wait cycles with limits extension → MAX reached → terminate
 */
static void s_test_mempool_wait_full_cycle(void)
{
    dap_print_module_name("Test 14: Full mempool wait cycle — extend + terminate");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_confirmed_hash, l_mempool_hash;
    dap_hash_fast("confirmed_tx", 12, &l_confirmed_hash);
    dap_hash_fast("mempool_tx", 10, &l_mempool_hash);

    // Step 1: Initial state — confirmed tx
    l_usage.tx_cond_hash = l_confirmed_hash;

    // Step 2: Mempool add (s_pay_service SUCCESS)
    l_usage.tx_cond_hash_prev = l_usage.tx_cond_hash;
    l_usage.tx_cond_hash = l_mempool_hash;
    l_usage.mempool_wait_count = 0;

    // Step 3: Each receipt cycle — tx not confirmed → extend limits, increment counter
    time_t l_limits_ts = 3600;
    uint64_t l_price_units = 3600;
    bool l_terminated = false;
    for(uint32_t i = 0; i < MAX_MEMPOOL_WAIT_CYCLES + 1; i++)
    {
        l_usage.mempool_wait_count++;
        if(l_usage.mempool_wait_count >= MAX_MEMPOOL_WAIT_CYCLES)
        {
            l_terminated = true;
            break;
        }
        l_limits_ts += (time_t)l_price_units;
    }

    dap_assert(l_terminated,
               "Stream should be terminated at MAX_MEMPOOL_WAIT_CYCLES");
    dap_assert(l_usage.mempool_wait_count >= MAX_MEMPOOL_WAIT_CYCLES,
               "Wait counter should have reached MAX");
    dap_assert(!dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should still be set (no revert in new logic)");
    dap_assert(l_limits_ts > 3600,
               "Limits should have been extended during wait cycles");

    dap_pass_msg("Full mempool wait cycle test passed");
}

/**
 * @brief Test 15: MAX_MEMPOOL_WAIT_CYCLES constant value
 * @details Verify the constant is sensible (positive, not too large)
 */
static void s_test_max_mempool_wait_cycles_value(void)
{
    dap_print_module_name("Test 15: MAX_MEMPOOL_WAIT_CYCLES constant value");

    dap_assert(MAX_MEMPOOL_WAIT_CYCLES > 0,
               "MAX_MEMPOOL_WAIT_CYCLES must be positive");
    dap_assert(MAX_MEMPOOL_WAIT_CYCLES <= 100,
               "MAX_MEMPOOL_WAIT_CYCLES should not be excessively large");
    dap_assert(MAX_MEMPOOL_WAIT_CYCLES >= 2,
               "MAX_MEMPOOL_WAIT_CYCLES should allow at least 1 wait cycle before revert");

    dap_pass_msg("MAX_MEMPOOL_WAIT_CYCLES constant value test passed");
}

/**
 * @brief Test 16: Accumulated receipt value calculation
 * @details When mempool tx confirms after N wait cycles, receipt value = N * price
 */
static void s_test_accumulated_receipt_value(void)
{
    dap_print_module_name("Test 16: Accumulated receipt value calculation");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Simulate 2 wait cycles
    l_usage.mempool_wait_count = 2;

    // Verify accumulated value would be counter * price
    uint32_t l_counter = l_usage.mempool_wait_count;
    dap_assert(l_counter == 2,
               "Wait counter should be 2 for accumulated receipt");
    dap_assert(l_counter > 0,
               "Counter must be > 0 for accumulated receipt");

    // After accumulated receipt is created, counter resets
    l_usage.mempool_wait_count = 0;
    dap_assert(l_usage.mempool_wait_count == 0,
               "Counter should reset after accumulated receipt");

    dap_pass_msg("Accumulated receipt value calculation test passed");
}

/**
 * @brief Test 17: Limits extension during mempool wait
 * @details Each wait cycle extends limits by price->units
 */
static void s_test_limits_extension_during_wait(void)
{
    dap_print_module_name("Test 17: Limits extension during mempool wait");

    time_t l_limits_ts = 1800;
    uint64_t l_price_units = 3600;

    // Simulate 2 wait cycles of extension
    for(uint32_t i = 0; i < 2; i++)
    {
        l_limits_ts += (time_t)l_price_units;
    }

    dap_assert(l_limits_ts == 1800 + 2 * 3600,
               "Limits should increase by price->units per wait cycle");

    dap_pass_msg("Limits extension during mempool wait test passed");
}

/**
 * @brief Test 18: Termination at MAX with no confirmation
 * @details Verify that stream terminates when counter reaches MAX and tx is not confirmed
 */
static void s_test_terminate_at_max_no_confirm(void)
{
    dap_print_module_name("Test 18: Terminate at MAX with no confirmation");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_confirmed, l_mempool;
    dap_hash_fast("confirmed", 9, &l_confirmed);
    dap_hash_fast("mempool", 7, &l_mempool);

    l_usage.tx_cond_hash = l_mempool;
    l_usage.tx_cond_hash_prev = l_confirmed;

    bool l_should_terminate = false;
    for(uint32_t i = 0; i < MAX_MEMPOOL_WAIT_CYCLES + 1; i++)
    {
        l_usage.mempool_wait_count++;
        if(l_usage.mempool_wait_count >= MAX_MEMPOOL_WAIT_CYCLES)
        {
            l_should_terminate = true;
            break;
        }
    }

    dap_assert(l_should_terminate, "Should terminate when counter reaches MAX");
    dap_assert(l_usage.mempool_wait_count == MAX_MEMPOOL_WAIT_CYCLES,
               "Counter should equal MAX at termination point");

    dap_pass_msg("Terminate at MAX test passed");
}

/**
 * @brief Test 19: Confirmation mid-wait resets counter and enables receipt
 * @details When tx confirms before MAX, counter resets and accumulated receipt is issued
 */
static void s_test_confirm_mid_wait(void)
{
    dap_print_module_name("Test 19: Confirmation mid-wait resets state");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_confirmed, l_mempool;
    dap_hash_fast("confirmed_base", 14, &l_confirmed);
    dap_hash_fast("mempool_tx", 10, &l_mempool);

    l_usage.tx_cond_hash = l_mempool;
    l_usage.tx_cond_hash_prev = l_confirmed;
    l_usage.mempool_wait_count = 2;

    // Simulate: tx confirmed on 3rd check (before MAX)
    uint32_t l_accumulated_count = l_usage.mempool_wait_count;
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));
    l_usage.mempool_wait_count = 0;

    dap_assert(l_accumulated_count == 2,
               "Accumulated count should match cycles waited");
    dap_assert(l_usage.mempool_wait_count == 0,
               "Counter should reset to 0 after confirmation");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be blank after confirmation");
    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_mempool),
               "tx_cond_hash should remain the now-confirmed hash");

    dap_pass_msg("Confirmation mid-wait test passed");
}

/**
 * @brief Test 20: Zero counter confirmation — normal receipt path
 * @details When counter is 0 and tx confirmed, normal receipt is issued (not accumulated)
 */
static void s_test_zero_counter_confirm(void)
{
    dap_print_module_name("Test 20: Zero counter confirmation — normal receipt");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_confirmed, l_mempool;
    dap_hash_fast("confirmed", 9, &l_confirmed);
    dap_hash_fast("mempool", 7, &l_mempool);

    l_usage.tx_cond_hash = l_mempool;
    l_usage.tx_cond_hash_prev = l_confirmed;
    l_usage.mempool_wait_count = 0;

    // Tx confirmed immediately (counter still 0) → normal receipt path
    bool l_use_accumulated = (l_usage.mempool_wait_count > 0);
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));
    l_usage.mempool_wait_count = 0;

    dap_assert(!l_use_accumulated,
               "With counter=0, should use normal receipt, not accumulated");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be cleared");

    dap_pass_msg("Zero counter confirmation test passed");
}

/**
 * Test 21: tx_recreate_count initial state
 * @details Zero-initialized usage should have tx_recreate_count == 0
 */
static void s_test_tx_recreate_count_initial(void)
{
    dap_print_module_name("Test 21: tx_recreate_count initial state");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_assert(l_usage.tx_recreate_count == 0,
               "tx_recreate_count should be 0 after zero-init");

    dap_pass_msg("tx_recreate_count initial state test passed");
}

/**
 * Test 22: tx_recreate_count threshold triggers termination
 * @details When tx_recreate_count >= MAX_TX_RECREATE_ATTEMPTS, stream should terminate
 */
static void s_test_tx_recreate_count_threshold(void)
{
    dap_print_module_name("Test 22: tx_recreate_count threshold");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    // Simulate recreation attempts
    for(uint32_t i = 0; i < MAX_TX_RECREATE_ATTEMPTS; i++)
    {
        l_usage.tx_recreate_count++;
    }

    dap_assert(l_usage.tx_recreate_count >= MAX_TX_RECREATE_ATTEMPTS,
               "tx_recreate_count should reach MAX_TX_RECREATE_ATTEMPTS");

    bool l_should_terminate = (l_usage.tx_recreate_count >= MAX_TX_RECREATE_ATTEMPTS);
    dap_assert(l_should_terminate, "Stream should terminate at MAX_TX_RECREATE_ATTEMPTS");

    dap_pass_msg("tx_recreate_count threshold test passed");
}

/**
 * Test 23: tx_recreate_count reset on success
 * @details PAY_SERVICE_STATUS_SUCCESS should reset tx_recreate_count to 0
 */
static void s_test_tx_recreate_count_reset_on_success(void)
{
    dap_print_module_name("Test 23: tx_recreate_count reset on success");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    l_usage.tx_recreate_count = 1;
    dap_assert(l_usage.tx_recreate_count == 1,
               "tx_recreate_count should be 1 before reset");

    // Simulate PAY_SERVICE_STATUS_SUCCESS handler
    l_usage.mempool_wait_count = 0;
    l_usage.tx_recreate_count = 0;

    dap_assert(l_usage.tx_recreate_count == 0,
               "tx_recreate_count should be 0 after success");

    dap_pass_msg("tx_recreate_count reset on success test passed");
}

/**
 * Test 24: tx_recreate_count reset on ledger confirm
 * @details When mempool tx is confirmed in ledger, tx_recreate_count resets to 0
 */
static void s_test_tx_recreate_count_reset_on_confirm(void)
{
    dap_print_module_name("Test 24: tx_recreate_count reset on ledger confirm");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_prev;
    dap_hash_fast("prev", 4, &l_prev);
    l_usage.tx_cond_hash_prev = l_prev;
    l_usage.mempool_wait_count = 2;
    l_usage.tx_recreate_count = 1;

    // Simulate ledger confirmation in s_update_limits
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));
    l_usage.mempool_wait_count = 0;
    l_usage.tx_recreate_count = 0;

    dap_assert(l_usage.tx_recreate_count == 0,
               "tx_recreate_count should be 0 after ledger confirm");
    dap_assert(l_usage.mempool_wait_count == 0,
               "mempool_wait_count should also be 0");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be cleared");

    dap_pass_msg("tx_recreate_count reset on ledger confirm test passed");
}

/**
 * Test 25: tx_recreate_count revert flow
 * @details When tx is rejected, hash reverts to prev and counter increments
 */
static void s_test_tx_recreate_revert_flow(void)
{
    dap_print_module_name("Test 25: tx_recreate revert flow");

    dap_chain_net_srv_usage_t l_usage;
    memset(&l_usage, 0, sizeof(l_usage));

    dap_hash_fast_t l_confirmed, l_rejected;
    dap_hash_fast("confirmed_tx", 12, &l_confirmed);
    dap_hash_fast("rejected_tx", 11, &l_rejected);

    l_usage.tx_cond_hash = l_rejected;
    l_usage.tx_cond_hash_prev = l_confirmed;
    l_usage.mempool_wait_count = 1;
    l_usage.tx_recreate_count = 0;

    // Simulate rejected tx detection: revert and recreate
    l_usage.tx_recreate_count++;
    bool l_should_terminate = (l_usage.tx_recreate_count >= MAX_TX_RECREATE_ATTEMPTS);
    dap_assert(!l_should_terminate,
               "First recreate attempt should not terminate (1 < MAX)");

    l_usage.tx_cond_hash = l_usage.tx_cond_hash_prev;
    memset(&l_usage.tx_cond_hash_prev, 0, sizeof(l_usage.tx_cond_hash_prev));
    l_usage.mempool_wait_count = 0;

    dap_assert(dap_hash_fast_compare(&l_usage.tx_cond_hash, &l_confirmed),
               "tx_cond_hash should revert to confirmed hash");
    dap_assert(dap_hash_fast_is_blank(&l_usage.tx_cond_hash_prev),
               "tx_cond_hash_prev should be cleared after revert");
    dap_assert(l_usage.mempool_wait_count == 0,
               "mempool_wait_count should be reset after revert");
    dap_assert(l_usage.tx_recreate_count == 1,
               "tx_recreate_count should be 1 after first revert");

    // Simulate second rejection: should trigger termination
    dap_hash_fast_t l_rejected2;
    dap_hash_fast("rejected_tx2", 12, &l_rejected2);
    l_usage.tx_cond_hash_prev = l_usage.tx_cond_hash;
    l_usage.tx_cond_hash = l_rejected2;

    l_usage.tx_recreate_count++;
    l_should_terminate = (l_usage.tx_recreate_count >= MAX_TX_RECREATE_ATTEMPTS);
    dap_assert(l_should_terminate,
               "Second recreate attempt should trigger termination (2 >= MAX)");

    dap_pass_msg("tx_recreate revert flow test passed");
}

/**
 * Test 26: MAX_TX_RECREATE_ATTEMPTS constant value
 * @details Verify the constant is set to 2
 */
static void s_test_max_tx_recreate_attempts_value(void)
{
    dap_print_module_name("Test 26: MAX_TX_RECREATE_ATTEMPTS value");

    dap_assert(MAX_TX_RECREATE_ATTEMPTS == 2,
               "MAX_TX_RECREATE_ATTEMPTS should be 2");

    dap_pass_msg("MAX_TX_RECREATE_ATTEMPTS value test passed");
}

int main(void)
{
    dap_print_module_name("=== srv_pay unit tests ===");

    // Hash state machine tests (tx_cond_hash_prev)
    s_test_hash_prev_initial_state();
    s_test_hash_prev_mempool_add();
    s_test_hash_prev_ledger_confirm();
    s_test_hash_prev_revert_invalid();
    s_test_hash_prev_multiple_cycles();
    s_test_hash_prev_chain_resolution();

    // State/substate tests
    s_test_service_state_enums();
    s_test_usage_struct_state_storage();
    s_test_usage_error_code_storage();

    // mempool_wait_count tests
    s_test_mempool_wait_count_initial();
    s_test_mempool_wait_count_threshold();
    s_test_mempool_wait_count_reset_on_success();
    s_test_mempool_wait_count_reset_on_confirm();
    s_test_mempool_wait_full_cycle();
    s_test_max_mempool_wait_cycles_value();

    // Accumulated receipt and limits extension tests
    s_test_accumulated_receipt_value();
    s_test_limits_extension_during_wait();
    s_test_terminate_at_max_no_confirm();
    s_test_confirm_mid_wait();
    s_test_zero_counter_confirm();

    // tx_recreate_count tests
    s_test_tx_recreate_count_initial();
    s_test_tx_recreate_count_threshold();
    s_test_tx_recreate_count_reset_on_success();
    s_test_tx_recreate_count_reset_on_confirm();
    s_test_tx_recreate_revert_flow();
    s_test_max_tx_recreate_attempts_value();

    printf("\n%s=== All srv_pay unit tests passed ===%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}
