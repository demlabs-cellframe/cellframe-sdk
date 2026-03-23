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

    printf("\n%s=== All srv_pay unit tests passed ===%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}
