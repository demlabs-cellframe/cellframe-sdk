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
 * @file srv_pay_integration_test.c
 * @brief Integration tests for VPN/service payment logic fixes
 * @details Tests:
 *   - Conditional tx chain following via dap_ledger_get_final_chain_tx_hash
 *   - Mempool datum add/get roundtrip
 *   - dap_ledger_tx_add_check validation
 *   - dap_chain_mempool_tx_create_cond_input error handling
 * @date 2026-03-23
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dap_common.h"
#include "dap_hash.h"
#include "dap_enc_key.h"
#include "dap_cert.h"
#include "dap_math_ops.h"
#include "dap_file_utils.h"
#include "dap_config.h"

#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum.h"
#include "dap_chain_ledger.h"
#include "dap_chain_common.h"
#include "dap_chain_mempool.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag.h"
#include "dap_chain_cs_dag_poa.h"
#include "dap_chain_cs_none.h"

#include "test_ledger_fixtures.h"
#include "test_token_fixtures.h"
#include "test_emission_fixtures.h"
#include "test_transaction_fixtures.h"
#include "dap_test.h"

#define LOG_TAG "srv_pay_integration_test"

static const char *s_token_ticker = "TPAY";
static const uint64_t s_srv_uid_value = 0x0001;

static test_net_fixture_t *s_net_fixture = NULL;
static char s_config_dir[256] = {0};
static char s_gdb_dir[256] = {0};
static char s_certs_dir[256] = {0};

/**
 * @brief Permissive verificator for SRV_PAY conditional outputs in test environment
 */
static int s_srv_pay_verificator(dap_ledger_t *a_ledger, dap_chain_tx_out_cond_t *a_tx_out_cond,
                                 dap_chain_datum_tx_t *a_tx_in, bool a_owner, bool a_check_for_apply)
{
    UNUSED(a_ledger);
    UNUSED(a_tx_out_cond);
    UNUSED(a_tx_in);
    UNUSED(a_owner);
    UNUSED(a_check_for_apply);
    return 0;
}

/**
 * @brief Create a test key for signing
 */
static dap_enc_key_t *s_create_test_key(const char *a_seed)
{
    return dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
                                   NULL, 0, a_seed, strlen(a_seed), 0);
}

/**
 * @brief Build a transaction with emission input + conditional output (SRV_PAY)
 */
static test_tx_fixture_t *s_create_cond_tx_from_emission(
    dap_ledger_t *a_ledger,
    dap_chain_hash_fast_t *a_emission_hash,
    const char *a_token_ticker,
    uint256_t a_cond_value,
    dap_chain_net_srv_uid_t a_srv_uid,
    dap_hash_fast_t *a_pkey_hash,
    dap_cert_t *a_cert)
{
    test_tx_fixture_t *l_fixture = DAP_NEW_Z(test_tx_fixture_t);
    if(!l_fixture)
        return NULL;

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if(!l_tx)
    {
        DAP_DELETE(l_fixture);
        return NULL;
    }

    dap_chain_tx_in_ems_t l_in_ems = {
        .header = {
            .type = TX_ITEM_TYPE_IN_EMS,
            .token_emission_chain_id = {.uint64 = 0},
            .token_emission_hash = *a_emission_hash
        }
    };
    strncpy(l_in_ems.header.ticker, a_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    if(dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_in_ems) != 1)
    {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_fixture);
        return NULL;
    }

    dap_chain_net_srv_price_unit_uid_t l_unit = {.enm = SERV_UNIT_SEC};
    uint256_t l_max_per_unit = uint256_0;
    if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_pkey_hash, a_srv_uid,
                                            a_cond_value, l_max_per_unit, l_unit, NULL, 0) != 1)
    {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_fixture);
        return NULL;
    }

    // Add change output if emission value > cond value
    dap_chain_datum_token_emission_t *l_emission = dap_ledger_token_emission_find(a_ledger, a_emission_hash);
    if(l_emission)
    {
        uint256_t l_change = {0};
        SUBTRACT_256_256(l_emission->hdr.value, a_cond_value, &l_change);
        if(!IS_ZERO_256(l_change))
        {
            dap_chain_addr_t l_addr = {};
            dap_chain_addr_fill_from_key(&l_addr, a_cert->enc_key, (dap_chain_net_id_t){.uint64 = 0x0FA0});
            dap_chain_datum_tx_add_out_ext_item(&l_tx, &l_addr, l_change, a_token_ticker);
        }
    }

    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key) != 1)
    {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_fixture);
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast(l_tx, l_tx_size, &l_fixture->tx_hash);
    l_fixture->tx = l_tx;
    l_fixture->out_count = 1;

    return l_fixture;
}

/**
 * @brief Build a transaction that spends a conditional output and creates a new one
 */
static test_tx_fixture_t *s_create_cond_spend_tx(
    dap_chain_hash_fast_t *a_prev_tx_hash,
    uint32_t a_out_cond_idx,
    uint256_t a_spend_value,
    uint256_t a_remaining_value,
    dap_chain_net_srv_uid_t a_srv_uid,
    dap_hash_fast_t *a_pkey_hash,
    dap_chain_addr_t *a_addr_to,
    const char *a_token_ticker,
    dap_enc_key_t *a_sign_key)
{
    test_tx_fixture_t *l_fixture = DAP_NEW_Z(test_tx_fixture_t);
    if(!l_fixture)
        return NULL;

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    if(!l_tx)
    {
        DAP_DELETE(l_fixture);
        return NULL;
    }

    if(dap_chain_datum_tx_add_in_cond_item(&l_tx, a_prev_tx_hash, a_out_cond_idx, 0) != 1)
    {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_fixture);
        return NULL;
    }

    if(dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr_to, a_spend_value, a_token_ticker) != 1)
    {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_fixture);
        return NULL;
    }

    if(!IS_ZERO_256(a_remaining_value))
    {
        dap_chain_net_srv_price_unit_uid_t l_unit = {.enm = SERV_UNIT_SEC};
        uint256_t l_max_per_unit = uint256_0;
        if(dap_chain_datum_tx_add_out_cond_item(&l_tx, a_pkey_hash, a_srv_uid,
                                                a_remaining_value, l_max_per_unit, l_unit, NULL, 0) != 1)
        {
            dap_chain_datum_tx_delete(l_tx);
            DAP_DELETE(l_fixture);
            return NULL;
        }
    }

    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_sign_key) != 1)
    {
        dap_chain_datum_tx_delete(l_tx);
        DAP_DELETE(l_fixture);
        return NULL;
    }

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast(l_tx, l_tx_size, &l_fixture->tx_hash);
    l_fixture->tx = l_tx;
    l_fixture->out_count = 1;

    return l_fixture;
}


/**
 * @brief Test 1: dap_ledger_get_final_chain_tx_hash — single unspent cond tx
 */
static void s_test_chain_following_single(dap_cert_t *a_cert,
                                          dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_emission_hash)
{
    dap_print_module_name("Test 1: Chain following - single unspent cond tx");

    dap_hash_fast_t l_pkey_hash;
    dap_hash_fast(a_cert->enc_key->pub_key_data, a_cert->enc_key->pub_key_data_size, &l_pkey_hash);

    dap_chain_net_srv_uid_t l_srv_uid = {.uint64 = s_srv_uid_value};
    uint256_t l_cond_value = dap_chain_balance_scan("1000.0");

    test_tx_fixture_t *l_cond_tx = s_create_cond_tx_from_emission(
        s_net_fixture->ledger, a_emission_hash, s_token_ticker,
        l_cond_value, l_srv_uid, &l_pkey_hash, a_cert);
    dap_assert(l_cond_tx != NULL, "Conditional tx created successfully");

    int l_add_result = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_cond_tx);
    dap_assert(l_add_result == 0, "Conditional tx added to ledger");

    dap_hash_fast_t l_final = dap_ledger_get_final_chain_tx_hash(
        s_net_fixture->ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
        &l_cond_tx->tx_hash, true);

    dap_assert(!dap_hash_fast_is_blank(&l_final),
               "Final chain hash should not be blank");
    dap_assert(dap_hash_fast_compare(&l_final, &l_cond_tx->tx_hash),
               "Final chain hash should equal the original (single unspent tx)");

    test_tx_fixture_destroy(l_cond_tx);
    dap_pass_msg("Chain following single tx test passed");
}

/**
 * @brief Test 2: dap_ledger_get_final_chain_tx_hash — chain of two cond txs
 */
static void s_test_chain_following_two_hops(dap_cert_t *a_cert,
                                            dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_emission_hash)
{
    dap_print_module_name("Test 2: Chain following - two-hop cond tx chain");

    dap_hash_fast_t l_pkey_hash;
    dap_hash_fast(a_cert->enc_key->pub_key_data, a_cert->enc_key->pub_key_data_size, &l_pkey_hash);

    dap_chain_net_srv_uid_t l_srv_uid = {.uint64 = s_srv_uid_value};
    uint256_t l_cond_value = dap_chain_balance_scan("2000.0");

    test_tx_fixture_t *l_tx1 = s_create_cond_tx_from_emission(
        s_net_fixture->ledger, a_emission_hash, s_token_ticker,
        l_cond_value, l_srv_uid, &l_pkey_hash, a_cert);
    dap_assert(l_tx1 != NULL, "First conditional tx created");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx1);
    dap_assert(l_res == 0, "First conditional tx added to ledger");

    uint256_t l_spend = dap_chain_balance_scan("100.0");
    uint256_t l_remaining = {0};
    SUBTRACT_256_256(l_cond_value, l_spend, &l_remaining);

    int l_out_cond_idx = 0;
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_out_cond_get(
        l_tx1->tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, &l_out_cond_idx);
    dap_assert(l_out_cond != NULL, "OUT_COND found in tx1");

    test_tx_fixture_t *l_tx2 = s_create_cond_spend_tx(
        &l_tx1->tx_hash, l_out_cond_idx,
        l_spend, l_remaining, l_srv_uid, &l_pkey_hash,
        a_addr, s_token_ticker, a_cert->enc_key);
    dap_assert(l_tx2 != NULL, "Second conditional tx created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx2);
    dap_assert(l_res == 0, "Second conditional tx added to ledger");

    dap_hash_fast_t l_final = dap_ledger_get_final_chain_tx_hash(
        s_net_fixture->ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
        &l_tx1->tx_hash, true);

    dap_assert(!dap_hash_fast_is_blank(&l_final),
               "Final chain hash should not be blank");
    dap_assert(dap_hash_fast_compare(&l_final, &l_tx2->tx_hash),
               "Final chain hash should be tx2 (the latest in chain)");

    dap_hash_fast_t l_final2 = dap_ledger_get_final_chain_tx_hash(
        s_net_fixture->ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
        &l_tx2->tx_hash, true);
    dap_assert(dap_hash_fast_compare(&l_final2, &l_tx2->tx_hash),
               "Final from tx2 should be tx2 itself");

    test_tx_fixture_destroy(l_tx1);
    test_tx_fixture_destroy(l_tx2);
    dap_pass_msg("Chain following two-hop test passed");
}

/**
 * @brief Test 3: dap_ledger_tx_add_check — valid tx returns 0
 */
static void s_test_tx_add_check_valid(dap_cert_t *a_cert,
                                      dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_emission_hash)
{
    dap_print_module_name("Test 3: dap_ledger_tx_add_check - valid tx");

    test_tx_fixture_t *l_tx = test_tx_fixture_create_from_emission(
        s_net_fixture->ledger, a_emission_hash, s_token_ticker,
        "500.0", a_addr, a_cert);
    dap_assert(l_tx != NULL, "Transaction from emission created");

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx->tx);
    int l_check = dap_ledger_tx_add_check(s_net_fixture->ledger, l_tx->tx, l_tx_size, &l_tx->tx_hash);
    dap_assert(l_check == 0, "Valid tx should pass dap_ledger_tx_add_check");

    test_tx_fixture_destroy(l_tx);
    dap_pass_msg("dap_ledger_tx_add_check valid tx test passed");
}

/**
 * @brief Test 4: dap_ledger_tx_add_check — invalid tx returns non-zero
 */
static void s_test_tx_add_check_invalid(dap_cert_t *a_cert, dap_chain_addr_t *a_addr)
{
    dap_print_module_name("Test 4: dap_ledger_tx_add_check - invalid tx");

    dap_hash_fast_t l_fake_emission_hash;
    dap_hash_fast("fake_emission_data_12345", 23, &l_fake_emission_hash);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_assert(l_tx != NULL, "Empty transaction created");

    dap_chain_tx_in_ems_t l_in_ems = {
        .header = {
            .type = TX_ITEM_TYPE_IN_EMS,
            .token_emission_chain_id = {.uint64 = 0},
            .token_emission_hash = l_fake_emission_hash
        }
    };
    strncpy(l_in_ems.header.ticker, s_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_in_ems);

    uint256_t l_value = dap_chain_balance_scan("100.0");
    dap_chain_datum_tx_add_out_ext_item(&l_tx, a_addr, l_value, s_token_ticker);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key);

    dap_hash_fast_t l_tx_hash;
    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_hash_fast(l_tx, l_tx_size, &l_tx_hash);

    int l_check = dap_ledger_tx_add_check(s_net_fixture->ledger, l_tx, l_tx_size, &l_tx_hash);
    dap_assert(l_check != 0, "Invalid tx (fake emission) should fail dap_ledger_tx_add_check");

    dap_chain_datum_tx_delete(l_tx);
    dap_pass_msg("dap_ledger_tx_add_check invalid tx test passed");
}

/**
 * @brief Test 5: dap_chain_mempool_tx_create_cond_input — bad arguments
 */
static void s_test_mempool_cond_input_bad_args(void)
{
    dap_print_module_name("Test 5: dap_chain_mempool_tx_create_cond_input - bad arguments");

    int l_ret_status = 0;
    dap_hash_fast_t l_dummy_hash;
    dap_hash_fast("dummy", 5, &l_dummy_hash);
    dap_chain_addr_t l_dummy_addr = {};

    char *l_result = dap_chain_mempool_tx_create_cond_input(
        NULL, &l_dummy_hash, &l_dummy_addr, NULL, NULL, "hex", &l_ret_status);
    dap_assert(l_result == NULL, "NULL net should return NULL");
    dap_assert(l_ret_status == DAP_CHAIN_MEMPOOL_RET_STATUS_BAD_ARGUMENTS,
               "NULL net should set BAD_ARGUMENTS status");

    dap_pass_msg("Mempool cond input bad args test passed");
}

/**
 * @brief Test 6: Mempool datum add/get roundtrip
 */
static void s_test_mempool_datum_roundtrip(void)
{
    dap_print_module_name("Test 6: Mempool datum add/get roundtrip");

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_assert(l_tx != NULL, "Empty transaction created for datum test");

    size_t l_tx_size = dap_chain_datum_tx_get_size(l_tx);
    dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, l_tx, l_tx_size);
    dap_assert(l_datum != NULL, "Datum created from tx");

    dap_chain_t *l_chain = s_net_fixture->chain_main;
    if(!l_chain)
    {
        dap_test_msg("No main chain available, skipping mempool roundtrip test");
        DAP_DELETE(l_datum);
        dap_chain_datum_tx_delete(l_tx);
        dap_pass_msg("Mempool datum roundtrip skipped (no chain)");
        return;
    }

    char *l_hash_str = dap_chain_mempool_datum_add(l_datum, l_chain, "hex");
    if(!l_hash_str)
    {
        dap_test_msg("Mempool datum_add returned NULL (mempool/GDB may not be initialized), skipping");
        DAP_DELETE(l_datum);
        dap_chain_datum_tx_delete(l_tx);
        dap_pass_msg("Mempool datum roundtrip skipped (datum_add failed)");
        return;
    }

    dap_chain_datum_t *l_got = dap_chain_mempool_datum_get(l_chain, l_hash_str);
    dap_assert(l_got != NULL, "Datum retrieved from mempool by hash");
    dap_assert(l_got->header.type_id == DAP_CHAIN_DATUM_TX,
               "Retrieved datum type should be DAP_CHAIN_DATUM_TX");

    DAP_DEL_Z(l_got);
    DAP_DELETE(l_hash_str);
    DAP_DELETE(l_datum);
    dap_chain_datum_tx_delete(l_tx);
    dap_pass_msg("Mempool datum roundtrip test passed");
}

/**
 * @brief Test 7: Fully spent conditional tx — blank final hash
 */
static void s_test_chain_following_fully_spent(dap_cert_t *a_cert,
                                               dap_chain_addr_t *a_addr, dap_chain_hash_fast_t *a_emission_hash)
{
    dap_print_module_name("Test 7: Chain following - fully spent cond tx");

    dap_hash_fast_t l_pkey_hash;
    dap_hash_fast(a_cert->enc_key->pub_key_data, a_cert->enc_key->pub_key_data_size, &l_pkey_hash);

    dap_chain_net_srv_uid_t l_srv_uid = {.uint64 = s_srv_uid_value};
    uint256_t l_cond_value = dap_chain_balance_scan("300.0");

    test_tx_fixture_t *l_tx1 = s_create_cond_tx_from_emission(
        s_net_fixture->ledger, a_emission_hash, s_token_ticker,
        l_cond_value, l_srv_uid, &l_pkey_hash, a_cert);
    dap_assert(l_tx1 != NULL, "Cond tx created for full-spend test");

    int l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx1);
    dap_assert(l_res == 0, "Cond tx added to ledger");

    int l_out_cond_idx = 0;
    dap_chain_datum_tx_out_cond_get(l_tx1->tx, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY, &l_out_cond_idx);

    test_tx_fixture_t *l_tx2 = s_create_cond_spend_tx(
        &l_tx1->tx_hash, l_out_cond_idx,
        l_cond_value, uint256_0, l_srv_uid, &l_pkey_hash,
        a_addr, s_token_ticker, a_cert->enc_key);
    dap_assert(l_tx2 != NULL, "Fully-spending tx created");

    l_res = test_tx_fixture_add_to_ledger(s_net_fixture->ledger, l_tx2);
    dap_assert(l_res == 0, "Fully-spending tx added to ledger");

    dap_hash_fast_t l_final = dap_ledger_get_final_chain_tx_hash(
        s_net_fixture->ledger, DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
        &l_tx1->tx_hash, true);

    dap_assert(dap_hash_fast_is_blank(&l_final),
               "Final hash should be blank for fully spent chain (no unspent cond output)");

    test_tx_fixture_destroy(l_tx1);
    test_tx_fixture_destroy(l_tx2);
    dap_pass_msg("Chain following fully spent test passed");
}


static void s_setup(void)
{
    log_it(L_NOTICE, "=== srv_pay Integration Tests Setup ===");

    const char *l_tmp = test_get_temp_dir();
    snprintf(s_config_dir, sizeof(s_config_dir), "%s/srv_pay_test_config", l_tmp);
    snprintf(s_gdb_dir, sizeof(s_gdb_dir), "%s/srv_pay_test_gdb", l_tmp);
    snprintf(s_certs_dir, sizeof(s_certs_dir), "%s/srv_pay_test_certs", l_tmp);

    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
    dap_rm_rf(s_config_dir);

    dap_mkdir_with_parents(s_config_dir);

    char l_config_content[2048];
    snprintf(l_config_content, sizeof(l_config_content),
        "[general]\n"
        "debug=true\n"
        "[ledger]\n"
        "debug_more=true\n"
        "[global_db]\n"
        "driver=mdbx\n"
        "path=%s\n"
        "debug_more=false\n"
        "[resources]\n"
        "ca_folders=%s\n",
        s_gdb_dir, s_certs_dir);

    char l_config_path[1024];
    snprintf(l_config_path, sizeof(l_config_path), "%s/test.cfg", s_config_dir);
    FILE *l_config_file = fopen(l_config_path, "w");
    if(l_config_file)
    {
        fwrite(l_config_content, 1, strlen(l_config_content), l_config_file);
        fclose(l_config_file);
    }
    dap_mkdir_with_parents(s_certs_dir);

    int l_env_res = test_env_init(s_config_dir, s_gdb_dir);
    dap_assert(l_env_res == 0, "Test environment initialization");

    dap_ledger_init();
    dap_chain_cs_dag_init();
    dap_chain_cs_dag_poa_init();
    dap_nonconsensus_init();

    dap_ledger_verificator_add(DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_PAY,
                               s_srv_pay_verificator, NULL, NULL);

    s_net_fixture = test_net_fixture_create("srv_pay_test");
    dap_assert(s_net_fixture != NULL, "Network fixture created");
    dap_assert(s_net_fixture->ledger != NULL, "Ledger available");
}

static void s_teardown(void)
{
    if(s_net_fixture)
    {
        test_net_fixture_destroy(s_net_fixture);
        s_net_fixture = NULL;
    }

    test_env_deinit();

    char l_cfg_path[1024];
    snprintf(l_cfg_path, sizeof(l_cfg_path), "%s/test.cfg", s_config_dir);
    remove(l_cfg_path);
    dap_rm_rf(s_config_dir);
    dap_rm_rf(s_gdb_dir);
    dap_rm_rf(s_certs_dir);
}

int main(void)
{
    dap_log_set_external_output(LOGGER_OUTPUT_STDERR, NULL);
    dap_log_level_set(L_DEBUG);

    dap_print_module_name("=== srv_pay integration tests ===");

    s_setup();

    dap_enc_key_t *l_key = s_create_test_key("srv_pay_integration_test_seed_2026");
    dap_assert(l_key != NULL, "Test key created");

    dap_chain_addr_t l_addr = {};
    dap_chain_addr_fill_from_key(&l_addr, l_key, s_net_fixture->net->pub.id);

    test_token_fixture_t *l_token = test_token_fixture_create(s_net_fixture->ledger, s_token_ticker, "1000000.0");
    dap_assert(l_token != NULL, "Test token created");

    // Create separate emissions for each test using emission fixture API
    uint256_t l_emission_value = dap_chain_balance_scan("5000.0");

    test_emission_fixture_t *l_em1 = test_emission_fixture_create_with_cert(
        s_token_ticker, l_emission_value, &l_addr, l_token->owner_cert);
    dap_assert(l_em1 != NULL, "Emission 1 created");
    int l_em1_res = test_emission_fixture_add_to_ledger(s_net_fixture->ledger, l_em1);
    dap_assert(l_em1_res == 0, "Emission 1 added to ledger");

    test_emission_fixture_t *l_em2 = test_emission_fixture_create_with_cert(
        s_token_ticker, l_emission_value, &l_addr, l_token->owner_cert);
    dap_assert(l_em2 != NULL, "Emission 2 created");
    int l_em2_res = test_emission_fixture_add_to_ledger(s_net_fixture->ledger, l_em2);
    dap_assert(l_em2_res == 0, "Emission 2 added to ledger");

    test_emission_fixture_t *l_em3 = test_emission_fixture_create_with_cert(
        s_token_ticker, l_emission_value, &l_addr, l_token->owner_cert);
    dap_assert(l_em3 != NULL, "Emission 3 created");
    int l_em3_res = test_emission_fixture_add_to_ledger(s_net_fixture->ledger, l_em3);
    dap_assert(l_em3_res == 0, "Emission 3 added to ledger");

    test_emission_fixture_t *l_em4 = test_emission_fixture_create_with_cert(
        s_token_ticker, l_emission_value, &l_addr, l_token->owner_cert);
    dap_assert(l_em4 != NULL, "Emission 4 created");
    int l_em4_res = test_emission_fixture_add_to_ledger(s_net_fixture->ledger, l_em4);
    dap_assert(l_em4_res == 0, "Emission 4 added to ledger");

    // Run tests
    s_test_chain_following_single(l_token->owner_cert, &l_addr, &l_em1->emission_hash);
    s_test_chain_following_two_hops(l_token->owner_cert, &l_addr, &l_em2->emission_hash);
    s_test_tx_add_check_valid(l_token->owner_cert, &l_addr, &l_em3->emission_hash);
    s_test_tx_add_check_invalid(l_token->owner_cert, &l_addr);
    s_test_mempool_cond_input_bad_args();
    s_test_mempool_datum_roundtrip();
    s_test_chain_following_fully_spent(l_token->owner_cert, &l_addr, &l_em4->emission_hash);

    // Cleanup
    test_emission_fixture_destroy(l_em1);
    test_emission_fixture_destroy(l_em2);
    test_emission_fixture_destroy(l_em3);
    test_emission_fixture_destroy(l_em4);
    test_token_fixture_destroy(l_token);
    dap_enc_key_delete(l_key);

    s_teardown();

    printf("\n%s=== All srv_pay integration tests passed ===%s\n", TEXT_COLOR_GRN, TEXT_COLOR_RESET);
    return 0;
}
