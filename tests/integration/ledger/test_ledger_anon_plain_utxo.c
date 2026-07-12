/**
 * @file test_ledger_anon_plain_utxo.c
 * @brief I2: anon ledger orchestrator — plain UTXO canary + open rejects anon items.
 */

#include "dap_test.h"
#include "dap_common.h"
#include "dap_chain_ledger.h"
#include "dap_chain_ledger_pvt.h"
#include "dap_chain_ledger_type.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_common.h"
#include "dap_hash.h"

#define LOG_TAG "test_ledger_anon_plain_utxo"

static dap_ledger_t *s_create_ledger(uint8_t a_ledger_type)
{
    dap_ledger_create_options_t l_opts = {
        .net_id = (dap_chain_net_id_t){ .uint64 = 0xFA0A000000000001ULL },
        .flags = 0,
        .native_ticker = "CFN",
        .ledger_type = a_ledger_type,
        .anon_type = DAP_LEDGER_ANON_CHIPMUNK_SNARK,
    };
    snprintf(l_opts.name, sizeof(l_opts.name), "test_ledger_%u", (unsigned)a_ledger_type);
    return dap_ledger_create(&l_opts);
}

static void s_destroy_ledger(dap_ledger_t *a_ledger)
{
    if (!a_ledger)
        return;
    dap_ledger_handle_free(a_ledger);
}

static dap_chain_datum_tx_t *s_make_stub_anon_tx(void)
{
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_anon_t l_in = {
        .hdr = { .type = TX_ITEM_TYPE_IN_ANON, .size = sizeof(l_in) },
        .ring_size = 0,
    };
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t *)&l_in);
    return l_tx;
}

static void test_anon_ledger_create_has_anon_data(void)
{
    dap_ledger_t *l_ledger = s_create_ledger(DAP_LEDGER_TYPE_ANON);
    dap_assert(l_ledger != NULL, "anon ledger create succeeds");
    dap_assert(PVT(l_ledger)->anon_data != NULL, "anon_data initialized on create");
    dap_assert(PVT(l_ledger)->ledger_type == DAP_LEDGER_TYPE_ANON, "ledger_type is ANON");
    s_destroy_ledger(l_ledger);
}

static void test_type_dispatch_registered(void)
{
    dap_assert(dap_ledger_type_get_by_enum(DAP_LEDGER_TYPE_OPEN) != NULL, "open type_desc registered");
    dap_assert(dap_ledger_type_get_by_enum(DAP_LEDGER_TYPE_ANON) != NULL, "anon type_desc registered");
    dap_assert(dap_ledger_type_get_by_enum(DAP_LEDGER_TYPE_ANON)->tx_check != NULL, "anon tx_check wired");
}

static void test_open_ledger_rejects_anon_items(void)
{
    dap_ledger_t *l_ledger = s_create_ledger(DAP_LEDGER_TYPE_OPEN);
    dap_assert(l_ledger != NULL, "open ledger create succeeds");

    dap_chain_datum_tx_t *l_tx = s_make_stub_anon_tx();
    dap_hash_sha3_256_t l_hash = {};
    dap_hash_sha3_256(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);

    int l_rc = dap_ledger_tx_add_check(l_ledger, l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);
    dap_assert(l_rc == DAP_LEDGER_TX_CHECK_ANON_ITEM_MISSTYPED,
               "open ledger rejects anon TX items (MISSTYPED)");

    DAP_DELETE(l_tx);
    s_destroy_ledger(l_ledger);
}

static void test_anon_ledger_orchestrator_rejects_anon_without_inputs(void)
{
    dap_ledger_t *l_ledger = s_create_ledger(DAP_LEDGER_TYPE_ANON);
    dap_assert(l_ledger != NULL, "anon ledger create succeeds");

    dap_chain_datum_tx_t *l_tx = s_make_stub_anon_tx();
    dap_hash_sha3_256_t l_hash = {};
    dap_hash_sha3_256(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);

    /* Routed through type_desc → s_anon_tx_check → utxo structural + crypto verify */
    int l_rc = dap_ledger_tx_add_check(l_ledger, l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);
    dap_assert(l_rc != DAP_LEDGER_CHECK_OK && l_rc != DAP_LEDGER_TX_CHECK_ANON_ITEM_FORBIDDEN,
               "anon orchestrator rejects incomplete anon TX (not open-forbidden)");

    DAP_DELETE(l_tx);
    s_destroy_ledger(l_ledger);
}

static void test_tx_load_matches_mempool_check_path(void)
{
    dap_ledger_t *l_ledger = s_create_ledger(DAP_LEDGER_TYPE_ANON);
    dap_assert(l_ledger != NULL, "anon ledger create succeeds");

    dap_chain_datum_tx_t *l_tx = s_make_stub_anon_tx();
    dap_hash_sha3_256_t l_hash = {};
    dap_hash_sha3_256(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);

    int l_check = dap_ledger_tx_add_check(l_ledger, l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);
    int l_load = dap_ledger_tx_load(l_ledger, l_tx, &l_hash, NULL);
    dap_assert(l_check == l_load, "block/sync tx_load matches mempool tx_add_check for anon stub");

    DAP_DELETE(l_tx);
    s_destroy_ledger(l_ledger);
}

static void test_open_ledger_tx_load_rejects_anon_items(void)
{
    dap_ledger_t *l_ledger = s_create_ledger(DAP_LEDGER_TYPE_OPEN);
    dap_assert(l_ledger != NULL, "open ledger create succeeds");

    dap_chain_datum_tx_t *l_tx = s_make_stub_anon_tx();
    dap_hash_sha3_256_t l_hash = {};
    dap_hash_sha3_256(l_tx, dap_chain_datum_tx_get_size(l_tx), &l_hash);

    int l_load = dap_ledger_tx_load(l_ledger, l_tx, &l_hash, NULL);
    dap_assert(l_load == DAP_LEDGER_TX_CHECK_ANON_ITEM_MISSTYPED,
               "open ledger tx_load rejects anon TX items (MISSTYPED)");

    DAP_DELETE(l_tx);
    s_destroy_ledger(l_ledger);
}

int main(void)
{
    dap_set_appname("test_ledger_anon_plain_utxo");
    dap_common_init("test_ledger_anon_plain_utxo", NULL);

    test_type_dispatch_registered();
    test_anon_ledger_create_has_anon_data();
    test_open_ledger_rejects_anon_items();
    test_anon_ledger_orchestrator_rejects_anon_without_inputs();
    test_tx_load_matches_mempool_check_path();
    test_open_ledger_tx_load_rejects_anon_items();

    log_it(L_INFO, "=== test_ledger_anon_plain_utxo PASSED ===");
    dap_common_deinit();
    return 0;
}
