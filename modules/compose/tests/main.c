#include "dap_test.h"
#include "rand/dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_tx_out_cond.h"
#include "dap_chain_datum_token.h"
#include "dap_tsd.h"
#include <json-c/json.h>

#define LOG_TAG "dap_tx_compose_tests"
#define KEY_COUNT 10

const char *s_ticker_native = "BUZ";
const char *s_ticker_delegate = "mBUZ";
const char *s_ticker_custom = "cBUZ";
const char *s_net_name = "foobar";
const char *s_url = "localhost";

struct tests_data {
    dap_chain_addr_t addr_from;
    dap_chain_addr_t addr_to;
    dap_chain_addr_t addr_any;
    dap_chain_node_addr_t node_addr;
    uint256_t value;
    uint256_t value_fee;
    uint256_t value_delegate;
    uint256_t value_per_unit_max;
    uint256_t reinvest_percent;
    uint32_t idx_1;
    uint32_t idx_2;
    dap_hash_fast_t hash_1;
    dap_chain_net_srv_uid_t srv_uid;
    dap_chain_id_t chain_id;
    compose_config_t config;
    time_t time_staking;
    dap_chain_tx_out_cond_t cond_out;
};

static dap_enc_key_type_t s_key_types[] = {
#ifdef DAP_ECDSA
        DAP_ENC_KEY_TYPE_SIG_ECDSA,
#endif
#ifdef DAP_SHIPOVNIK
        DAP_ENC_KEY_TYPE_SIG_SHIPOVNIK,
#endif
    DAP_ENC_KEY_TYPE_SIG_DILITHIUM,
    DAP_ENC_KEY_TYPE_SIG_FALCON,
    DAP_ENC_KEY_TYPE_SIG_SPHINCSPLUS,
};

static dap_enc_key_t *s_key[KEY_COUNT];
static size_t s_sign_type_count = sizeof(s_key_types) / sizeof(s_key_types[0]);

static struct tests_data *s_data = NULL;

int dap_chain_tx_datum_from_json(json_object *a_tx_json, dap_chain_net_t *a_net, json_object *a_jobj_arr_errors, 
        dap_chain_datum_tx_t** a_out_tx, size_t* a_items_count, size_t *a_items_ready);
int dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, json_object *a_out_json);

void s_datum_sign_and_check(dap_chain_datum_tx_t **a_datum)
{
    size_t l_signs_count = rand() % KEY_COUNT + 1;
    dap_test_msg("add %zu tsd sections", l_signs_count);
    for (size_t i = 0; i < l_signs_count; ++i) {
        int l_rand_data = rand();
        // Use valid TSD types instead of random values
        dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create(&l_rand_data, rand(), sizeof(l_rand_data));
        dap_assert(dap_chain_datum_tx_add_item(a_datum, l_tsd) == 1, "datum_1 add tsd");
        DAP_DEL_Z(l_tsd);
    }
    l_signs_count = rand() % KEY_COUNT + 1;
    dap_test_msg("add %zu signs", l_signs_count);
    for (size_t i = 0; i < l_signs_count; ++i)
        dap_assert(dap_chain_datum_tx_add_sign_item(a_datum, s_key[rand() % KEY_COUNT]) == 1, "datum_1 sign create");

    dap_assert(dap_chain_datum_tx_verify_sign_all(*a_datum) == 0, "datum sign verify");

    dap_chain_tx_tsd_t *l_out_count = dap_chain_datum_tx_item_tsd_create(&l_signs_count, DAP_CHAIN_DATUM_TRANSFER_TSD_TYPE_OUT_COUNT, sizeof(l_signs_count));
    dap_assert(dap_chain_datum_tx_add_item(a_datum, l_out_count) != 1, "Protection to add item after signs");
    DAP_DEL_Z(l_out_count);
    json_object *l_datum_1_json = json_object_new_object();
    json_object *l_error_json = json_object_new_array();
    dap_test_msg("convert to json");
    dap_chain_net_tx_to_json(*a_datum, l_datum_1_json);
    dap_assert(json_object_object_length(l_datum_1_json), "dap_chain_net_tx_to_json");
    printf("\n");
    dap_chain_datum_tx_t *l_datum_2 = NULL;
    size_t
        l_items_count = 0,
        l_items_ready = 0;
    dap_test_msg("create datum from json");
    dap_assert(!dap_chain_tx_datum_from_json(l_datum_1_json, NULL, l_error_json, &l_datum_2, &l_items_count, &l_items_ready), "tx_create_by_json");
    dap_assert(l_items_count == l_items_ready, "items_count == items_ready")
    dap_assert((*a_datum)->header.tx_items_size == l_datum_2->header.tx_items_size, "items_size_1 == items_size_2");
    dap_assert(!memcmp((*a_datum), l_datum_2, dap_chain_datum_tx_get_size(*a_datum)), "datum_1 == datum_2");
    dap_assert(!dap_chain_datum_tx_verify_sign_all(l_datum_2), "datum_2 sign verify");
    dap_chain_datum_tx_delete(l_datum_2);
    json_object_put(l_datum_1_json);
    json_object_put(l_error_json);
}

void s_chain_datum_tx_create_test()
{ 
    dap_print_module_name("tx_create_compose");
    dap_chain_addr_t *l_addr_to = &s_data->addr_to;
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_tx_create(&s_data->addr_from, &l_addr_to, s_ticker_native, &s_data->value, NULL, s_data->value_fee, 1, &s_data->config);
    dap_assert(l_datum_1, "tx_create_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_cond_create_test()
{
    dap_print_module_name("tx_cond_create_compose");
    size_t l_rand_data_size = rand() % 256;
    char *l_rand_data = DAP_NEW_Z_SIZE_RET_IF_FAIL(char, l_rand_data_size);
    randombytes(l_rand_data, l_rand_data_size);
    size_t l_pkey_size = rand() % 1024;
    dap_pkey_t *pkey = DAP_NEW_Z_SIZE_RET_IF_FAIL(dap_pkey_t, l_pkey_size + sizeof(dap_pkey_t));
    pkey->header.type.type = DAP_PKEY_TYPE_SIGN_BLISS;
    pkey->header.size = l_pkey_size;
    randombytes(pkey->pkey, l_pkey_size);
    dap_chain_net_srv_price_unit_uid_t price_unit;
    price_unit.enm = SERV_UNIT_B;
    dap_hash_fast_t l_pkey_hash = {};
    dap_assert(dap_pkey_get_hash(pkey, &l_pkey_hash), "get pkey hash");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_tx_cond_create(
        &s_data->addr_from, &l_pkey_hash, s_ticker_native, s_data->value,
        s_data->value_per_unit_max, price_unit,
        s_data->srv_uid, s_data->value_fee, l_rand_data, l_rand_data_size, &s_data->config
    );
    dap_assert(l_datum_1, "tx_cond_create_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(l_rand_data);
    DAP_DELETE(pkey);
}

void s_chain_datum_delegate_test()
{
    dap_print_module_name("tx_stake_compose");
    size_t l_pkey_size = rand() % 1024;
    dap_pkey_t *pkey = DAP_NEW_Z_SIZE_RET_IF_FAIL(dap_pkey_t, l_pkey_size + sizeof(dap_pkey_t));
    pkey->header.type.type = DAP_PKEY_TYPE_SIGN_BLISS;
    pkey->header.size = l_pkey_size;
    randombytes(pkey->pkey, l_pkey_size);
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_srv_stake_delegate(&s_data->addr_any, s_data->value, s_data->value_fee, &s_data->addr_from, &s_data->node_addr, &s_data->addr_to, s_data->reinvest_percent, NULL, pkey, &s_data->config);
    dap_assert(l_datum_1, "tx_stake_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(pkey);
}

void s_chain_datum_stake_lock_test()
{
    dap_print_module_name("tx_lock_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_stake_lock_hold(
        &s_data->addr_from, s_ticker_native, s_data->value, s_data->value_fee, 
        s_data->time_staking, s_data->reinvest_percent, s_ticker_delegate, s_data->value_delegate, 
        s_data->chain_id, &s_data->config);
    dap_assert(l_datum_1, "tx_lock_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_stake_unlock_test()
{
    dap_print_module_name("tx_unlock_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_stake_lock_take(
        &s_data->addr_from, &s_data->hash_1, s_data->idx_1, s_ticker_native, s_data->value, s_data->value_fee, 
        s_ticker_delegate, s_data->value_delegate, &s_data->config);
    dap_assert(l_datum_1, "tx_unlock_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_stake_invalidate_test()
{
    dap_print_module_name("tx_invalidate_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_srv_stake_invalidate(
        &s_data->hash_1, s_data->value_fee, &s_data->addr_from, &s_data->config);
    dap_assert(l_datum_1, "tx_invalidate_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_vote_create_test()
{
    dap_print_module_name("tx_vote_create_compose");
    const char *l_question = "Test is PASS?";
    const char *l_options[] = {
        "YES!!!",
        "no:(",
        "I don't know",
        "See results"
    };
    dap_list_t *l_options_list = NULL;
    for (size_t i = 0; i < sizeof(l_options) / sizeof(const char *); ++i)
        l_options_list = dap_list_append(l_options_list, (void *)l_options[i]);
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_poll_create(
        l_question, l_options_list, s_data->time_staking, rand() % 10, s_data->value_fee, false, false, &s_data->addr_from, 
        s_ticker_native, &s_data->config);
    dap_assert(l_datum_1, "tx_vote_create_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    dap_list_free(l_options_list);
}


void s_chain_datum_vote_voting_test()
{
    dap_print_module_name("tx_vote_voting_compose");
    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("tx_voting_compose_cert", s_key_types[rand() % s_sign_type_count], NULL, 0);
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_poll_vote(
        l_cert, s_data->value_fee, &s_data->addr_from, s_data->hash_1, s_data->idx_1, &s_data->config);
    dap_assert(l_datum_1, "tx_vote_voting_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    dap_cert_delete(l_cert);
}

#if 0
void s_chain_datum_exchange_create_test()
{
    dap_print_module_name("tx_exchange_create_compose");
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    dap_stpcpy(l_price->token_sell, s_ticker_native);
    dap_stpcpy(l_price->token_buy, s_ticker_delegate);
    l_price->datoshi_sell = s_data->value;
    l_price->rate = s_data->reinvest_percent;
    l_price->fee = s_data->value_fee;
    // sell native
    dap_chain_datum_tx_t *l_datum_1 = dap_xchange_tx_create_request_compose(l_price, &s_data->addr_from, s_ticker_native, &s_data->config);
    dap_assert(l_datum_1, "tx_exchange_create_compose sell native");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    // sell non native
    l_datum_1 = dap_xchange_tx_create_request_compose(l_price, &s_data->addr_from, s_ticker_delegate, &s_data->config);
    dap_assert(l_datum_1, "tx_exchange_create_compose sell non native");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(l_price);
}

void s_chain_datum_exchange_purchase_test(const char *a_token_sell, const char *a_token_buy)
{
    dap_print_module_name("tx_exchange_purchase_compose");
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    dap_stpcpy(l_price->token_sell, a_token_sell);
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = s_data->value;
    l_price->rate = s_data->reinvest_percent;
    l_price->fee = s_data->value_fee;
    dap_chain_datum_tx_t *l_datum_1 = dap_xchange_tx_create_exchange_compose(
        l_price, &s_data->addr_from, s_data->value_delegate, s_data->value_fee,
        &s_data->cond_out, s_data->idx_1, &s_data->config
    );
    dap_assert(l_datum_1, "tx_exchange_purchase_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(l_price);
}
#endif

void s_chain_datum_xchange_invalidate_test(const char *a_token_sell, const char *a_token_buy)
{
    dap_print_module_name("tx_exchange_invalidate_compose");
    dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
    dap_stpcpy(l_price->token_sell, a_token_sell);
    dap_stpcpy(l_price->token_buy, a_token_buy);
    l_price->datoshi_sell = s_data->value;
    l_price->rate = s_data->reinvest_percent;
    l_price->fee = s_data->value_fee;
    dap_chain_datum_tx_t *l_datum_1 = dap_xchange_tx_invalidate_compose(l_price, &s_data->cond_out, &s_data->addr_from, &s_data->addr_to, a_token_buy, 0, &s_data->config);
    dap_assert(l_datum_1, "tx_exchange_invalidate_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(l_price);
}

static void s_fill_test_addr(dap_chain_addr_t *a_addr, const dap_hash_fast_t *a_pkey_hash);
static size_t s_count_tsd_by_type(const uint8_t *a_tsd_data, uint32_t a_tsd_size, uint16_t a_type, size_t a_expected_entry_size);

void s_chain_datum_shared_funds_hold_test()
{
    dap_print_module_name("tx_shared_funds_hold_compose");
    size_t l_owner_hashes_count = rand() % KEY_COUNT + 1;
    size_t l_signs_min = rand() % l_owner_hashes_count + 1;
    dap_hash_fast_t *l_owner_hashes = DAP_NEW_Z_SIZE_RET_IF_FAIL(dap_hash_fast_t, l_owner_hashes_count * sizeof(dap_hash_fast_t));
    randombytes(l_owner_hashes, l_owner_hashes_count * sizeof(dap_hash_fast_t));
    char *l_rand_tag = DAP_NEW_Z_SIZE_RET_IF_FAIL(char, l_owner_hashes_count);
    dap_random_string_fill(l_rand_tag, l_owner_hashes_count);
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_wallet_shared_hold(
        &s_data->addr_from, s_ticker_native, s_data->value, s_data->value_fee,
        l_signs_min, l_owner_hashes, l_owner_hashes_count, l_rand_tag, &s_data->config);
    dap_assert(l_datum_1, "tx_shared_funds_hold_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DEL_MULTY(l_owner_hashes, l_rand_tag);
}

void s_chain_datum_shared_funds_hold_by_addrs_test()
{
    dap_print_module_name("tx_shared_funds_hold_by_addrs_compose");
    size_t l_addrs_count = rand() % KEY_COUNT + 1;
    size_t l_signs_min = rand() % l_addrs_count + 1;
    dap_hash_fast_t l_hashes[KEY_COUNT];
    randombytes(l_hashes, l_addrs_count * sizeof(dap_hash_fast_t));
    dap_chain_addr_t l_addrs[KEY_COUNT];
    for (size_t i = 0; i < l_addrs_count; i++)
        s_fill_test_addr(&l_addrs[i], &l_hashes[i]);
    char *l_rand_tag = DAP_NEW_Z_SIZE_RET_IF_FAIL(char, l_addrs_count);
    dap_random_string_fill(l_rand_tag, l_addrs_count);
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_wallet_shared_hold_by_addrs(
        &s_data->addr_from, s_ticker_native, s_data->value, s_data->value_fee,
        l_signs_min, l_addrs, l_addrs_count, l_rand_tag, &s_data->config);
    dap_assert(l_datum_1, "tx_shared_funds_hold_by_addrs_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(l_rand_tag);
}

void s_chain_datum_shared_funds_hold_ext_test()
{
    dap_print_module_name("tx_shared_funds_hold_ext_compose");
    size_t l_addrs_count = rand() % (KEY_COUNT / 2) + 1;
    size_t l_hashes_count = rand() % (KEY_COUNT / 2) + 1;
    size_t l_total = l_addrs_count + l_hashes_count;
    size_t l_signs_min = rand() % l_total + 1;
    dap_hash_fast_t l_addr_hashes[KEY_COUNT], l_standalone_hashes[KEY_COUNT];
    randombytes(l_addr_hashes, l_addrs_count * sizeof(dap_hash_fast_t));
    randombytes(l_standalone_hashes, l_hashes_count * sizeof(dap_hash_fast_t));
    dap_chain_addr_t l_addrs[KEY_COUNT];
    for (size_t i = 0; i < l_addrs_count; i++)
        s_fill_test_addr(&l_addrs[i], &l_addr_hashes[i]);
    char *l_rand_tag = DAP_NEW_Z_SIZE_RET_IF_FAIL(char, l_total);
    dap_random_string_fill(l_rand_tag, l_total);
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_wallet_shared_hold_ext(
        &s_data->addr_from, s_ticker_native, s_data->value, s_data->value_fee,
        l_signs_min, l_addrs, l_addrs_count, l_standalone_hashes, l_hashes_count, l_rand_tag, &s_data->config);
    dap_assert(l_datum_1, "tx_shared_funds_hold_ext_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(l_rand_tag);
}

void s_chain_datum_shared_funds_take_test()
{
    dap_print_module_name("tx_shared_funds_take_compose");
    size_t l_tsd_count = rand() % KEY_COUNT;
    dap_list_t *l_tsd_list = NULL;
    for (size_t i = 0; i < l_tsd_count; ++i) {
        int l_rand_data = rand();
        // Use valid TSD types instead of random values
        dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create(&l_rand_data, rand(), sizeof(l_rand_data));
        l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
    }
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_wallet_shared_take(
        &s_data->addr_from, &s_data->addr_to, &s_data->value, 1, s_data->value_fee,
        &s_data->hash_1, l_tsd_list, &s_data->config);
    dap_assert(l_datum_1, "tx_shared_funds_take_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    dap_list_free_full(l_tsd_list, NULL);
}

void s_chain_datum_shared_funds_refill_test()
{
    dap_print_module_name("tx_shared_funds_refill_compose");
    size_t l_signs_count = rand() % KEY_COUNT + 1;
    dap_test_msg("add %zu tsd sections", l_signs_count);
    dap_list_t *l_tsd_list = NULL;
    for (size_t i = 0; i < l_signs_count; ++i) {
        int l_rand_data = rand();
        dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create(&l_rand_data, rand(), sizeof(l_rand_data));
        l_tsd_list = dap_list_append(l_tsd_list, l_tsd);
    }

    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_wallet_shared_refill(
        &s_data->addr_from, s_data->value, s_data->value_fee,
        &s_data->hash_1, l_tsd_list, &s_data->config);
    dap_assert(l_datum_1, "tx_shared_funds_refill_compose");
    dap_list_free_full(l_tsd_list, NULL);
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_tx_cond_refill_test()
{
    dap_print_module_name("tx_cond_refill_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_tx_cond_refill(
        &s_data->addr_from, s_data->value, s_data->value_fee,
        &s_data->hash_1, &s_data->config);
    dap_assert(l_datum_1, "tx_cond_refill_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_tx_cond_remove_test()
{
    dap_print_module_name("tx_cond_remove_compose");
    dap_hash_fast_t l_hash_2 = {};
    randombytes(&l_hash_2, sizeof(dap_hash_fast_t));
    dap_list_t *l_hashes = dap_list_append(NULL, &s_data->hash_1);
    l_hashes = dap_list_append(l_hashes, &l_hash_2);
    dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = 1 };
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_tx_compose_datum_tx_cond_remove(
        &s_data->addr_from, l_hashes, s_data->value_fee, l_srv_uid, &s_data->config);
    dap_assert(l_datum_1, "tx_cond_remove_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    dap_list_free(l_hashes);
}

static void s_fill_test_addr(dap_chain_addr_t *a_addr, const dap_hash_fast_t *a_pkey_hash)
{
    dap_sign_type_t l_sig_type = { .type = SIG_TYPE_DILITHIUM };
    dap_chain_net_id_t l_net_id = { .uint64 = 0xDEADBEEF };
    dap_chain_addr_fill(a_addr, l_sig_type, (dap_chain_hash_fast_t *)a_pkey_hash, l_net_id);
}

static size_t s_count_tsd_by_type(const uint8_t *a_tsd_data, uint32_t a_tsd_size, uint16_t a_type, size_t a_expected_entry_size)
{
    size_t l_count = 0;
    dap_tsd_t *l_tsd; size_t l_tsd_size;
    dap_tsd_iter(l_tsd, l_tsd_size, a_tsd_data, a_tsd_size) {
        if (l_tsd->type == a_type && l_tsd->size == a_expected_entry_size)
            l_count++;
    }
    return l_count;
}

void s_wallet_shared_item_create_tests()
{
    dap_print_module_name("wallet_shared_item_create");
    dap_chain_net_srv_uid_t l_srv_uid = { .uint64 = 0x1234 };
    uint256_t l_value = dap_chain_coins_to_balance("100.0");
    uint32_t l_signs_min = 2;

    // --- Variant 1: hashes only ---
    {
        dap_test_msg("variant 1: hashes only, 3 owners");
        dap_hash_fast_t l_hashes[3];
        randombytes(l_hashes, sizeof(l_hashes));
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
            l_srv_uid, l_value, l_signs_min, l_hashes, 3, "test_tag");
        dap_assert(l_item, "variant1: item created");
        dap_assert(l_item->header.subtype == DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, "variant1: subtype");
        dap_assert(l_item->subtype.wallet_shared.signers_minimum == l_signs_min, "variant1: signs_min");
        size_t l_hash_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_HASH, sizeof(dap_hash_fast_t));
        size_t l_addr_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, sizeof(dap_chain_addr_t));
        dap_assert(l_hash_count == 3, "variant1: 3 TSD_HASH entries");
        dap_assert(l_addr_count == 0, "variant1: 0 TSD_ADDR entries");
        DAP_DELETE(l_item);
    }

    // --- Variant 1: hashes only, no tag ---
    {
        dap_test_msg("variant 1: hashes only, no tag");
        dap_hash_fast_t l_hashes[2];
        randombytes(l_hashes, sizeof(l_hashes));
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
            l_srv_uid, l_value, l_signs_min, l_hashes, 2, NULL);
        dap_assert(l_item, "variant1_notag: item created");
        size_t l_str_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_STR, 0);
        dap_assert(l_str_count == 0, "variant1_notag: no TSD_STR");
        DAP_DELETE(l_item);
    }

    // --- Variant 1: single owner ---
    {
        dap_test_msg("variant 1: single owner");
        dap_hash_fast_t l_hash;
        randombytes(&l_hash, sizeof(l_hash));
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
            l_srv_uid, l_value, 1, &l_hash, 1, NULL);
        dap_assert(l_item, "variant1_single: item created");
        size_t l_hash_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_HASH, sizeof(dap_hash_fast_t));
        dap_assert(l_hash_count == 1, "variant1_single: 1 TSD_HASH");
        DAP_DELETE(l_item);
    }

    // --- Variant 2: addrs only ---
    {
        dap_test_msg("variant 2: addrs only, 3 owners");
        dap_hash_fast_t l_hashes[3];
        randombytes(l_hashes, sizeof(l_hashes));
        dap_chain_addr_t l_addrs[3];
        for (size_t i = 0; i < 3; i++)
            s_fill_test_addr(&l_addrs[i], &l_hashes[i]);
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_by_addrs(
            l_srv_uid, l_value, l_signs_min, l_addrs, 3, "addr_tag");
        dap_assert(l_item, "variant2: item created");
        size_t l_hash_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_HASH, sizeof(dap_hash_fast_t));
        size_t l_addr_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, sizeof(dap_chain_addr_t));
        dap_assert(l_hash_count == 3, "variant2: 3 TSD_HASH entries");
        dap_assert(l_addr_count == 3, "variant2: 3 TSD_ADDR entries (full bijection)");

        dap_tsd_t *l_tsd; size_t l_tsd_size;
        size_t l_idx = 0;
        dap_hash_fast_t l_extracted_hashes[3];
        dap_tsd_iter(l_tsd, l_tsd_size, l_item->tsd, l_item->tsd_size) {
            if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t))
                l_extracted_hashes[l_idx++] = *(dap_hash_fast_t *)l_tsd->data;
        }
        for (size_t i = 0; i < 3; i++)
            dap_assert(dap_hash_fast_compare(&l_extracted_hashes[i], &l_hashes[i]), "variant2: hash[i] matches addr[i].pkey_hash");
        DAP_DELETE(l_item);
    }

    // --- Variant 3: mixed addrs + standalone hashes ---
    {
        dap_test_msg("variant 3: mixed, 2 addrs + 2 standalone hashes");
        dap_hash_fast_t l_addr_hashes[2], l_standalone_hashes[2];
        randombytes(l_addr_hashes, sizeof(l_addr_hashes));
        randombytes(l_standalone_hashes, sizeof(l_standalone_hashes));
        dap_chain_addr_t l_addrs[2];
        for (size_t i = 0; i < 2; i++)
            s_fill_test_addr(&l_addrs[i], &l_addr_hashes[i]);
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, l_signs_min, l_addrs, 2, l_standalone_hashes, 2, "mixed_tag");
        dap_assert(l_item, "variant3: item created");
        size_t l_hash_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_HASH, sizeof(dap_hash_fast_t));
        size_t l_addr_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, sizeof(dap_chain_addr_t));
        dap_assert(l_hash_count == 4, "variant3: 4 TSD_HASH entries (2 from addrs + 2 standalone)");
        dap_assert(l_addr_count == 2, "variant3: 2 TSD_ADDR entries (partial bijection)");

        dap_tsd_t *l_tsd; size_t l_tsd_size;
        size_t l_idx = 0;
        dap_hash_fast_t l_all_hashes[4];
        dap_tsd_iter(l_tsd, l_tsd_size, l_item->tsd, l_item->tsd_size) {
            if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_HASH && l_tsd->size == sizeof(dap_hash_fast_t))
                l_all_hashes[l_idx++] = *(dap_hash_fast_t *)l_tsd->data;
        }
        dap_assert(dap_hash_fast_compare(&l_all_hashes[0], &l_addr_hashes[0]), "variant3: hash[0] from addr[0]");
        dap_assert(dap_hash_fast_compare(&l_all_hashes[1], &l_addr_hashes[1]), "variant3: hash[1] from addr[1]");
        dap_assert(dap_hash_fast_compare(&l_all_hashes[2], &l_standalone_hashes[0]), "variant3: hash[2] is standalone[0]");
        dap_assert(dap_hash_fast_compare(&l_all_hashes[3], &l_standalone_hashes[1]), "variant3: hash[3] is standalone[1]");
        DAP_DELETE(l_item);
    }

    // --- Edge: cross-duplicate detection ---
    {
        dap_test_msg("edge: cross-duplicate addr hash == standalone hash");
        dap_hash_fast_t l_hash;
        randombytes(&l_hash, sizeof(l_hash));
        dap_chain_addr_t l_addr;
        s_fill_test_addr(&l_addr, &l_hash);
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 1, &l_addr, 1, &l_hash, 1, NULL);
        dap_assert(!l_item, "cross_dup: returns NULL on cross-duplicate");
    }

    // --- Edge: invalid addr type ---
    {
        dap_test_msg("edge: non-regular address type");
        dap_hash_fast_t l_hash;
        randombytes(&l_hash, sizeof(l_hash));
        dap_chain_addr_t l_addr;
        s_fill_test_addr(&l_addr, &l_hash);
        l_addr.addr_type = DAP_CHAIN_ADDR_TYPE_SHARED;
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_by_addrs(
            l_srv_uid, l_value, 1, &l_addr, 1, NULL);
        dap_assert(!l_item, "invalid_addr: returns NULL for non-regular addr");
    }

    // --- Edge: zero owners ---
    {
        dap_test_msg("edge: zero owners");
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 1, NULL, 0, NULL, 0, NULL);
        dap_assert(!l_item, "zero_owners: returns NULL");
    }

    // --- Edge: NULL hashes ptr with non-zero count ---
    {
        dap_test_msg("edge: NULL hashes ptr with count > 0");
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 1, NULL, 0, NULL, 5, NULL);
        dap_assert(!l_item, "null_ptr: returns NULL for NULL ptr with count");
    }

    // --- Edge: NULL addrs ptr with non-zero count ---
    {
        dap_test_msg("edge: NULL addrs ptr with count > 0");
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 1, NULL, 3, NULL, 0, NULL);
        dap_assert(!l_item, "null_addr_ptr: returns NULL for NULL addrs with count");
    }

    // --- Large owner count ---
    {
        dap_test_msg("stress: 50 addrs + 50 standalone hashes");
        dap_hash_fast_t l_addr_hashes[50], l_standalone[50];
        randombytes(l_addr_hashes, sizeof(l_addr_hashes));
        randombytes(l_standalone, sizeof(l_standalone));
        dap_chain_addr_t l_addrs[50];
        for (size_t i = 0; i < 50; i++)
            s_fill_test_addr(&l_addrs[i], &l_addr_hashes[i]);
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 5, l_addrs, 50, l_standalone, 50, "big_tag");
        dap_assert(l_item, "stress: item created with 100 owners");
        size_t l_hash_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_HASH, sizeof(dap_hash_fast_t));
        size_t l_addr_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, sizeof(dap_chain_addr_t));
        dap_assert(l_hash_count == 100, "stress: 100 TSD_HASH entries");
        dap_assert(l_addr_count == 50, "stress: 50 TSD_ADDR entries");
        DAP_DELETE(l_item);
    }

    // --- Variant 3: addrs only through _ext (pkey_hashes=NULL, count=0) ---
    {
        dap_test_msg("variant3 as variant2: addrs only through _ext");
        dap_hash_fast_t l_hash;
        randombytes(&l_hash, sizeof(l_hash));
        dap_chain_addr_t l_addr;
        s_fill_test_addr(&l_addr, &l_hash);
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 1, &l_addr, 1, NULL, 0, NULL);
        dap_assert(l_item, "ext_as_v2: item created");
        size_t l_hash_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_HASH, sizeof(dap_hash_fast_t));
        size_t l_addr_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, sizeof(dap_chain_addr_t));
        dap_assert(l_hash_count == 1, "ext_as_v2: 1 TSD_HASH");
        dap_assert(l_addr_count == 1, "ext_as_v2: 1 TSD_ADDR");
        DAP_DELETE(l_item);
    }

    // --- Variant 3: hashes only through _ext (addrs=NULL, count=0) ---
    {
        dap_test_msg("variant3 as variant1: hashes only through _ext");
        dap_hash_fast_t l_hash;
        randombytes(&l_hash, sizeof(l_hash));
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 1, NULL, 0, &l_hash, 1, NULL);
        dap_assert(l_item, "ext_as_v1: item created");
        size_t l_hash_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_HASH, sizeof(dap_hash_fast_t));
        size_t l_addr_count = s_count_tsd_by_type(l_item->tsd, l_item->tsd_size, DAP_CHAIN_TX_OUT_COND_TSD_ADDR, sizeof(dap_chain_addr_t));
        dap_assert(l_hash_count == 1, "ext_as_v1: 1 TSD_HASH");
        dap_assert(l_addr_count == 0, "ext_as_v1: 0 TSD_ADDR");
        DAP_DELETE(l_item);
    }

    // --- TSD tag presence/absence ---
    {
        dap_test_msg("tag: verify TSD_STR written when tag provided");
        dap_hash_fast_t l_hash;
        randombytes(&l_hash, sizeof(l_hash));
        const char *l_tag = "my_test_tag";
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared(
            l_srv_uid, l_value, 1, &l_hash, 1, l_tag);
        dap_assert(l_item, "tag: item created");
        bool l_found_tag = false;
        dap_tsd_t *l_tsd; size_t l_tsd_size;
        dap_tsd_iter(l_tsd, l_tsd_size, l_item->tsd, l_item->tsd_size) {
            if (l_tsd->type == DAP_CHAIN_TX_OUT_COND_TSD_STR) {
                l_found_tag = !strcmp((char *)l_tsd->data, l_tag);
            }
        }
        dap_assert(l_found_tag, "tag: TSD_STR matches expected tag string");
        DAP_DELETE(l_item);
    }

    // --- TSD ordering: hashes from addrs, then standalone hashes, then addrs ---
    {
        dap_test_msg("ordering: verify TSD entry order in mixed mode");
        dap_hash_fast_t l_ah[2], l_sh[1];
        randombytes(l_ah, sizeof(l_ah));
        randombytes(l_sh, sizeof(l_sh));
        dap_chain_addr_t l_addrs[2];
        for (size_t i = 0; i < 2; i++)
            s_fill_test_addr(&l_addrs[i], &l_ah[i]);
        dap_chain_tx_out_cond_t *l_item = dap_chain_datum_tx_item_out_cond_create_wallet_shared_ext(
            l_srv_uid, l_value, 1, l_addrs, 2, l_sh, 1, "ord_tag");
        dap_assert(l_item, "ordering: item created");
        uint16_t l_type_order[6];
        size_t l_ord_idx = 0;
        dap_tsd_t *l_tsd; size_t l_tsd_size;
        dap_tsd_iter(l_tsd, l_tsd_size, l_item->tsd, l_item->tsd_size) {
            if (l_ord_idx < 6)
                l_type_order[l_ord_idx++] = l_tsd->type;
        }
        dap_assert(l_ord_idx == 6, "ordering: exactly 6 TSD entries (3 hash + 2 addr + 1 str)");
        dap_assert(l_type_order[0] == DAP_CHAIN_TX_OUT_COND_TSD_HASH, "ordering: [0] is TSD_HASH");
        dap_assert(l_type_order[1] == DAP_CHAIN_TX_OUT_COND_TSD_HASH, "ordering: [1] is TSD_HASH");
        dap_assert(l_type_order[2] == DAP_CHAIN_TX_OUT_COND_TSD_HASH, "ordering: [2] is TSD_HASH");
        dap_assert(l_type_order[3] == DAP_CHAIN_TX_OUT_COND_TSD_ADDR, "ordering: [3] is TSD_ADDR");
        dap_assert(l_type_order[4] == DAP_CHAIN_TX_OUT_COND_TSD_ADDR, "ordering: [4] is TSD_ADDR");
        dap_assert(l_type_order[5] == DAP_CHAIN_TX_OUT_COND_TSD_STR, "ordering: [5] is TSD_STR");
        DAP_DELETE(l_item);
    }
}

void s_chain_datum_tx_ser_deser_test()
{
    s_data = DAP_NEW_Z_RET_IF_FAIL(struct tests_data);
    randombytes(s_data, sizeof(struct tests_data));
    s_data->time_staking = dap_time_now() + 10000;
    s_data->reinvest_percent = dap_chain_coins_to_balance("12.3456789");
    for (size_t i = 0; i < KEY_COUNT; ++i)
        s_key[i] = dap_enc_key_new_generate(s_key_types[rand() % s_sign_type_count], NULL, 0, NULL, 0, 0);
    memset(&s_data->config, 0, sizeof(compose_config_t));
    s_data->config.net_name = s_net_name;
    s_data->config.url_str = s_url;
    s_data->config.port = 8081;
    s_data->config.enc_cert_path = NULL;
    s_data->config.response_handler = json_object_new_object();
    s_data->value_fee._hi.a = 0;
    s_data->value_fee._hi.b = 0;
    s_data->value_fee._lo.a = 0;
    s_data->value_fee._lo.b = rand() % 1000;
    s_data->config.native_ticker = s_ticker_native;
    s_data->config.net_name = s_net_name;
    s_data->config.net_id.uint64 = rand();

    
    s_chain_datum_tx_create_test();
    s_chain_datum_cond_create_test();
    s_chain_datum_stake_lock_test();
    s_chain_datum_delegate_test();
    s_chain_datum_stake_unlock_test();
    s_chain_datum_stake_invalidate_test();
#if 0
    s_chain_datum_exchange_create_test();
    s_chain_datum_exchange_purchase_test(s_ticker_native, s_ticker_delegate);
    s_chain_datum_exchange_purchase_test(s_ticker_delegate, s_ticker_native);
    s_chain_datum_exchange_purchase_test(s_ticker_delegate, s_ticker_custom);
#endif
    s_chain_datum_xchange_invalidate_test(s_ticker_native, s_ticker_delegate);
    s_chain_datum_xchange_invalidate_test(s_ticker_delegate, s_ticker_native);
    s_chain_datum_xchange_invalidate_test(s_ticker_delegate, s_ticker_custom);
    s_chain_datum_vote_create_test();
    s_chain_datum_vote_voting_test();
    s_wallet_shared_item_create_tests();
    s_chain_datum_shared_funds_hold_test();
    s_chain_datum_shared_funds_hold_by_addrs_test();
    s_chain_datum_shared_funds_hold_ext_test();
    s_chain_datum_shared_funds_take_test();
    s_chain_datum_shared_funds_refill_test();
    s_chain_datum_tx_cond_refill_test();
    s_chain_datum_tx_cond_remove_test();
    // s_chain_datum_shared_funds_sign_test();  no need for now
    if (s_data->config.response_handler) {
        json_object_put(s_data->config.response_handler);
    }
    DAP_DEL_Z(s_data);
    for (size_t i = 0; i < KEY_COUNT; ++i)
        dap_enc_key_delete(s_key[i]);
}

int main(void){
    dap_log_level_set(L_DEBUG);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    srand(time(NULL));
    s_chain_datum_tx_ser_deser_test();
    return 0;
}
