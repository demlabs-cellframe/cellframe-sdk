#include "dap_test.h"
#include "dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_token.h"
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
    dap_chain_tx_out_cond_t cond_out;
    compose_config_t config;
    time_t time_staking;
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
        int l_tsd_type = (i % 2 == 0) ? DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_DATA : DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_TIMESTAMP;
        dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create(&l_rand_data, l_tsd_type, sizeof(l_rand_data));
        if (l_tsd->header.size != sizeof(dap_time_t)) {
            log_it(L_WARNING, "Invalid expire time size");
            DAP_DEL_Z(l_tsd);
            continue;
        }
        dap_assert(dap_chain_datum_tx_add_item(a_datum, l_tsd) == 1, "datum_1 add tsd");
        DAP_DEL_Z(l_tsd);
    }
    l_signs_count = rand() % KEY_COUNT + 3;
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
    dap_chain_datum_tx_t *l_datum_2 = dap_chain_datum_tx_create();;
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
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_datum_tx_create_compose(&s_data->addr_from, &l_addr_to, s_ticker_native, &s_data->value, s_data->value_fee, 1, &s_data->config);
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
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_mempool_tx_create_cond_compose(
        &s_data->addr_from, pkey, s_ticker_native, s_data->value,
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
    dap_chain_datum_tx_t *l_datum_1 = dap_stake_tx_create_compose(&s_data->addr_any, s_data->value, s_data->value_fee, &s_data->addr_from, &s_data->node_addr, &s_data->addr_to, s_data->reinvest_percent, NULL, pkey, &s_data->config);
    dap_assert(l_datum_1, "tx_stake_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(pkey);
}

void s_chain_datum_stake_lock_test()
{
    dap_print_module_name("tx_lock_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_stake_lock_datum_create_compose(&s_data->addr_from, s_ticker_native, s_data->value, s_data->value_fee, s_data->time_staking, s_data->reinvest_percent, s_ticker_delegate, s_data->value_delegate, "0x0123456789abcdef", &s_data->config);
    dap_assert(l_datum_1, "tx_lock_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_stake_unlock_test()
{
    dap_print_module_name("tx_unlock_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_stake_unlock_datum_create_compose(
        &s_data->addr_from, &s_data->hash_1, s_data->idx_1, s_ticker_native, s_data->value, s_data->value_fee, 
        s_ticker_delegate, s_data->value_delegate, &s_data->config);
    dap_assert(l_datum_1, "tx_unlock_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_stake_invalidate_test()
{
    dap_print_module_name("tx_invalidate_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_stake_tx_invalidate_compose(
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
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_net_vote_create_compose(
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
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_net_vote_voting_compose(
        l_cert, s_data->value_fee, &s_data->addr_from, s_data->hash_1, s_data->idx_1, &s_data->config);
    dap_assert(l_datum_1, "tx_vote_voting_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    dap_cert_delete(l_cert);
}

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
    s_data->config.enc = false;
    s_data->config.cert_path = NULL;
    s_data->config.response_handler = json_object_new_object();
    s_data->value_fee._hi.a = 0;
    s_data->value_fee._hi.b = 0;
    s_data->value_fee._lo.a = 0;
    s_data->value_fee._lo.b = rand() % 1000;
    
    s_chain_datum_tx_create_test();
    s_chain_datum_cond_create_test();
    s_chain_datum_stake_lock_test();
    s_chain_datum_delegate_test();
    s_chain_datum_stake_unlock_test();
    s_chain_datum_stake_invalidate_test();
    s_chain_datum_exchange_create_test();
    s_chain_datum_exchange_purchase_test(s_ticker_native, s_ticker_delegate);
    s_chain_datum_exchange_purchase_test(s_ticker_delegate, s_ticker_native);
    s_chain_datum_exchange_purchase_test(s_ticker_delegate, s_ticker_custom);
    s_chain_datum_xchange_invalidate_test(s_ticker_native, s_ticker_delegate);
    s_chain_datum_xchange_invalidate_test(s_ticker_delegate, s_ticker_native);
    s_chain_datum_xchange_invalidate_test(s_ticker_delegate, s_ticker_custom);
    s_chain_datum_vote_create_test();
    s_chain_datum_vote_voting_test();

    if (s_data->config.response_handler) {
        json_object_put(s_data->config.response_handler);
    }
    DAP_DEL_Z(s_data);
    for (size_t i = 0; i < KEY_COUNT; ++i)
        dap_enc_key_delete(s_key[i]);
}

int main(void){
    dap_log_level_set(L_WARNING);
    dap_log_set_external_output(LOGGER_OUTPUT_STDOUT, NULL);
    srand(time(NULL));
    s_chain_datum_tx_ser_deser_test();
    return 0;
}
