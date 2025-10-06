#include "dap_chain_net_srv_xchange_compose.h"
#include "dap_chain_mempool_compose.h"
#include "dap_chain_net_srv_stake_compose.h"
#include "dap_test.h"
#include "dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_tx_compose.h"
#include "dap_chain_net_srv_voting_compose.h"
#include "dap_chain_datum_tx.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_chain_datum_token.h"
#include "dap_json.h"

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
    dap_chain_srv_uid_t srv_uid;
    dap_chain_tx_compose_config_t config;
    time_t time_staking;
    dap_chain_tx_out_cond_t cond_out; // Variable sized type moved to end
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

int dap_chain_tx_datum_from_json(dap_json_t *a_tx_json, dap_chain_net_t *a_net, dap_json_t *a_jobj_arr_errors,
        dap_chain_datum_tx_t** a_out_tx, size_t* a_items_count, size_t *a_items_ready);
int dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, dap_json_t *a_out_json);

void s_datum_sign_and_check(dap_chain_datum_tx_t **a_datum)
{
    size_t l_signs_count = rand() % KEY_COUNT + 1;
    dap_test_msg("add %zu tsd sections", l_signs_count);
    for (size_t i = 0; i < l_signs_count; ++i) {
        int l_rand_data = rand() % dap_maxval(l_rand_data);
        dap_chain_tx_tsd_t *l_tsd = dap_chain_datum_tx_item_tsd_create(&l_rand_data, rand() % dap_maxval(l_rand_data), sizeof(l_rand_data));
        if (l_tsd->header.size != sizeof(dap_time_t)) {
            log_it(L_WARNING, "Invalid expire time size");
            continue;
        }
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
    dap_json_t *l_datum_1_json = dap_json_object_new();
    dap_json_t *l_error_json = dap_json_array_new();
    dap_test_msg("convert to json");
    int l_json_result = dap_chain_net_tx_to_json(*a_datum, l_datum_1_json);
    if (l_json_result == 0 && dap_json_object_length(l_datum_1_json) > 0) {
        dap_test_msg("dap_chain_net_tx_to_json PASS.");
        printf("\n");
        
        dap_chain_datum_tx_t *l_datum_2 = dap_chain_datum_tx_create();
        size_t l_items_count = 0, l_items_ready = 0;
        dap_test_msg("create datum from json");
        int l_from_json_result = dap_chain_tx_datum_from_json(l_datum_1_json, NULL, l_error_json, &l_datum_2, &l_items_count, &l_items_ready);
        
        if (l_from_json_result == 0) {
            dap_test_msg("tx_create_by_json PASS.");
            dap_assert(l_items_count == l_items_ready, "items_count == items_ready");
            dap_assert((*a_datum)->header.tx_items_size == l_datum_2->header.tx_items_size, "items_size_1 == items_size_2");
            dap_assert(!memcmp((*a_datum), l_datum_2, dap_chain_datum_tx_get_size(*a_datum)), "datum_1 == datum_2");
            
        } else {
            dap_test_msg("tx_create_by_json FAILED.");
        }
        
        if (l_datum_2) {
            dap_chain_datum_tx_delete(l_datum_2);
        }
    } else {
        dap_test_msg("dap_chain_net_tx_to_json FAILED.");
    }
    
    dap_json_object_free(l_datum_1_json);
    dap_json_object_free(l_error_json);
}

void s_chain_datum_tx_create_test()
{ 
    dap_print_module_name("tx_create_compose");
    dap_chain_addr_t *l_addr_to_ptr = &s_data->addr_to;
    dap_chain_addr_t **l_addr_to = &l_addr_to_ptr;
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_datum_tx_create_compose(&s_data->addr_from, l_addr_to, s_ticker_native, &s_data->value, s_data->value_fee, 1, &s_data->config);
    dap_assert(l_datum_1, "tx_create_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_cond_create_test()
{
    dap_print_module_name("tx_cond_create_compose");
    size_t l_rand_data_size = rand() % 256;
    char *l_rand_data = DAP_NEW_Z_SIZE_RET_IF_FAIL(char, l_rand_data_size);
    if (l_rand_data_size > 0) {
        randombytes(l_rand_data, l_rand_data_size);
    }
    size_t l_pkey_size = rand() % 1024 + 1; // Ensure non-zero size
    dap_pkey_t *pkey = DAP_NEW_Z_SIZE_RET_IF_FAIL(dap_pkey_t, l_pkey_size + sizeof(dap_pkey_t));
    pkey->header.type.type = DAP_PKEY_TYPE_SIG_BLISS;
    pkey->header.size = l_pkey_size;
    randombytes(pkey->pkey, l_pkey_size);
    dap_chain_net_srv_price_unit_uid_t price_unit;
    price_unit.enm = SERV_UNIT_B;
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_mempool_compose_tx_create_cond(
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
    dap_print_module_name("tx_delegate_compose");
    size_t l_pkey_size = rand() % 1024 + 1; // Ensure non-zero size
    dap_pkey_t *pkey = DAP_NEW_Z_SIZE_RET_IF_FAIL(dap_pkey_t, l_pkey_size + sizeof(dap_pkey_t));
    pkey->header.type.type = DAP_PKEY_TYPE_SIG_BLISS;
    pkey->header.size = l_pkey_size;
    randombytes(pkey->pkey, l_pkey_size);
    // TODO fix to delegate
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_net_srv_stake_compose_tx_create(&s_data->addr_any, s_data->value, s_data->value_fee, &s_data->addr_from, &s_data->node_addr, &s_data->addr_to, s_data->reinvest_percent, NULL, pkey, &s_data->config);
    dap_assert(l_datum_1, "tx_delegate_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
    DAP_DELETE(pkey);
}

void s_chain_datum_stake_lock_test()
{
    dap_print_module_name("tx_lock_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_net_srv_stake_compose_lock_datum_create(&s_data->addr_from, s_ticker_native, s_data->value, s_data->value_fee, s_data->time_staking, s_data->reinvest_percent, s_ticker_delegate, s_data->value_delegate, "0x0123456789abcdef", &s_data->config);
    dap_assert(l_datum_1, "tx_lock_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_stake_unlock_test()
{
    dap_print_module_name("tx_unlock_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_net_srv_stake_compose_unlock_datum_create(
        &s_data->addr_from, &s_data->hash_1, s_data->idx_1, s_ticker_native, s_data->value, s_data->value_fee, 
        s_ticker_delegate, s_data->value_delegate, &s_data->config);
    dap_assert(l_datum_1, "tx_unlock_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_stake_invalidate_test()
{
    dap_print_module_name("tx_invalidate_compose");
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_net_srv_stake_compose_tx_invalidate(
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
//     dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
//     dap_stpcpy(l_price->token_sell, s_ticker_native);
//     dap_stpcpy(l_price->token_buy, s_ticker_delegate);
//     l_price->datoshi_sell = s_data->value;
// //     l_price->rate = s_data->reinvest_percent;
// //     l_price->fee = s_data->value_fee;
// //     // sell native
// //     dap_chain_datum_tx_t *l_datum_1 = dap_xchange_tx_create_request_compose(l_price, &s_data->addr_from, s_ticker_native, &s_data->config);
// //     dap_assert(l_datum_1, "tx_exchange_create_compose sell native");
// //     s_datum_sign_and_check(&l_datum_1);
// //     dap_chain_datum_tx_delete(l_datum_1);
// //     // sell non native
// // //     l_datum_1 = dap_xchange_tx_create_request_compose(l_price, &s_data->addr_from, s_ticker_delegate, &s_data->config);
// //     dap_assert(l_datum_1, "tx_exchange_create_compose sell non native");
// //     s_datum_sign_and_check(&l_datum_1);
// //     dap_chain_datum_tx_delete(l_datum_1);
// //     DAP_DELETE(l_price);
// // }
// // 
// // void s_chain_datum_exchange_purchase_test(const char *a_token_sell, const char *a_token_buy)
// // {
// //     dap_print_module_name("tx_exchange_purchase_compose");
// //     dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
// //     dap_stpcpy(l_price->token_sell, a_token_sell);
// //     dap_stpcpy(l_price->token_buy, a_token_buy);
// //     l_price->datoshi_sell = s_data->value;
// //     l_price->rate = s_data->reinvest_percent;
// //     l_price->fee = s_data->value_fee;
// // //     dap_chain_datum_tx_t *l_datum_1 = dap_xchange_tx_create_exchange_compose(
// // //         l_price, &s_data->addr_from, s_data->value_delegate, s_data->value_fee,
// //         &s_data->cond_out, s_data->idx_1, &s_data->config
// //     );
// //     dap_assert(l_datum_1, "tx_exchange_purchase_compose");
// //     s_datum_sign_and_check(&l_datum_1);
// //     dap_chain_datum_tx_delete(l_datum_1);
// //     DAP_DELETE(l_price);
// // }
// // 
// // void s_chain_datum_xchange_invalidate_test(const char *a_token_sell, const char *a_token_buy)
// // {
// //     dap_print_module_name("tx_exchange_invalidate_compose");
// //     dap_chain_net_srv_xchange_price_t *l_price = DAP_NEW_Z(dap_chain_net_srv_xchange_price_t);
// //     dap_stpcpy(l_price->token_sell, a_token_sell);
// //     dap_stpcpy(l_price->token_buy, a_token_buy);
// //     l_price->datoshi_sell = s_data->value;
// //     l_price->rate = s_data->reinvest_percent;
// //     l_price->fee = s_data->value_fee;
// // //     dap_chain_datum_tx_t *l_datum_1 = dap_xchange_tx_invalidate_compose(l_price, &s_data->cond_out, &s_data->addr_from, &s_data->addr_to, a_token_buy, 0, &s_data->config);
// // //     dap_assert(l_datum_1, "tx_exchange_invalidate_compose");
// //     s_datum_sign_and_check(&l_datum_1);
// //     dap_chain_datum_tx_delete(l_datum_1);
// //     DAP_DELETE(l_price);
}

void s_chain_datum_tx_ser_deser_test()
{
    s_data = DAP_NEW_Z_RET_IF_FAIL(struct tests_data);

    // Generate keys first before any tests
    for (size_t i = 0; i < KEY_COUNT; ++i)
        s_key[i] = dap_enc_key_new_generate(s_key_types[rand() % s_sign_type_count], NULL, 0, NULL, 0, 0);
    
    // Initialize individual fields instead of overwriting entire structure with random data
    randombytes(&s_data->value, sizeof(s_data->value));
    randombytes(&s_data->value_delegate, sizeof(s_data->value_delegate));
    randombytes(&s_data->value_per_unit_max, sizeof(s_data->value_per_unit_max));
    randombytes(&s_data->hash_1, sizeof(s_data->hash_1));
    randombytes(&s_data->srv_uid, sizeof(s_data->srv_uid));
    randombytes(&s_data->cond_out, sizeof(s_data->cond_out));
    randombytes(&s_data->node_addr, sizeof(s_data->node_addr));
    s_data->idx_1 = rand();
    s_data->idx_2 = rand();
    
    s_data->time_staking = dap_time_now() + 10000;
    s_data->reinvest_percent = dap_chain_balance_coins_scan("12.3456789");
    
    memset(&s_data->config, 0, sizeof(dap_chain_tx_compose_config_t));
    s_data->addr_from = *dap_chain_addr_from_str("o9z3wUTSTicckJuoxkLc5q1CwaYs23474GbBm8ebgSZd1WmB7EhkPDpsoZPGX3hmhGa1wCqTDKgPjirbp3H45bg3tc6U5k8wCEJX575X");
    s_data->addr_to = *dap_chain_addr_from_str("o9z3wUTSTicckJuoyzRZwr7gJE6GruN5VYiGwWA2TWh5LWXSZC4gS21WrxHD3eqaTJneuoCGVzgrbMNrMPAW3BtWRujQn9TgtJhGqBgS");
    // Initialize addr_any to a valid address
    s_data->addr_any = s_data->addr_from;
    
    s_data->config.net_name = s_net_name;
    s_data->config.url_str = s_url;
    s_data->config.port = 8081;
    s_data->config.enc = false;
    s_data->config.cert_path = NULL;
    s_data->config.response_handler = dap_json_object_new();
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
//     s_chain_datum_exchange_purchase_test(s_ticker_native, s_ticker_delegate);
    s_chain_datum_exchange_purchase_test(s_ticker_delegate, s_ticker_native);
    s_chain_datum_exchange_purchase_test(s_ticker_delegate, s_ticker_custom);
//     s_chain_datum_xchange_invalidate_test(s_ticker_native, s_ticker_delegate);
    s_chain_datum_xchange_invalidate_test(s_ticker_delegate, s_ticker_native);
    s_chain_datum_xchange_invalidate_test(s_ticker_delegate, s_ticker_custom);
    // s_chain_datum_vote_create_test();
    // s_chain_datum_vote_voting_test();

    if (s_data->config.response_handler) {
        dap_json_object_free(s_data->config.response_handler);
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
