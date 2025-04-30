#include "dap_test.h"
#include "dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_tx_compose.h"
#include <json-c/json.h>

#define LOG_TAG "dap_tx_compose_tests"


const char *s_ticker = "BUZ";
const char *s_ticker_delegate = "mBUZ";

struct tests_data {
    dap_chain_addr_t addr_from;
    dap_chain_addr_t addr_to;
    uint256_t value;
    uint256_t value_fee;
    uint256_t value_delegate;
    uint256_t value_per_unit_max;
    uint256_t reinvest_percent;
    dap_chain_net_srv_uid_t srv_uid;
    compose_config_t config;
    time_t time_staking;
};

static struct tests_data *s_data = NULL;
dap_enc_key_t *s_key = NULL;

int dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, json_object *a_out_json);
int dap_chain_net_tx_create_by_json(json_object *a_tx_json, dap_chain_net_t *a_net, json_object *a_json_obj_error, 
    dap_chain_datum_tx_t** a_out_tx, size_t* a_items_count, size_t *a_items_ready);

void s_datum_sign_and_check(dap_chain_datum_tx_t **a_datum)
{
    size_t l_tx_size = dap_chain_datum_tx_get_size(*a_datum);
    dap_assert_PIF(dap_chain_datum_tx_add_sign_item(a_datum, s_key), "datum_1 sign create");
    json_object *l_datum_1_json = json_object_new_object();
    json_object *l_error_json = json_object_new_array();
    dap_chain_net_tx_to_json(*a_datum, l_datum_1_json);
    dap_assert_PIF(*a_datum, "tx_create_compose");
    dap_chain_datum_tx_t *l_datum_2 = DAP_NEW_Z(dap_chain_datum_tx_t);
    size_t
        l_items_count = 0,
        l_items_ready = 0;
    dap_assert_PIF(!dap_chain_net_tx_create_by_json(l_datum_1_json, NULL, l_error_json, &l_datum_2, &l_items_count, &l_items_ready), "tx_create_by_json");
    dap_assert_PIF(l_items_count == l_items_ready, "items_count == items_ready")
    dap_assert_PIF((*a_datum)->header.tx_items_size == l_datum_2->header.tx_items_size, "items_size_1 == items_size_2");
    dap_assert_PIF(!memcmp((*a_datum), l_datum_2, dap_chain_datum_size(*a_datum)), "datum_1 == datum_2");
    dap_assert_PIF(!dap_chain_datum_tx_verify_sign(*a_datum, 0), "datum_2 sign verify");
    dap_chain_datum_tx_delete(l_datum_2);
}

void s_chain_datum_tx_create_test()
{ 
    dap_chain_addr_t *l_addr_to = &s_data->addr_to;
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_datum_tx_create_compose(&s_data->addr_from, &l_addr_to, s_ticker, &s_data->value, s_data->value_fee, 1, NULL);
    dap_assert_PIF(l_datum_1, "tx_create_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_cond_create_test()
{ 
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
        s_key, pkey, s_ticker, s_data->value,
        s_data->value_per_unit_max, price_unit,
        s_data->srv_uid, s_data->value_fee, l_rand_data, l_rand_data_size, &s_data->config
    );
    dap_assert_PIF(l_datum_1, "tx_create_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}


void s_chain_datum_stake_lock_test()
{ 
    dap_chain_datum_tx_t *l_datum_1 = dap_stake_lock_datum_create_compose(s_key, s_ticker, s_data->value, s_data->value_fee, s_data->time_staking, s_data->reinvest_percent, s_ticker_delegate, s_data->value_delegate, "0x0123456789abcdef", &s_data->config);
    dap_assert_PIF(l_datum_1, "tx_lock_compose");
    s_datum_sign_and_check(&l_datum_1);
    dap_chain_datum_tx_delete(l_datum_1);
}

void s_chain_datum_tx_ser_deser_test()
{
    s_data = DAP_NEW_Z_RET_IF_FAIL(struct tests_data);
    randombytes(s_data, sizeof(struct tests_data));
    s_data->time_staking = dap_time_now() + 10000;
    s_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    
    s_chain_datum_tx_create_test();
    // s_chain_datum_cond_create_test();
    // s_chain_datum_stake_lock_test();

    DAP_DEL_Z(s_data);
    dap_enc_key_delete(s_key);
}

int main(void){
    dap_log_level_set(L_WARNING);
    s_chain_datum_tx_ser_deser_test();
    return 0;
}