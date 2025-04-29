#include "dap_test.h"
#include "dap_rand.h"
#include "dap_chain_net.h"
#include "dap_chain_tx_compose.h"
#include <json-c/json.h>

#define LOG_TAG "dap_tx_compose_tests"

int dap_chain_net_tx_to_json(dap_chain_datum_tx_t *a_tx, json_object *a_out_json);
int dap_chain_net_tx_create_by_json(json_object *a_tx_json, dap_chain_net_t *a_net, json_object *a_json_obj_error, 
    dap_chain_datum_tx_t** a_out_tx, size_t* a_items_count, size_t *a_items_ready);

void s_chain_datum_tx_create_test()
{ 
    dap_chain_addr_t *l_addr_from = DAP_NEW_Z_RET_IF_FAIL(dap_chain_addr_t);
    dap_chain_addr_t *l_addr_to = DAP_NEW_Z_RET_IF_FAIL(dap_chain_addr_t);
    const char *l_ticker = "BUZ";
    uint256_t l_value, l_value_fee;
    randombytes(l_addr_from, sizeof(dap_chain_addr_t));
    randombytes(l_addr_to, sizeof(dap_chain_addr_t));
    randombytes(&l_value, sizeof(uint256_t));
    randombytes(&l_value_fee, sizeof(uint256_t));
    dap_chain_datum_tx_t *l_datum_1 = dap_chain_datum_tx_create_compose(l_addr_from, &l_addr_to, l_ticker, &l_value, l_value_fee, 1, NULL);
    dap_assert_PIF(l_datum_1, "tx_create_compose");
    json_object *l_datum_1_json = json_object_new_object();
    json_object *l_error_json = json_object_new_array();
    dap_chain_net_tx_to_json(l_datum_1, l_datum_1_json);
    dap_assert_PIF(l_datum_1, "tx_create_compose");
    const char *l_to_print = json_object_to_json_string(l_datum_1_json);
    dap_pass_msg(l_to_print);
    dap_chain_datum_tx_t *l_datum_2 = DAP_NEW_Z(dap_chain_datum_tx_t);
    size_t
        l_items_count = 0,
        l_items_ready = 0;
    dap_assert_PIF(!dap_chain_net_tx_create_by_json(l_datum_1_json, NULL, l_error_json, &l_datum_2, &l_items_count, &l_items_ready), "tx_create_by_json");
    dap_assert_PIF(l_items_count == l_items_ready, "items_count == items_ready")
    dap_assert_PIF(l_datum_1->header.tx_items_size == l_datum_2->header.tx_items_size, "items_size_1 == items_size_2");
    dap_assert_PIF(!memcmp(l_datum_1, l_datum_2, dap_chain_datum_size(l_datum_1)), "datum_1 == datum_2");
    dap_chain_datum_tx_delete(l_datum_1);
    dap_chain_datum_tx_delete(l_datum_2);
    return;
}

void s_chain_datum_tx_ser_deser_test()
{
    s_chain_datum_tx_create_test();
}

int main(void){
    dap_log_level_set(L_WARNING);
    s_chain_datum_tx_ser_deser_test();
    return 0;
}