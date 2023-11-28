#include "dap_struct_packing_tests.h"
#include "dap_math_ops.h"
#include "../include/dap_chain_datum_tx_out.h"
#include "../include/dap_chain_datum_tx_in_cond.h"
#include "../include/dap_chain_datum_tx_in_ems.h"
#include "../include/dap_chain_datum_tx_in.h"
#include "../include/dap_chain_datum_tx_out_cond.h"

DAP_STATIC_INLINE int s_get_delta_addr(const void *a_addr_1, const void *a_addr_2)
{
    return a_addr_2 - a_addr_1;
}

static int s_chain_tx_in_cond_test()
{
    dap_print_module_name("dap_chain_tx_in_cond_test");
    dap_chain_tx_in_cond_t s = {0};
    dap_assert(sizeof(s) == 44, "size");
    dap_assert(sizeof(s.header) == 44, "header size");
    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "header");
    dap_assert(s_get_delta_addr(&s, &s.header.type) == 0, "header.type");
    dap_assert(s_get_delta_addr(&s, &s.header.tx_prev_hash) == 1, "header.tx_prev_hash");
    dap_assert(s_get_delta_addr(&s, &s.header.tx_out_prev_idx) == 36, "header.tx_out_prev_idx");
    dap_assert(s_get_delta_addr(&s, &s.header.receipt_idx) == 40, "header.receipt_idx");
    return 0;
}

static int s_chain_datum_tx_in_ems_test()
{
    dap_print_module_name("dap_chain_datum_tx_in_ems_test");
    dap_chain_tx_in_ems_t s = {0};
    dap_assert(sizeof(s) == 52, "size");
    dap_assert(sizeof(s.header) == 52, "header size");
    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "header");
    dap_assert(s_get_delta_addr(&s, &s.header.type) == 0, "header.type");
    dap_assert(s_get_delta_addr(&s, &s.header.ticker) == 1, "header.ticker");
    dap_assert(s_get_delta_addr(&s, &s.header.token_emission_chain_id) == 12, "header.tx_out_prev_idx");
    dap_assert(s_get_delta_addr(&s, &s.header.token_emission_hash) == 20, "header.receipt_idx");
    return 0;
}

static int s_chain_tx_in_test()
{
    dap_print_module_name("dap_chain_tx_in_test");
    dap_chain_tx_in_t s = {0};   
    dap_assert(sizeof(s) == 40, "size");
    dap_assert(sizeof(s.header) == 40, "header size");
    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "header");
    dap_assert(s_get_delta_addr(&s, &s.header.type) == 0, "header.type");
    dap_assert(s_get_delta_addr(&s, &s.header.tx_prev_hash) == 1, "header.tx_prev_hash");
    dap_assert(s_get_delta_addr(&s, &s.header.tx_out_prev_idx) == 36, "header.tx_out_prev_idx");
    return 0;
}

static int s_chain_tx_out_cond_old_test()
{
    dap_print_module_name("dap_chain_tx_in_test");
    dap_chain_tx_out_cond_old_t s = {0};
 
    dap_assert(sizeof(s) == 220, "size");
    dap_assert(sizeof(s.header) == 24, "header size");
    dap_assert(sizeof(s.subtype) == 192, "subtype size");
    dap_assert(sizeof(s.subtype.srv_pay) == 56, "subtype.srv_pay size");
    dap_assert(sizeof(s.subtype.srv_stake) == 192, "subtype.srv_stake size");
    dap_assert(sizeof(s.subtype.srv_xchange) == 40, "subtype.srv_xchange size");

    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "header");
    dap_assert(s_get_delta_addr(&s, &s.header.item_type) == 0, "header.item_type");
    dap_assert(s_get_delta_addr(&s, &s.header.subtype) == 1, "header.subtype");
    dap_assert(s_get_delta_addr(&s, &s.header.value) == 8, "header.value");
    dap_assert(s_get_delta_addr(&s, &s.header.ts_expires) == 16, "header.ts_expires");

    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_pay) == 24, "subtype.srv_pay");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_pay.pkey_hash) == 24, "subtype.srv_pay.pkey_hash");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_pay.srv_uid) == 56, "subtype.srv_pay.srv_uid");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_pay.unit) == 64, "subtype.srv_pay.unit");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_pay.unit_price_max_datoshi) == 72, "subtype.srv_pay.unit_price_max_datoshi");

    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_xchange) == 24, "subtype.srv_xchange");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_xchange.srv_uid) == 24, "subtype.srv_xchange.srv_uid");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_xchange.token) == 32, "subtype.srv_xchange.token");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_xchange.net_id) == 42, "subtype.srv_xchange.net_id");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_xchange.value) == 56, "subtype.srv_xchange.value");

    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_stake) == 24, "subtype.srv_stake");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_stake.srv_uid) == 24, "subtype.srv_stake.srv_uid");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_stake.hldr_addr) == 32, "subtype.srv_stake.hldr_addr");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_stake.fee_addr) == 109, "subtype.srv_stake.fee_addr");
    dap_assert(s_get_delta_addr(&s, &s.subtype.srv_stake.fee_value) == 200, "subtype.srv_stake.fee_value");

    dap_assert(s_get_delta_addr(&s, &s.params_size) == 216, "params_size");
    dap_assert(s_get_delta_addr(&s, &s.params) == 220, "params");
    return 0;
}

static int s_chain_tx_out_test()
{
    dap_print_module_name("dap_chain_tx_out_test");
    dap_chain_tx_out_old_t s_old = {0};
    dap_assert(sizeof(s_old) == 93, "old size");
    dap_assert(sizeof(s_old.header) == 16, "old.header size");
    dap_assert(s_get_delta_addr(&s_old, &s_old.header) == 0, "old.header");
    dap_assert(s_get_delta_addr(&s_old, &s_old.header.type) == 0, "old.header.type");
    dap_assert(s_get_delta_addr(&s_old, &s_old.header.value) == 8, "old.header.value");
    dap_assert(s_get_delta_addr(&s_old, &s_old.addr) == 16, "old.header.addr");


    dap_chain_tx_out_t s = {0};
    dap_assert(sizeof(s) == 110, "new size");
    dap_assert(sizeof(s.header) == 33, "new.header size");
    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "new.header");
    dap_assert(s_get_delta_addr(&s, &s.header.type) == 0, "new.header.type");
    dap_assert(s_get_delta_addr(&s, &s.header.value) == 1, "new.header.value");
    dap_assert(s_get_delta_addr(&s, &s.addr) == 33, "new.header.addr");
    return 0;
}

void dap_struct_packing_test_run(void){
    dap_print_module_name("dap_struct_packing");
    s_chain_tx_in_cond_test();
    s_chain_datum_tx_in_ems_test();
    s_chain_tx_in_test();
    s_chain_tx_out_cond_old_test();
    s_chain_tx_out_test();
}


