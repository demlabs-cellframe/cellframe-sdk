#include "dap_struct_packing_tests.h"
#include "dap_math_ops.h"
#include "../include/dap_chain_datum_tx_out.h"
#include "../include/dap_chain_datum_tx_in_cond.h"


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
    s_chain_tx_out_test();

}
