#include "dap_struct_packing_tests.h"
#include "dap_math_ops.h"
#include "dap_chain_datum_tx_out.h"
#include "dap_chain_datum_tx_in_cond.h"
#include "dap_chain_datum_tx_in_ems.h"
#include "dap_chain_datum_tx_in.h"
#include "dap_chain_datum_tx_pkey.h"
#include "dap_chain_datum_tx_sig.h"
#include "dap_chain_datum_tx_tsd.h"
#include <stddef.h>
#include <stdio.h> // Added for printf

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

static int s_chain_tx_out_ext_test()
{
    dap_print_module_name("dap_chain_tx_out_ext_test");
    dap_chain_tx_out_ext_t s = {0};
    dap_assert(sizeof(s) == 120, "size");
    dap_assert(sizeof(s.header) == 33, "header size");
    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "header");
    dap_assert(s_get_delta_addr(&s, &s.header.type) == 0, "header.type");
    dap_assert(s_get_delta_addr(&s, &s.header.value) == 1, "header.value");
    dap_assert(s_get_delta_addr(&s, &s.addr) == 33, "addr");
    dap_assert(s_get_delta_addr(&s, &s.token) == 110, "token");
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

static int s_chain_tx_pkey_test()
{
    dap_print_module_name("dap_chain_tx_pkey_test");
    dap_chain_tx_pkey_t s = {0};
    printf("sizeof(s) = %zu\n", sizeof(s));
    printf("offsetof(header) = %zu\n", offsetof(dap_chain_tx_pkey_t, header));
    printf("offsetof(header.type) = %zu\n", offsetof(dap_chain_tx_pkey_t, header.type));
    printf("offsetof(header.size) = %zu\n", offsetof(dap_chain_tx_pkey_t, header.size));
    printf("offsetof(pkey) = %zu\n", offsetof(dap_chain_tx_pkey_t, pkey));
    dap_assert(sizeof(s) == 9, "size");
    dap_assert(offsetof(dap_chain_tx_pkey_t, header) == 1, "header offset");
    dap_assert(offsetof(dap_chain_tx_pkey_t, header.type) == 1, "header.type offset");
    dap_assert(offsetof(dap_chain_tx_pkey_t, header.size) == 5, "header.size offset");
    dap_assert(offsetof(dap_chain_tx_pkey_t, pkey) == 9, "pkey offset");
    return 0;
}

static int s_chain_tx_sig_test()
{
    dap_print_module_name("dap_chain_tx_sig_test");
    dap_chain_tx_sig_t s = {0};
    dap_assert(sizeof(s) == 8, "size");
    dap_assert(sizeof(s.header) == 8, "header size");
    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "header");
    dap_assert(s_get_delta_addr(&s, &s.header.type) == 0, "header.type");
    dap_assert(s_get_delta_addr(&s, &s.header.sig_size) == 4, "header.sig_size");
    dap_assert(s_get_delta_addr(&s, &s.sig) == 8, "sig");
    return 0;
}

static int s_chain_tx_tsd_test()
{
    dap_print_module_name("dap_chain_tx_sig_test");
    dap_chain_tx_tsd_t s = {0};
    dap_assert(sizeof(s) == 16, "size");
    dap_assert(sizeof(s.header) == 16, "header size");
    dap_assert(s_get_delta_addr(&s, &s.header) == 0, "header");
    dap_assert(s_get_delta_addr(&s, &s.header.type) == 0, "header.type");
    dap_assert(s_get_delta_addr(&s, &s.header.size) == 8, "header.size");
    dap_assert(s_get_delta_addr(&s, &s.tsd) == 16, "tsd");
    return 0;
}

void dap_struct_packing_test_run(void){
    dap_print_module_name("dap_struct_packing");
    s_chain_tx_in_cond_test();
    s_chain_datum_tx_in_ems_test();
    s_chain_tx_in_test();
    s_chain_tx_out_ext_test();
    s_chain_tx_out_test();
    s_chain_tx_pkey_test();
    s_chain_tx_sig_test();
    s_chain_tx_tsd_test();
}
