/*
 * Regression: dap_chain_net_srv_xchange_get_fee() must leave its out-parameters
 * in a defined state even when it reports "no service fee configured".
 *
 * It returned early on the no-fee path without touching a_addr, while its
 * callers use the address unconditionally: dap_chain_net_srv_xchange.c:804
 * declares `dap_chain_addr_t l_service_fee_addr;` (uninitialized) and line 831
 * then reads it -
 *
 *     if (l_service_fee_used && !strcmp(l_out_token, l_service_ticker) &&
 *             !memcmp(&l_out_addr, &l_service_fee_addr, sizeof(l_out_addr)) && ...)
 *
 * - so the comparison ran against stack garbage. The same pattern was already
 * fixed at the other two call sites (they initialize with `= { }`); this test
 * pins the contract in the function itself so a fourth caller cannot inherit it.
 *
 * The observable promise checked here: with no fee registered for the network,
 * the function returns false AND zeroes the address/value it was given (rather
 * than leaving whatever the caller had on its stack). A pre-filled address is
 * used so an untouched buffer is detectable.
 */

#include "dap_common.h"
#include "dap_test.h"
#include "dap_chain_common.h"    // dap_chain_addr_t
#include "dap_chain_net_srv_xchange.h"

#define LOG_TAG "xchange_fee_contract_test"

// A network id that has no fee registered anywhere in this test.
static const dap_chain_net_id_t s_net_id = { .uint64 = 0xFEEDFACE00000001ULL };

static void test_get_fee_zeroes_outputs_without_fee(void)
{
    // Pre-fill with a non-zero pattern: if the no-fee path forgets to write the
    // address, these bytes stay and the assertions below catch it.
    dap_chain_addr_t l_addr;
    memset(&l_addr, 0xA5, sizeof(l_addr));
    uint256_t l_fee;
    memset(&l_fee, 0x5A, sizeof(l_fee));
    uint16_t l_type = 0xBEEF;

    bool l_used = dap_chain_net_srv_xchange_get_fee(s_net_id, &l_fee, &l_addr, &l_type);

    dap_assert(!l_used, "No service fee configured for an unknown net");

    // The address must be a defined "no address" value, not the caller's garbage.
    unsigned char *l_bytes = (unsigned char *)&l_addr;
    bool l_all_zero = true;
    for (size_t i = 0; i < sizeof(l_addr); ++i)
        if (l_bytes[i]) { l_all_zero = false; break; }
    dap_assert(l_all_zero,
               "Out-address is zeroed when there is no service fee (callers read it unconditionally)");

    // Same for the value and the type.
    unsigned char *l_fee_bytes = (unsigned char *)&l_fee;
    bool l_fee_zero = true;
    for (size_t i = 0; i < sizeof(l_fee); ++i)
        if (l_fee_bytes[i]) { l_fee_zero = false; break; }
    dap_assert(l_fee_zero, "Out-value is zeroed when there is no service fee");
    dap_assert(l_type == 0, "Out-type is zeroed when there is no service fee");
}

static void test_get_fee_tolerates_null_outputs(void)
{
    // Callers may pass NULL for the parts they do not need; the no-fee path must
    // not crash on them either.
    bool l_used = dap_chain_net_srv_xchange_get_fee(s_net_id, NULL, NULL, NULL);
    dap_assert(!l_used, "No-fee lookup with NULL out-parameters reports false");
    dap_pass_msg("NULL out-parameters accepted");
}

int main(int argc, char **argv)
{
    dap_common_init(LOG_TAG, NULL);
    UNUSED(argc); UNUSED(argv);

    dap_print_module_name("xchange_fee_contract");
    test_get_fee_zeroes_outputs_without_fee();
    test_get_fee_tolerates_null_outputs();

    dap_assert(1, "xchange fee contract tests passed");
    dap_common_deinit();
    return 0;
}