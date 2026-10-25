/*
 * Unit tests for service-order signature verification (policy rule 0xD).
 *
 * Orders are node-local objects (never ledger datums), so their embedded signature
 * is the only thing that binds price/tax/ext to their author. These tests cover the
 * primitive itself: a well-formed order verifies, any tampering with the body or the
 * extension block breaks it, and re-signing restores validity.
 */

#include <stdio.h>
#include <string.h>

#include "dap_common.h"
#include "dap_enc_key.h"
#include "dap_sign.h"
#include "dap_hash.h"
#include "dap_chain_net_srv_order.h"
#include "dap_test.h"

#define LOG_TAG "order_sign_test"

// Build an order body + signature the same way dap_chain_net_srv_order_compose does:
// the producer signs sizeof(order) + ext_size bytes and appends the sign blob.
static dap_chain_net_srv_order_t *s_make_order(dap_enc_key_t *a_key, const void *a_ext, uint32_t a_ext_size)
{
    dap_chain_net_srv_order_t *l_order = a_ext_size
        ? (dap_chain_net_srv_order_t *)DAP_NEW_Z_SIZE(dap_chain_net_srv_order_t,
                sizeof(dap_chain_net_srv_order_t) + a_ext_size)
        : DAP_NEW_Z(dap_chain_net_srv_order_t);
    if (!l_order)
        return NULL;
    if (a_ext_size) {
        memcpy(l_order->ext_n_sign, a_ext, a_ext_size);
        l_order->ext_size = a_ext_size;
    }
    l_order->version = 3;
    l_order->direction = SERV_DIR_SELL;
    l_order->ts_created = 1700000000;
    l_order->price_unit.uint32 = 1;
    l_order->units = 7;
    strncpy(l_order->price_ticker, "CELL", DAP_CHAIN_TICKER_SIZE_MAX - 1);

    size_t l_body_size = sizeof(dap_chain_net_srv_order_t) + l_order->ext_size;
    dap_sign_t *l_sign = dap_sign_create(a_key, l_order, l_body_size);
    if (!l_sign) {
        DAP_DELETE(l_order);
        return NULL;
    }
    size_t l_sign_size = dap_sign_get_size(l_sign);
    dap_chain_net_srv_order_t *l_new = DAP_REALLOC(l_order, l_body_size + l_sign_size);
    if (!l_new) {
        DAP_DELETE(l_sign);
        DAP_DELETE(l_order);
        return NULL;
    }
    l_order = l_new;
    memcpy(l_order->ext_n_sign + l_order->ext_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);
    return l_order;
}

static void test_order_sign_valid(void)
{
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generated");

    dap_chain_net_srv_order_t *l_order = s_make_order(l_key, NULL, 0);
    dap_assert_PIF(l_order != NULL, "Order composed");
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_order) == 1,
                   "A freshly signed order verifies");

    DAP_DELETE(l_order);
    dap_enc_key_delete(l_key);
    dap_pass_msg("test_order_sign_valid");
}

static void test_order_sign_tampered_body(void)
{
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generated");

    dap_chain_net_srv_order_t *l_order = s_make_order(l_key, NULL, 0);
    dap_assert_PIF(l_order != NULL, "Order composed");
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_order) == 1, "Order verifies before tampering");

    // The price is what a consumer bills; changing it must invalidate the signature.
    l_order->units += 1;
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_order) == 0,
                   "Tampered body (units changed) fails verification");

    DAP_DELETE(l_order);
    dap_enc_key_delete(l_key);
    dap_pass_msg("test_order_sign_tampered_body");
}

static void test_order_sign_tampered_ext(void)
{
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generated");

    // Validator orders carry tax/value_max in the extension - the very bytes an
    // attacker would edit to change the fee split they claim.
    uint8_t l_ext[40] = { 0 };
    memset(l_ext, 0x11, sizeof(l_ext));
    dap_chain_net_srv_order_t *l_order = s_make_order(l_key, l_ext, sizeof(l_ext));
    dap_assert_PIF(l_order != NULL, "Order with extension composed");
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_order) == 1,
                   "Order with extension verifies");

    l_order->ext_n_sign[0] ^= 0xFF;
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_order) == 0,
                   "Tampered extension fails verification");

    DAP_DELETE(l_order);
    dap_enc_key_delete(l_key);
    dap_pass_msg("test_order_sign_tampered_ext");
}

static void test_order_sign_foreign_key(void)
{
    dap_enc_key_t *l_author = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_enc_key_t *l_attacker = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_author && l_attacker, "Keys generated");

    // Signature made by the attacker over the same body: it verifies, but not
    // against the author's key - the caller checks identity separately by pkey
    // (e.g. net_srv.c compares hashes). This pins down that verify_sign() reports
    // a cryptographically sound signature, not one that belongs to anyone specific.
    dap_chain_net_srv_order_t *l_order = s_make_order(l_attacker, NULL, 0);
    dap_assert_PIF(l_order != NULL, "Order composed");
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_order) == 1,
                   "Signature by a foreign key still verifies as a signature");
    dap_assert_PIF(dap_chain_net_srv_order_get_sign(l_order) != NULL,
                   "Sign accessor returns the embedded signature");

    DAP_DELETE(l_order);
    dap_enc_key_delete(l_author);
    dap_enc_key_delete(l_attacker);
    dap_pass_msg("test_order_sign_foreign_key");
}

static void test_order_re_sign(void)
{
    dap_enc_key_t *l_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_DILITHIUM, NULL, 0, NULL, 0, 0);
    dap_assert_PIF(l_key != NULL, "Key generated");

    // The update path hands over a body-only buffer (the previous signature was
    // dropped by the realloc): reproduce exactly that shape.
    dap_chain_net_srv_order_t *l_order = s_make_order(l_key, NULL, 0);
    dap_assert_PIF(l_order != NULL, "Order composed");
    size_t l_body_size = sizeof(dap_chain_net_srv_order_t) + l_order->ext_size;
    dap_chain_net_srv_order_t *l_body = DAP_REALLOC(l_order, l_body_size);
    dap_assert_PIF(l_body != NULL, "Buffer trimmed to the body");
    l_body->units += 5;     // the update changed the body

    dap_assert_PIF(dap_chain_net_srv_order_re_sign(&l_body, l_key) == 0, "Re-sign succeeded");
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_body) == 1,
                   "Re-signed order verifies over its new body");
    dap_assert_PIF(l_body->units == 12, "Body change survived the re-sign");
    dap_assert_PIF(dap_chain_net_srv_order_get_size(l_body) == l_body_size + dap_sign_get_size(
                   dap_chain_net_srv_order_get_sign(l_body)), "Size matches body + signature");

    DAP_DELETE(l_body);
    dap_enc_key_delete(l_key);
    dap_pass_msg("test_order_re_sign");
}

static void test_order_sign_null_type(void)
{
    dap_chain_net_srv_order_t *l_order = DAP_NEW_Z(dap_chain_net_srv_order_t);
    dap_assert_PIF(l_order != NULL, "Order allocated");
    l_order->version = 3;
    // An explicitly unsigned order: a zeroed sign header has SIG_TYPE_NULL.
    dap_assert_PIF(dap_chain_net_srv_order_verify_sign(l_order) == 0,
                   "Unsigned order reports 'not verified'");
    DAP_DELETE(l_order);
    dap_pass_msg("test_order_sign_null_type");
}

int main(int argc, char **argv)
{
    UNUSED(argc); UNUSED(argv);
    dap_print_module_name("order_signature_unit");
    if (dap_common_init(LOG_TAG, NULL))
        return 1;

    test_order_sign_valid();
    test_order_sign_tampered_body();
    test_order_sign_tampered_ext();
    test_order_sign_foreign_key();
    test_order_re_sign();
    test_order_sign_null_type();

    dap_print_module_name("order_signature_unit PASS");
    dap_common_deinit();
    return 0;
}