#include "dap_test.h"
#include "dap_chain_ledger_tests.h"
#include "dap_chain_datum.h"
#include "dap_cert.h"
#include "dap_chain_wallet.h"
#include "dap_math_ops.h"
#include "dap_chain_net.h"

static const uint64_t s_fee = 2;
static const uint64_t s_total_supply = 500;
static const uint64_t s_standard_value_tx = 500;
static const char* s_token_ticker = "TestCoins";

dap_chain_datum_token_t  *dap_ledger_test_create_datum_decl(dap_cert_t *a_cert, size_t *a_token_size,
                                                                  const char *a_token_ticker, uint256_t a_total_supply,
                                                                  byte_t *a_tsd_section, size_t a_size_tsd_section, uint16_t flags) {
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    dap_snprintf(l_token->ticker, sizeof(l_token->ticker), "%s", a_token_ticker);
    l_token->signs_valid = 1;
    l_token->total_supply = a_total_supply;
    l_token->header_native_decl.decimals = 18;
    l_token->signs_total = 0;
    l_token->header_native_decl.flags = flags;
    if (a_tsd_section && a_size_tsd_section != 0) {
        l_token->header_native_decl.tsd_total_size = a_size_tsd_section;
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section);
        memcpy(l_token->data_n_tsd, a_tsd_section, a_size_tsd_section);
    }
    dap_sign_t * l_sign = dap_cert_sign(a_cert,l_token,
                                        sizeof(*l_token) + a_size_tsd_section, 0);
    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section + l_sign_size);
        memcpy(l_token->data_n_tsd + a_size_tsd_section, l_sign, l_sign_size);
        DAP_DELETE(l_sign);
        l_token->signs_total = 1;
        *a_token_size = sizeof(dap_chain_datum_token_t) + l_sign_size + a_size_tsd_section;
        return l_token;
    } else {
        DAP_DEL_Z(l_token);
        DAP_DELETE(l_sign);
        return NULL;
    }
}

dap_chain_datum_tx_t *dap_ledger_test_create_datum_base_tx(
        dap_chain_datum_token_emission_t *a_emi,
        dap_chain_hash_fast_t *l_emi_hash,
        dap_chain_addr_t  a_addr_to,
        dap_cert_t *a_cert) {
	uint256_t l_value_fee = dap_chain_uint256_from(s_fee);
    uint256_t l_value_need = a_emi->hdr.value;
    dap_chain_datum_tx_t *l_tx = DAP_NEW_Z_SIZE(dap_chain_datum_tx_t, sizeof(dap_chain_datum_tx_t));
    l_tx->header.ts_created = time(NULL);
    dap_chain_tx_in_ems_t *l_in_ems = DAP_NEW_Z(dap_chain_tx_in_ems_t);
    l_in_ems->header.type = TX_ITEM_TYPE_IN_EMS;
    l_in_ems->header.token_emission_chain_id.uint64 = 0;
    l_in_ems->header.token_emission_hash = *l_emi_hash;
    strcpy(l_in_ems->header.ticker, a_emi->hdr.ticker);
	SUBTRACT_256_256(l_value_need, l_value_fee, &l_value_need);
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(&a_addr_to, l_value_need);
	dap_chain_tx_out_cond_t *l_tx_out_fee = dap_chain_datum_tx_item_out_cond_create_fee(l_value_fee);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_ems);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);
	dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_tx_out_fee);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key);
    DAP_DEL_Z(l_in_ems);
    DAP_DEL_Z(l_out);
	DAP_DEL_Z(l_tx_out_fee);

    return l_tx;
}

dap_chain_datum_tx_t *dap_ledger_test_create_tx(dap_enc_key_t *a_key_from, dap_chain_hash_fast_t *a_hash_prev,
                                                      dap_chain_addr_t *a_addr_to, uint256_t a_value) {
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(a_hash_prev, 0);
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(a_addr_to, a_value);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from);
    DAP_DEL_Z(l_in);
    DAP_DEL_Z(l_out);
    return l_tx;
}

void dap_ledger_test_double_spending(
        dap_ledger_t *a_ledger, dap_hash_fast_t *a_prev_hash, dap_enc_key_t  *a_from_key, dap_chain_net_id_t a_net_id) {
    dap_print_module_name("dap_ledger_double_spending");
    dap_cert_t *l_first_cert = dap_cert_generate_mem_with_seed("newCert", DAP_ENC_KEY_TYPE_SIG_PICNIC, "FMknbirh8*^#$RYU*H", 18);
    dap_chain_addr_t l_addr_first = {0};
    dap_chain_addr_fill_from_key(&l_addr_first, l_first_cert->enc_key, a_net_id);
    dap_chain_datum_tx_t *l_first_tx = dap_ledger_test_create_tx(a_from_key, a_prev_hash,
                                                                       &l_addr_first, dap_chain_uint256_from(s_standard_value_tx - s_fee));
    dap_assert_PIF(l_first_tx, "Can't creating base transaction.");
    dap_chain_hash_fast_t l_first_tx_hash = {0};
    dap_hash_fast(l_first_tx, dap_chain_datum_tx_get_size(l_first_tx), &l_first_tx_hash);
    dap_assert_PIF(!dap_ledger_tx_add(a_ledger, l_first_tx, &l_first_tx_hash, false), "Can't added first transaction on ledger");
    //uint256_t l_balance = dap_ledger_calc_balance(a_ledger, &l_addr_first, s_token_ticker);
    // Second tx
    dap_chain_datum_tx_t *l_second_tx = dap_ledger_test_create_tx(a_from_key, a_prev_hash,
                                                                       &l_addr_first, dap_chain_uint256_from(s_standard_value_tx - s_fee));
    dap_chain_hash_fast_t l_second_tx_hash = {0};
    dap_hash_fast(l_second_tx, dap_chain_datum_tx_get_size(l_second_tx), &l_second_tx_hash);
    dap_assert_PIF(dap_ledger_tx_add(a_ledger, l_second_tx, &l_second_tx_hash, false), "Added second transaction on ledger");
    dap_pass_msg("The verification test is not able to make two normal transactions per one basic transaction.");
}

void dap_ledger_test_excess_supply(dap_ledger_t *a_ledger, dap_cert_t *a_cert, dap_chain_addr_t *a_addr){
    dap_print_module_name("dap_ledger_test_excess_supply");
    const char *l_token_ticker = "Test2";
    uint256_t l_value_first_emi = dap_chain_uint256_from(s_total_supply / 2);
    uint256_t l_value_second_emi = dap_chain_uint256_from(s_total_supply);
    size_t l_decl_size = 0;
    dap_chain_datum_token_t *l_decl = dap_ledger_test_create_datum_decl(a_cert, &l_decl_size, l_token_ticker,
                                                                              dap_chain_uint256_from(s_total_supply), NULL, 0, DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
    dap_assert_PIF(!dap_ledger_token_add(a_ledger, l_decl, l_decl_size), "Adding token declaration to ledger.");
    dap_chain_datum_token_emission_t *l_femi = dap_chain_datum_emission_create(l_value_first_emi, l_token_ticker, a_addr);
    l_femi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_femi);
    dap_chain_hash_fast_t l_femi_hash = {0};
    dap_hash_fast(l_femi, dap_chain_datum_emission_get_size((byte_t*)l_femi), &l_femi_hash);
    dap_assert_PIF(!dap_ledger_token_emission_add(a_ledger, (byte_t*)l_femi,
                                                        dap_chain_datum_emission_get_size((byte_t*)l_femi),
                                                        &l_femi_hash, false), "Added first emission in ledger");
    //Second emi
    dap_chain_datum_token_emission_t *l_semi = dap_chain_datum_emission_create(l_value_second_emi, l_token_ticker, a_addr);
    l_semi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_semi);
    dap_chain_hash_fast_t l_semi_hash = {0};
    dap_hash_fast(l_semi, dap_chain_datum_emission_get_size((byte_t*)l_semi), &l_semi_hash);
    int res =dap_ledger_token_emission_add(a_ledger, (byte_t*)l_semi,
                                                        dap_chain_datum_emission_get_size((byte_t*)l_semi),
                                                        &l_semi_hash, false);
    if (!res){
        dap_fail("The total supply test failed because the second emission exceeded the total supply.");
    } else {
        dap_pass_msg("The verification of the total supply passed because the second issue in excess of the total "
                     "supply was rejected.");
    }
}

typedef struct addr_key_container{
    dap_chain_addr_t *addr;
    dap_enc_key_t *enc_key;
    char *str;
}addr_key_container_t;

addr_key_container_t *gen_addr(dap_chain_net_id_t a_iddn){
    addr_key_container_t *l_container = DAP_NEW(addr_key_container_t);
    dap_enc_key_t *l_new_key = dap_enc_key_new_generate(DAP_ENC_KEY_TYPE_SIG_PICNIC, NULL, 0, NULL, 0, 0);
    dap_chain_addr_t *l_addr = DAP_NEW(dap_chain_addr_t);
    dap_chain_addr_fill_from_key(l_addr, l_new_key, a_iddn);
    l_container->enc_key = l_new_key;
    l_container->addr = l_addr;
    l_container->str = dap_chain_addr_to_str(l_container->addr);
    return l_container;
}

void dap_ledger_test_write_back_list(dap_ledger_t *a_ledger, dap_cert_t *a_cert, dap_chain_net_id_t a_net_id) {
    dap_print_module_name("dap_ledger_test_write_back_list");
    addr_key_container_t *l_addr_1 = gen_addr(a_net_id);
    addr_key_container_t *l_addr_2 = gen_addr(a_net_id);
    addr_key_container_t *l_addr_3 = gen_addr(a_net_id);
    addr_key_container_t *l_addr_4 = gen_addr(a_net_id);
    //Check white list
    {
        size_t l_decl_size = 0;
        char *l_token_ticker = "TestWL";
        dap_tsd_t *l_tsd_white_addr_emi = dap_tsd_create(
                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD,
//                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD,
                l_addr_4->addr, sizeof(dap_chain_addr_t));
        size_t l_tsd_white_addr_emi_size = dap_tsd_size(l_tsd_white_addr_emi);
        dap_tsd_t *l_tsd_white_addr_tx_received = dap_tsd_create(
                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD,
                l_addr_1->addr, sizeof(dap_chain_addr_t));
        size_t l_tsd_white_addr_tx_received_size = dap_tsd_size(l_tsd_white_addr_tx_received);
        dap_tsd_t *l_tsd_white_addr_tx_send = dap_tsd_create(
                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD,
                l_addr_1->addr, sizeof(dap_chain_addr_t));
        size_t l_tsd_white_addr_tx_send_size = dap_tsd_size(l_tsd_white_addr_tx_send);
//        size_t l_tsd_container_size = l_tsd_white_addr_emi_size +
//                                      l_tsd_white_addr_tx_received_size + l_tsd_white_addr_tx_send_size + l_tsd_size_a;
        size_t l_tsd_container_size = l_tsd_white_addr_emi_size + l_tsd_white_addr_tx_received_size + l_tsd_white_addr_tx_send_size;
        byte_t *l_tsd_container = DAP_NEW_Z_SIZE(byte_t, l_tsd_container_size);
        size_t l_offset = 0;
        memcpy(l_tsd_container, l_tsd_white_addr_emi, l_tsd_white_addr_emi_size);
        l_offset += l_tsd_white_addr_emi_size;
        memcpy(l_tsd_container + l_offset, l_tsd_white_addr_tx_received,
               l_tsd_white_addr_tx_received_size);
        l_offset += l_tsd_white_addr_tx_received_size;
        memcpy(l_tsd_container + l_offset, l_tsd_white_addr_tx_send, l_tsd_white_addr_tx_send_size);
        l_offset += l_tsd_white_addr_tx_send_size;
//        memcpy(l_tsd_container + l_offset, l_tsd_a, l_tsd_size_a);
//        l_offset += l_tsd_size_a;
        if (l_offset == l_tsd_container_size){
            dap_pass_msg("TSD section created");
        }
        uint16_t l_flags_decl = 0;
        l_flags_decl |= DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED;
        l_flags_decl |= DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED;
        dap_chain_datum_token_t *l_decl = dap_ledger_test_create_datum_decl(a_cert, &l_decl_size,
                                                                                  l_token_ticker,
                                                                                  dap_chain_uint256_from(
                                                                                          s_total_supply),
                                                                                  l_tsd_container,
                                                                                  l_tsd_container_size,
                                                                                  //DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
                                                                                  l_flags_decl);

        dap_assert_PIF(!dap_ledger_token_add(a_ledger, l_decl, l_decl_size),
                "Can't added datum in ledger");
        //Check emission in not a white list
        dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_create(
                dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_3->addr);
        l_emi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi);
        dap_chain_hash_fast_t l_emi_hash = {0};
        dap_hash_fast(l_emi, dap_chain_datum_emission_get_size((uint8_t*)l_emi), &l_emi_hash);
        dap_assert(dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi, dap_chain_datum_emission_get_size((byte_t*)l_emi),
                                                            &l_emi_hash, false) != 0,
                       "Checking the impossibility of emission to an address not from the white list.");
        //Emission in white list
        dap_chain_datum_token_emission_t *l_emi_whi = dap_chain_datum_emission_create(
            dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_1->addr);
        l_emi_whi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi_whi);
        dap_chain_hash_fast_t l_emi_whi_hash = {0};
        dap_hash_fast(l_emi_whi, dap_chain_datum_emission_get_size((uint8_t*)l_emi_whi), &l_emi_whi_hash);
        dap_assert_PIF(!dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi_whi, dap_chain_datum_emission_get_size((byte_t*)l_emi_whi),
                                            &l_emi_whi_hash, false),
                       "Can't add emission in white address");
        dap_chain_datum_tx_t *l_btx_addr1 = dap_ledger_test_create_datum_base_tx(l_emi_whi, &l_emi_whi_hash,
                                                                                      *l_addr_1->addr, a_cert);
        dap_hash_fast_t l_btx_addr1_hash = {0};
        dap_hash_fast(l_btx_addr1, dap_chain_datum_tx_get_size(l_btx_addr1), &l_btx_addr1_hash);
        int l_ledger_add_code = dap_ledger_tx_add(a_ledger, l_btx_addr1, &l_btx_addr1_hash, false);
        char *l_ledger_tx_add_str = dap_strdup_printf("Can't add base tx in white address. Code: %d", l_ledger_add_code);
        dap_assert_PIF(!l_ledger_add_code, l_ledger_tx_add_str);
        DAP_DELETE(l_ledger_tx_add_str);
        dap_hash_fast_t l_tx_addr4_hash = {0};
        dap_chain_datum_tx_t *l_tx_to_addr4 = dap_ledger_test_create_tx(l_addr_1->enc_key, &l_btx_addr1_hash,
                                                                              l_addr_4->addr, dap_chain_uint256_from(s_total_supply-s_fee));
        dap_hash_fast(l_tx_to_addr4, dap_chain_datum_tx_get_size(l_tx_to_addr4), &l_tx_addr4_hash);
        dap_assert_PIF(!dap_ledger_tx_add(a_ledger, l_tx_to_addr4, &l_tx_addr4_hash, false),
                       "Can't add transaction to address from white list in ledger");
        dap_chain_datum_tx_t *l_tx_to_addr3 = dap_ledger_test_create_tx(l_addr_4->enc_key, &l_tx_addr4_hash,
                                                                              l_addr_3->addr, dap_chain_uint256_from(s_total_supply-s_fee));
        dap_hash_fast_t l_tx_addr3_hash = {0};
        dap_hash_fast(l_tx_to_addr3, dap_chain_datum_tx_get_size(l_tx_to_addr3), &l_tx_addr3_hash);
        int res_add_tx = dap_ledger_tx_add(a_ledger, l_tx_to_addr3, &l_tx_addr3_hash, false);
        if (!res_add_tx) {
            dap_fail("It was possible to carry out a transaction to a forbidden address");
        } else {
            dap_pass_msg("Transaction to banned address failed.");
        }
    }
    dap_pass_msg("Test white list.");
    // Update TSD section
//    {
//        size_t l_offset = 0;
//        uint256_t l_total_supply = dap_chain_uint256_from(s_total_supply * 2);
//        dap_tsd_t *l_tsd_update_total_size = dap_tsd_create(
//                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY, &l_total_supply, sizeof(uint256_t));
//        l_offset += dap_tsd_size(l_tsd_update_total_size);
//        uint16_t l_flags_update = 0;
//        l_flags_update |= DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED;
//        l_flags_update |= DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED;
//        dap_tsd_t *l_tsd_dis_flags = dap_tsd_create(
//                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS, &l_flags_update, sizeof(uint16_t));
//        l_offset += dap_tsd_size(l_tsd_dis_flags);
//        dap_chain_datum_token_t  *l_datum_token_update = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, sizeof(dap_chain_datum_token_t)+l_offset);
//        l_datum_token_update->type = DAP_CHAIN_DATUM_TOKEN_TYPE_NATIVE_UPDATE;
//        char *l_token_ticker = "TestWL";
//        dap_snprintf(l_datum_token_update->ticker, sizeof(l_datum_token_update->ticker), "%s", l_token_ticker);
//        l_datum_token_update->header_native_update.tsd_total_size = l_offset;
//        l_datum_token_update->signs_total = 1;
//        l_offset = 0;
//        memcpy(l_datum_token_update->data_n_tsd, l_tsd_update_total_size, dap_tsd_size(l_tsd_update_total_size));
//        l_offset += dap_tsd_size(l_tsd_update_total_size);
//        memcpy(l_datum_token_update->data_n_tsd + l_offset, l_tsd_dis_flags, dap_tsd_size(l_tsd_dis_flags));
//        l_offset += dap_tsd_size(l_tsd_dis_flags);
//        dap_sign_t * l_sign = dap_cert_sign(a_cert, l_datum_token_update,
//                                           sizeof(*l_datum_token_update) - sizeof(uint16_t), 0);
//        if (l_sign) {
//            size_t l_sign_size = dap_sign_get_size(l_sign);
//            l_datum_token_update = DAP_REALLOC(l_datum_token_update, sizeof(dap_chain_datum_token_t) + l_offset + l_sign_size);
//            memcpy(l_datum_token_update->data_n_tsd + l_offset, l_sign, l_sign_size);
//            DAP_DELETE(l_sign);
//            size_t l_token_update_size = sizeof(dap_chain_datum_token_t) + l_sign_size + l_offset;
//            dap_assert(!dap_ledger_token_add(a_ledger, l_datum_token_update, l_token_update_size),
//                           "Added token update in ledger.");
//        } else {
//            dap_fail("Can't creating sign for token update");
//        }
//    }
    //Check black list
    {
        uint16_t l_flags_decl = 0;
        dap_tsd_t *l_tsd_blocked_send = dap_tsd_create(
                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD,
                l_addr_1->addr, sizeof(dap_chain_addr_t));
        size_t l_tsd_blocked_send_size = dap_tsd_size(l_tsd_blocked_send);
        dap_tsd_t *l_tsd_blocked_received = dap_tsd_create(
                DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD,
                l_addr_1->addr, sizeof(dap_chain_addr_t));
        size_t l_tsd_blocked_received_size = dap_tsd_size(l_tsd_blocked_received);
        size_t l_tsd_container_size = l_tsd_blocked_send_size + l_tsd_blocked_received_size;
        byte_t *l_tsd_container = DAP_NEW_Z_SIZE(byte_t , l_tsd_container_size);
        size_t l_offset = 0;
        memcpy(l_tsd_container, l_tsd_blocked_send, l_tsd_blocked_send_size);
        l_offset += l_tsd_blocked_send_size;
        memcpy(l_tsd_container + l_offset, l_tsd_blocked_received, l_tsd_blocked_received_size);
        l_flags_decl |= DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED;
        l_flags_decl |= DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED;
        const char *l_token_ticker = "TestBL";
        size_t l_decl_size = 0;
        dap_chain_datum_token_t *l_decl = dap_ledger_test_create_datum_decl(a_cert, &l_decl_size,
                                                                                  l_token_ticker,
                                                                                  dap_chain_uint256_from(
                                                                                          s_total_supply),
                                                                                  l_tsd_container,
                                                                                  l_tsd_container_size,
                //DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
                                                                                  l_flags_decl);

        dap_assert_PIF(!dap_ledger_token_add(a_ledger, l_decl, l_decl_size),
                       "Can't added datum in ledger");
        //Check emission at addr in block list
        dap_chain_datum_token_emission_t *l_emi_block = dap_chain_datum_emission_create(
                dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_1->addr);
        l_emi_block = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi_block);
        dap_chain_hash_fast_t l_emi_block_hash = {0};
        dap_hash_fast(l_emi_block, dap_chain_datum_emission_get_size((uint8_t*)l_emi_block), &l_emi_block_hash);
        dap_assert(dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi_block, dap_chain_datum_emission_get_size((byte_t*)l_emi_block),
                                                            &l_emi_block_hash, false),
                       "Test for emission rejection to an address from the prohibited list.");
        //Check emission at addr
        dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_create(
                dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_2->addr);
        l_emi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi);
        dap_chain_hash_fast_t l_emi_hash = {0};
        dap_hash_fast(l_emi, dap_chain_datum_emission_get_size((uint8_t*)l_emi), &l_emi_hash);
        dap_assert(!dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi, dap_chain_datum_emission_get_size((byte_t*)l_emi),
                                                           &l_emi_hash, false),
                       "Emission test for a non-blacklisted address.");
        dap_chain_datum_tx_t *l_btx_addr2 = dap_ledger_test_create_datum_base_tx(l_emi, &l_emi_hash,
                                                                                       *l_addr_2->addr, a_cert);
        dap_hash_fast_t l_btx_addr2_hash = {0};
        dap_hash_fast(l_btx_addr2, dap_chain_datum_tx_get_size(l_btx_addr2), &l_btx_addr2_hash);
        dap_assert_PIF(!dap_ledger_tx_add(a_ledger, l_btx_addr2, &l_btx_addr2_hash, false),
                       "Can't add base tx in white address");
        //Check tx in addr from block list
        dap_chain_datum_tx_t *l_tx_to_addr1 = dap_ledger_test_create_tx(l_addr_4->enc_key, &l_btx_addr2_hash,
                                                                              l_addr_1->addr, dap_chain_uint256_from(s_total_supply));
        dap_hash_fast_t l_tx_addr1_hash = {0};
        dap_hash_fast(l_tx_to_addr1, dap_chain_datum_tx_get_size(l_tx_to_addr1), &l_tx_addr1_hash);
        dap_assert(dap_ledger_tx_add(a_ledger, l_tx_to_addr1, &l_tx_addr1_hash, false), "Transfer test to a forbidden address.");
        //Check tx in addr from list
        dap_chain_datum_tx_t *l_tx_to_addr3 = dap_ledger_test_create_tx(l_addr_4->enc_key, &l_tx_addr1_hash,
                                                                              l_addr_3->addr, dap_chain_uint256_from(s_total_supply));
        dap_hash_fast_t l_tx_addr3_hash = {0};
        dap_hash_fast(l_tx_to_addr3, dap_chain_datum_tx_get_size(l_tx_to_addr3), &l_tx_addr3_hash);
        dap_assert(dap_ledger_tx_add(a_ledger, l_tx_to_addr3, &l_tx_addr3_hash, false), "Transfer test to a not forbidden address.");
    }
}

void dap_ledger_test_run(void){
    dap_chain_net_id_t l_iddn = {0};
    dap_sscanf("0xFA0", "0x%16"DAP_UINT64_FORMAT_x, &l_iddn.uint64);
    dap_print_module_name("dap_ledger");
    uint16_t l_flags = 0;
    l_flags |= DAP_LEDGER_CHECK_TOKEN_EMISSION;
    dap_chain_net_t *l_net = DAP_NEW_Z(dap_chain_net_t);
    l_net->pub.id = l_iddn;
    l_net->pub.native_ticker = s_token_ticker;
    l_net->pub.name = "Snet";
    dap_ledger_t *l_ledger = dap_ledger_create(l_net, l_flags);
    char *l_seed_ph = "H58i9GJKbn91238937^#$t6cjdf";
    size_t l_seed_ph_size = strlen(l_seed_ph);
    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("testCert", DAP_ENC_KEY_TYPE_SIG_PICNIC, l_seed_ph, l_seed_ph_size);
    size_t l_token_decl_size = 0;
    dap_chain_datum_token_t *l_token_decl = dap_ledger_test_create_datum_decl(l_cert,
                                                                                    &l_token_decl_size, s_token_ticker,
                                                                                    dap_chain_uint256_from(s_total_supply), NULL, 0, DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
    dap_assert_PIF(l_token_decl || l_token_decl_size == 0, "Generate token declaration.");
    int l_check_added_decl_token = 0;
    l_check_added_decl_token = dap_ledger_token_decl_add_check(l_ledger, l_token_decl, l_token_decl_size);
    dap_assert_PIF(l_check_added_decl_token == 0, "Checking whether it is possible to add a token declaration to ledger.");
    dap_assert_PIF(!dap_ledger_token_add(l_ledger, l_token_decl, l_token_decl_size), "Adding token declaration to ledger.");
	
    // Create emission
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, l_cert->enc_key, l_iddn);
    dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_create(dap_chain_uint256_from(s_total_supply), s_token_ticker, &l_addr);
    dap_chain_datum_token_emission_t *l_emi_sign = dap_chain_datum_emission_add_sign(l_cert->enc_key, l_emi);
    size_t l_emi_size = dap_chain_datum_emission_get_size((byte_t*)l_emi_sign);
    dap_chain_hash_fast_t l_emi_hash = {0};
    dap_hash_fast(l_emi, l_emi_size, &l_emi_hash);
    int l_emi_check = dap_ledger_token_emission_add_check(l_ledger, (byte_t*)l_emi_sign, l_emi_size, &l_emi_hash);
    dap_assert_PIF(l_emi_check == 0, "check emission for add in ledger");
    dap_assert_PIF(!dap_ledger_token_emission_add(l_ledger, (byte_t*)l_emi_sign, l_emi_size, &l_emi_hash, false), "Added emission in ledger");
    //first base tx
    dap_chain_datum_tx_t *l_base_tx = dap_ledger_test_create_datum_base_tx(l_emi_sign, &l_emi_hash, l_addr, l_cert);
    size_t l_base_tx_size = dap_chain_datum_tx_get_size(l_base_tx);
    dap_hash_fast_t l_hash_btx = {0};
    dap_hash_fast(l_base_tx, l_base_tx_size, &l_hash_btx);
    dap_assert_PIF(!dap_ledger_tx_add_check(l_ledger, l_base_tx, l_base_tx_size, &l_hash_btx), "Check can added base tx in ledger");
    dap_assert_PIF(!dap_ledger_tx_add(l_ledger, l_base_tx, &l_hash_btx, false), "Added base tx in ledger.");
    uint256_t l_balance_example = dap_chain_uint256_from(s_standard_value_tx);
    uint256_t l_balance = dap_ledger_calc_balance(l_ledger, &l_addr, s_token_ticker);
	uint256_t l_fee = dap_chain_uint256_from(s_fee);
	SUM_256_256(l_balance,l_fee,&l_balance);
    dap_assert_PIF(!compare256(l_balance, l_balance_example), "Checking the availability of the necessary balance "
                                                             "on the wallet after the first transaction.");
    dap_pass_msg("Validation of the declaration of the tocen, creation of an emission and a basic transaction using this in the ledger.");
    //second base tx
    dap_chain_datum_tx_t  *l_base_tx_second = dap_ledger_test_create_datum_base_tx(l_emi_sign, &l_emi_hash, l_addr, l_cert);
    size_t l_base_tx_size2 = dap_chain_datum_tx_get_size(l_base_tx_second);
    dap_hash_fast_t l_hash_btx_second = {0};
    dap_hash_fast(l_base_tx_second, l_base_tx_size2, &l_hash_btx_second);
    if (dap_ledger_tx_add_check(l_ledger, l_base_tx_second, l_base_tx_size2, &l_hash_btx_second)) {
        dap_pass_msg("Checking can added second base tx in ledger");
    }
    if (dap_ledger_tx_add(l_ledger, l_base_tx_second, &l_hash_btx_second, false)){
        dap_pass_msg("Checking for a failure to add a second base transaction for the same issue to the ledger.");
    } else {
        dap_fail("Checking for a failure to add a second base transaction for the same issue to the ledger.");
    }	
    dap_ledger_test_double_spending(l_ledger, &l_hash_btx, l_cert->enc_key, l_iddn);
    dap_ledger_test_excess_supply(l_ledger, l_cert, &l_addr);
    dap_ledger_test_write_back_list(l_ledger, l_cert, l_iddn);
	
}
