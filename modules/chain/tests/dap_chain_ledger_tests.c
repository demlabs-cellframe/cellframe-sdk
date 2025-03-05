#include "dap_test.h"
#include "dap_chain_ledger_tests.h"
#include "dap_chain_datum.h"
#include "dap_cert.h"
#include "dap_chain_wallet.h"
#include "dap_math_ops.h"
#include "dap_config.h"
#include "dap_chain.h"
#include "dap_chain_net.h"
#include "dap_chain_common.h"
#include "dap_chain_net_srv_vpn.h"
#include "dap_chain_net_srv_stake_lock.h"
#include "dap_chain_net_srv_stake_pos_delegate.h"
#include "dap_chain_net_decree.h"
#include "dap_chain_block.h"
#include "dap_chain_cs_blocks.h"
#include "dap_chain_cs_esbocs.h"
#include "dap_chain_cs.h"
#include "dap_chain_cs_dag_poa.h"

static const uint64_t s_fee = 2;
static const uint64_t s_total_supply = 500;
static const uint64_t s_standard_value_tx = 500;
static const char* s_token_ticker = "TestCoin";
static const char* s_delegated_token_ticker = "mTestCoin";

dap_chain_datum_token_t *dap_ledger_test_create_datum_update(dap_cert_t *a_cert, size_t *a_token_size,
                                                                  const char *a_token_ticker, byte_t *a_tsd_section, size_t a_size_tsd_section){
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    snprintf(l_token->ticker, sizeof(l_token->ticker), "%s", a_token_ticker);
    l_token->signs_valid = 0;
    l_token->total_supply = uint256_0;
    l_token->header_native_decl.decimals = 0;
    l_token->signs_total = 0;
    l_token->header_native_decl.flags = 0;
    if (a_tsd_section && a_size_tsd_section != 0) {
        l_token->header_native_decl.tsd_total_size = a_size_tsd_section;
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section);
        memcpy(l_token->tsd_n_signs, a_tsd_section, a_size_tsd_section);
    }
    dap_sign_t * l_sign = dap_cert_sign(a_cert, l_token, sizeof(*l_token) + a_size_tsd_section);
    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section + l_sign_size);
        memcpy(l_token->tsd_n_signs + a_size_tsd_section, l_sign, l_sign_size);
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

dap_chain_datum_token_t  *dap_ledger_test_create_datum_decl(dap_cert_t *a_cert, size_t *a_token_size,
                                                                  const char *a_token_ticker, uint256_t a_total_supply,
                                                                  byte_t *a_tsd_section, size_t a_size_tsd_section, uint16_t flags) {
    dap_chain_datum_token_t *l_token = DAP_NEW_Z(dap_chain_datum_token_t);
    l_token->version = 2;
    l_token->type = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL;
    l_token->subtype = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE;
    snprintf(l_token->ticker, sizeof(l_token->ticker), "%s", a_token_ticker);
    l_token->signs_valid = 1;
    l_token->total_supply = a_total_supply;
    l_token->header_native_decl.decimals = 18;
    l_token->signs_total = 0;
    l_token->header_native_decl.flags = flags;
    if (a_tsd_section && a_size_tsd_section != 0) {
        l_token->header_native_decl.tsd_total_size = a_size_tsd_section;
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section);
        memcpy(l_token->tsd_n_signs, a_tsd_section, a_size_tsd_section);
    }
    dap_sign_t * l_sign = dap_cert_sign(a_cert, l_token, sizeof(*l_token) + a_size_tsd_section);
    if (l_sign) {
        size_t l_sign_size = dap_sign_get_size(l_sign);
        l_token = DAP_REALLOC(l_token, sizeof(dap_chain_datum_token_t) + a_size_tsd_section + l_sign_size);
        memcpy(l_token->tsd_n_signs + a_size_tsd_section, l_sign, l_sign_size);
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
    dap_chain_tx_in_ems_t l_in_ems = { .header.type = TX_ITEM_TYPE_IN_EMS, .header.token_emission_chain_id.uint64 = 0, .header.token_emission_hash = *l_emi_hash};
    strcpy(l_in_ems.header.ticker, a_emi->hdr.ticker);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) &l_in_ems);
    if ( !strcmp(l_in_ems.header.ticker, s_token_ticker) ) {
        SUBTRACT_256_256(l_value_need, l_value_fee, &l_value_need);
        dap_chain_datum_tx_add_out_item(&l_tx, &a_addr_to, l_value_need);
        dap_chain_datum_tx_add_fee_item(&l_tx, l_value_fee);
    } else {
        dap_chain_datum_tx_add_out_ext_item(&l_tx, &a_addr_to, l_value_need, l_in_ems.header.ticker);
    }
    dap_chain_datum_tx_add_sign_item(&l_tx, a_cert->enc_key);
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

dap_chain_datum_tx_t *dap_ledger_test_create_tx_full(dap_enc_key_t *a_key_from, dap_chain_hash_fast_t *a_hash_prev,
                                                      dap_chain_addr_t *a_addr_to, uint256_t a_value, dap_ledger_t *a_ledger) {

    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, a_key_from, a_ledger->net->pub.id);
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, a_hash_prev);
    int l_out_idx = 0;
    dap_chain_tx_out_t *l_tx_prev_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(l_tx_prev, &l_out_idx, NULL, TX_ITEM_TYPE_OUT, NULL);
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(a_hash_prev, 0);
    dap_chain_tx_out_t *l_out = dap_chain_datum_tx_item_out_create(a_addr_to, a_value);
    uint256_t l_change = {};
    SUBTRACT_256_256(l_tx_prev_out->header.value, a_value, &l_change);
    dap_chain_tx_out_t *l_out_change = dap_chain_datum_tx_item_out_create(&l_addr, l_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from);
    DAP_DEL_Z(l_in);
    DAP_DEL_Z(l_out);
    return l_tx;
}

dap_chain_datum_tx_t *dap_ledger_test_create_tx_cond(dap_enc_key_t *a_key_from, dap_chain_hash_fast_t *a_hash_prev,
                                                      dap_chain_addr_t *a_addr_to, uint256_t a_value, dap_ledger_t *a_ledger) {
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, a_key_from, a_ledger->net->pub.id);
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, a_hash_prev);
    int l_out_idx = 0;
    dap_chain_tx_out_t *l_tx_prev_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(l_tx_prev, &l_out_idx, NULL, TX_ITEM_TYPE_OUT, NULL);
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(a_hash_prev, 0);
    dap_chain_net_srv_uid_t l_srv_uid = {.uint64 = 1};
    dap_chain_net_srv_price_unit_uid_t l_uint_type = {.enm = SERV_UNIT_SEC};
    dap_pkey_t *l_pkey = dap_pkey_from_enc_key(a_key_from);
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_pay(l_pkey, l_srv_uid, a_value, uint256_0, l_uint_type, NULL, 0);
    uint256_t l_change = {};
    SUBTRACT_256_256(l_tx_prev_out->header.value, a_value, &l_change);
    dap_chain_tx_out_t *l_out_change = dap_chain_datum_tx_item_out_create(&l_addr, l_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_cond);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from);
    DAP_DEL_Z(l_in);
    DAP_DEL_Z(l_out_cond);
    DAP_DEL_Z(l_out_change);
    return l_tx;
}

dap_chain_datum_tx_t *dap_ledger_test_create_spend_tx_cond(dap_enc_key_t *a_key_from, dap_chain_hash_fast_t *a_hash_prev,
                                                      dap_enc_key_t *a_key_to, uint256_t a_value, dap_ledger_t *a_ledger) {
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, a_key_from, a_ledger->net->pub.id);
    // get previous transaction
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, a_hash_prev);
     // get previous cond out
    int l_out_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_prev_out = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_item_get(l_tx_prev, &l_out_idx, NULL, TX_ITEM_TYPE_OUT_COND, NULL);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_cond_t *l_in_cond = dap_chain_datum_tx_item_in_cond_create(a_hash_prev, 1, 0);

    // create conditional output
    dap_chain_net_srv_uid_t l_srv_uid = {.uint64 = 1};
    dap_chain_net_srv_price_unit_uid_t l_unit_type = {.enm = SERV_UNIT_SEC};
    dap_pkey_t *l_pkey = dap_pkey_from_enc_key(a_key_from);
    uint256_t l_cond_change = {};
    SUBTRACT_256_256(l_tx_prev_out->header.value, a_value, &l_cond_change);
    dap_chain_tx_out_cond_t *l_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_pay(l_pkey, l_tx_prev_out->header.srv_uid, l_cond_change, uint256_0, l_tx_prev_out->subtype.srv_pay.unit, NULL, 0);

    // create receipt
    dap_chain_datum_tx_receipt_t * l_receipt = dap_chain_datum_tx_receipt_create(l_srv_uid, l_unit_type, 1, a_value, NULL, 0);
    // Sign with our wallet
    l_receipt = dap_chain_datum_tx_receipt_sign_add(l_receipt, a_key_to);
    l_receipt = dap_chain_datum_tx_receipt_sign_add(l_receipt, a_key_from);
    
    
    // add all items to tx
    dap_chain_addr_t l_addr_to = {0};
    dap_chain_addr_fill_from_key(&l_addr_to, a_key_to, a_ledger->net->pub.id);
    dap_chain_tx_out_t *l_out_change = dap_chain_datum_tx_item_out_create(&l_addr_to, a_value);
    dap_chain_datum_tx_add_item(&l_tx, (byte_t*)l_receipt);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_cond);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_cond);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_to);
    DAP_DEL_Z(l_in_cond);
    DAP_DEL_Z(l_out_cond);
    DAP_DEL_Z(l_receipt);
    DAP_DEL_Z(l_out_change);
    return l_tx;
}

dap_chain_datum_tx_t *dap_ledger_test_create_return_from_tx_cond(dap_chain_hash_fast_t *a_hash_prev,
                                                      dap_enc_key_t *a_key_to, dap_ledger_t *a_ledger) {
    // get previous transaction
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, a_hash_prev);
     // get previous cond out
    int l_out_idx = 1;
    dap_chain_tx_out_cond_t *l_tx_prev_out = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_item_get(l_tx_prev, &l_out_idx, NULL, TX_ITEM_TYPE_OUT_COND, NULL);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_cond_t *l_in_cond = dap_chain_datum_tx_item_in_cond_create(a_hash_prev, 1, 0);

    // add all items to tx
    dap_chain_addr_t l_addr_to = {0};
    dap_chain_addr_fill_from_key(&l_addr_to, a_key_to, a_ledger->net->pub.id);
    dap_chain_tx_out_t *l_out_change = dap_chain_datum_tx_item_out_create(&l_addr_to, l_tx_prev_out->header.value);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_cond);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_change);
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_to);
    DAP_DEL_Z(l_in_cond);
    DAP_DEL_Z(l_out_change);
    return l_tx;
}

dap_chain_datum_tx_t *dap_ledger_test_create_stake_tx_cond(dap_enc_key_t *a_key_from, dap_chain_hash_fast_t *a_hash_prev, uint256_t a_value, dap_ledger_t *a_ledger) {
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    // get previous transaction
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, a_hash_prev);
     // get previous cond out
    int l_out_idx = 0;
    dap_chain_tx_out_t *l_tx_prev_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(l_tx_prev, &l_out_idx, NULL, TX_ITEM_TYPE_OUT, NULL);
    
    dap_chain_addr_t l_addr_to = {0};
    dap_chain_addr_fill_from_key(&l_addr_to, a_key_from, a_ledger->net->pub.id);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(a_hash_prev, 0);

    dap_chain_tx_in_ems_t *l_in_ems = DAP_NEW_Z(dap_chain_tx_in_ems_t);
    l_in_ems->header.type = TX_ITEM_TYPE_IN_EMS;
    l_in_ems->header.token_emission_chain_id.uint64 = 0;
    memset(&l_in_ems->header.token_emission_hash, 0, sizeof(l_in_ems->header.token_emission_hash));
    strcpy(l_in_ems->header.ticker, s_delegated_token_ticker);

    dap_time_t a_time_staking = 1;
    dap_chain_tx_out_cond_t* l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake_lock(
                                                l_uid, a_value, a_time_staking, uint256_0);

    // add all items to tx
    uint256_t value_change = {};
    SUBTRACT_256_256(l_tx_prev_out->header.value, a_value, &value_change);
    dap_chain_tx_out_ext_t *l_out_change = dap_chain_datum_tx_item_out_ext_create(&l_addr_to, value_change, s_token_ticker);
    uint256_t a_delegated_value = {};
    MULT_256_COIN(a_value, dap_chain_coins_to_balance("0.1"), &a_delegated_value);
    dap_chain_tx_out_ext_t *l_out_delegated = dap_chain_datum_tx_item_out_ext_create(&l_addr_to, a_delegated_value, s_delegated_token_ticker);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_ems);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_tx_out_cond);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_delegated);   
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from);
    DAP_DEL_Z(l_in);
    DAP_DEL_Z(l_in_ems);
    DAP_DEL_Z(l_out_change);
    DAP_DEL_Z(l_out_delegated);
    DAP_DEL_Z(l_tx_out_cond);

    return l_tx;
}

dap_chain_datum_tx_t *dap_ledger_test_create_unstake_tx_cond(dap_enc_key_t *a_key_from, dap_chain_hash_fast_t *a_hash_prev, uint256_t a_value, dap_ledger_t *a_ledger) {
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    // get previous transaction
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, a_hash_prev);
     // get previous cond out
    int l_out_idx = 0;
    dap_chain_tx_out_cond_t *l_tx_prev_out_cond = (dap_chain_tx_out_cond_t *)dap_chain_datum_tx_out_cond_get(l_tx_prev, 
                                                                            DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK, &l_out_idx);
    
    if(!l_tx_prev_out_cond || l_tx_prev_out_cond->header.subtype != DAP_CHAIN_TX_OUT_COND_SUBTYPE_SRV_STAKE_LOCK)
        return NULL;

    l_out_idx = 4;
    dap_chain_tx_out_ext_t *l_tx_prev_out_ext = (dap_chain_tx_out_ext_t *)dap_chain_datum_tx_item_get(l_tx_prev, &l_out_idx, NULL, TX_ITEM_TYPE_OUT_EXT, NULL);

    dap_chain_addr_t l_addr_to = {0};
    dap_chain_addr_fill_from_key(&l_addr_to, a_key_from, a_ledger->net->pub.id);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_t *l_in_ext = dap_chain_datum_tx_item_in_create(a_hash_prev, 2);

    dap_chain_tx_in_cond_t *l_in_cond = dap_chain_datum_tx_item_in_cond_create(a_hash_prev, 0, 0);
    dap_chain_tx_out_ext_t *l_out_change = dap_chain_datum_tx_item_out_ext_create(&l_addr_to, l_tx_prev_out_cond->header.value, s_token_ticker);
    dap_chain_addr_t l_addr_burning = {0};
    dap_chain_tx_out_ext_t *l_out_burn = dap_chain_datum_tx_item_out_ext_create(&l_addr_burning, l_tx_prev_out_ext->header.value, s_delegated_token_ticker);


    // add all items to tx
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_ext);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_cond);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_burn);   
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from);
    
    DAP_DEL_Z(l_in_ext);
    DAP_DEL_Z(l_out_change);
    DAP_DEL_Z(l_in_cond);
    DAP_DEL_Z(l_out_burn);

    return l_tx;
}


int dap_ledger_test_create_reward_decree(dap_chain_t *a_chain, dap_chain_net_id_t a_net_id, uint256_t a_value, dap_cert_t *a_cert)
{
    // Create decree
    size_t l_tsd_total_size = sizeof(dap_tsd_t) + sizeof(uint256_t);
    size_t l_decree_size = sizeof(dap_chain_datum_decree_t) + l_tsd_total_size;
    dap_chain_datum_decree_t *l_decree = DAP_NEW_Z_SIZE(dap_chain_datum_decree_t, l_decree_size);
    if (!l_decree) {
        return -1;
    }
    // Fill the header
    l_decree->decree_version = DAP_CHAIN_DATUM_DECREE_VERSION;
    l_decree->header.ts_created = dap_time_now();
    l_decree->header.type = DAP_CHAIN_DATUM_DECREE_TYPE_COMMON;
    l_decree->header.common_decree_params.net_id = a_net_id;
    l_decree->header.common_decree_params.chain_id = a_chain->id;
    l_decree->header.common_decree_params.cell_id = (dap_chain_cell_id_t){.uint64 = 0};
    l_decree->header.sub_type = DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD;
    l_decree->header.data_size = l_tsd_total_size;
    // Fill a TSD section
    dap_tsd_t *l_tsd = (dap_tsd_t *)l_decree->data_n_signs;
    l_tsd->type = DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE;
    l_tsd->size = sizeof(uint256_t);
    *(uint256_t*)(l_tsd->data) = a_value;
    // Sign it
    dap_sign_t *l_sign = dap_cert_sign(a_cert, l_decree, l_decree_size);
    if (!l_sign) {
        DAP_DELETE(l_decree);
        return -2;
    }
    size_t l_sign_size = dap_sign_get_size(l_sign);
    l_decree_size += l_sign_size;
    l_decree->header.signs_size = l_sign_size;
    void *l_decree_rl = DAP_REALLOC(l_decree, l_decree_size);
    if (!l_decree_rl) {
        DAP_DELETE(l_decree);
        return -3;
    } else
        l_decree = l_decree_rl;
    memcpy(l_decree->data_n_signs + l_tsd_total_size, l_sign, l_sign_size);
    DAP_DELETE(l_sign);

    // dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_DECREE, l_decree, l_decree_size);

    dap_hash_fast_t l_decree_hash = {};
    dap_hash_fast(l_decree, l_decree_size, &l_decree_hash);
    // a_chain->callback_atom_add();
    dap_assert_PIF(dap_chain_net_decree_apply(&l_decree_hash, l_decree, a_chain, false)==0, "Decree applying:");
    return 0;
}

/* int dap_ledger_test_create_reward_tx(dap_chain_t *a_chain, dap_enc_key_t *a_key_to, int block_num, dap_hash_fast_t a_block_hash, uint256_t a_value, dap_ledger_t *a_ledger)
{

    dap_chain_t *l_chain = a_chain;
    //add tx
    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_pkey_t *l_sign_pkey = dap_pkey_from_enc_key(a_key_to);
    dap_hash_fast_t l_sign_pkey_hash;
    dap_pkey_get_hash(l_sign_pkey, &l_sign_pkey_hash);
    uint256_t l_value_out = uint256_0;
    dap_ledger_t *l_ledger = a_ledger;

    uint256_t l_reward_value = l_chain->callback_calc_reward(l_chain, a_block_hash, l_sign_pkey);
    dap_assert_PIF(!IS_ZERO_256(l_reward_value), "Reward calculating:");
    dap_assert_PIF(dap_ledger_is_used_reward(l_ledger, &a_block_hash, &l_sign_pkey_hash), "Reward is collected. ");
    //add 'in_reward' items
    dap_chain_datum_tx_add_in_reward_item(&l_tx, &a_block_hash);
    SUM_256_256(l_value_out, l_reward_value, &l_value_out);

    DAP_DELETE(l_sign_pkey);
    uint256_t l_net_fee = uint256_0, l_total_fee = uint256_0;
    dap_chain_addr_t l_addr_fee = c_dap_chain_addr_blank;
 
    // Check and apply sovereign tax for this key
    uint256_t l_value_tax = {};
    dap_chain_net_srv_stake_item_t *l_key_item = dap_chain_net_srv_stake_check_pkey_hash(l_chain->net_id, &l_sign_pkey_hash);
    if (l_key_item && !IS_ZERO_256(l_key_item->sovereign_tax) &&
                !dap_chain_addr_is_blank(&l_key_item->sovereign_addr)) {
        MULT_256_COIN(l_value_out, l_key_item->sovereign_tax, &l_value_tax);
        if (compare256(l_value_tax, l_value_out) < 1)
            SUBTRACT_256_256(l_value_out, l_value_tax, &l_value_out);
    }
    //add 'out' items
    if (!IS_ZERO_256(l_value_out)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, a_addr_to, l_value_out) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    if (!IS_ZERO_256(l_value_tax)) {
        if (dap_chain_datum_tx_add_out_item(&l_tx, &l_key_item->sovereign_addr, l_value_tax) != 1) {
            dap_chain_datum_tx_delete(l_tx);
            log_it(L_WARNING, "Can't create out item in transaction fee");
            return NULL;
        }
    }
    // add 'sign' item
    if(dap_chain_datum_tx_add_sign_item(&l_tx, a_sign_key) != 1) {
        dap_chain_datum_tx_delete(l_tx);
        log_it(L_WARNING, "Can't sign item in transaction fee");
        return NULL;
    }

    return 0;
} */

void dap_ledger_test_create_delegate_key_approve_decree()
{

}

/*dap_chain_datum_tx_t *dap_ledger_test_create_delegate_tx_cond(dap_enc_key_t *a_key_from, dap_chain_hash_fast_t *a_hash_prev, dap_chain_hash_fast_t *a_stake_tx_hash,
                                                                     uint256_t a_value, dap_ledger_t *a_ledger) {
    dap_chain_net_srv_uid_t l_uid = { .uint64 = DAP_CHAIN_NET_SRV_STAKE_LOCK_ID };
    // get previous transaction
    dap_chain_datum_tx_t *l_tx_prev = dap_ledger_tx_find_by_hash(a_ledger, a_hash_prev);
     // get previous cond out
    int l_out_idx = 0;
    dap_chain_tx_out_t *l_tx_prev_out = (dap_chain_tx_out_t *)dap_chain_datum_tx_item_get(l_tx_prev, &l_out_idx, TX_ITEM_TYPE_OUT, NULL);
    
    dap_chain_addr_t l_addr_to = {0};
    dap_chain_addr_fill_from_key(&l_addr_to, a_key_from, a_ledger->net->pub.id);

    dap_chain_datum_tx_t *l_tx = dap_chain_datum_tx_create();
    dap_chain_tx_in_t *l_in = dap_chain_datum_tx_item_in_create(a_hash_prev, 0);

    dap_chain_tx_in_ems_t *l_in_ems = DAP_NEW_Z(dap_chain_tx_in_ems_t);
    l_in_ems->header.type = TX_ITEM_TYPE_IN_EMS;
    l_in_ems->header.token_emission_chain_id.uint64 = 0;
    memset(&l_in_ems->header.token_emission_hash, 0, sizeof(l_in_ems->header.token_emission_hash));
    strcpy(l_in_ems->header.ticker, s_delegated_token_ticker);

    uint64_t a_time_staking = 1;
    dap_chain_tx_out_cond_t* l_tx_out_cond = dap_chain_datum_tx_item_out_cond_create_srv_stake(
                                                l_uid, a_value, a_key_from, );

    // add all items to tx
    uint256_t value_change = {};
    SUBTRACT_256_256(l_tx_prev_out->header.value, a_value, &value_change);
    SUBTRACT_256_256(value_change, dap_chain_uint256_from(s_fee), &value_change);
    dap_chain_tx_out_ext_t *l_out_change = dap_chain_datum_tx_item_out_ext_create(&l_addr_to, value_change, s_token_ticker);
    uint256_t a_delegated_value = {};
    MULT_256_COIN(a_value, dap_chain_coins_to_balance("0.1"), &a_delegated_value);
    dap_chain_tx_out_ext_t *l_out_delegated = dap_chain_datum_tx_item_out_ext_create(&l_addr_to, a_delegated_value, s_delegated_token_ticker);
    dap_chain_tx_out_cond_t *l_cond_fee = dap_chain_datum_tx_item_out_cond_create_fee(dap_chain_uint256_from(s_fee));
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_in_ems);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_tx_out_cond);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_cond_fee);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_change);
    dap_chain_datum_tx_add_item(&l_tx, (const uint8_t*) l_out_delegated);   
    dap_chain_datum_tx_add_sign_item(&l_tx, a_key_from);
    DAP_DEL_Z(l_in);
    DAP_DEL_Z(l_cond_fee);
    DAP_DEL_Z(l_in_ems);
    DAP_DEL_Z(l_out_change);
    DAP_DEL_Z(l_out_delegated);
    DAP_DEL_Z(l_tx_out_cond);

    return l_tx;
}*/


uint256_t dap_ledger_test_print_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr)
{
    uint256_t l_balance_after = dap_ledger_calc_balance(a_ledger, a_addr, s_token_ticker);
    char *l_balanse_str = dap_chain_balance_print(l_balance_after);
    dap_test_msg("Balance = %s %s", l_balanse_str, s_token_ticker);
    DAP_DELETE(l_balanse_str);
    return l_balance_after;
}

uint256_t dap_ledger_test_print_delegate_balance(dap_ledger_t *a_ledger, const dap_chain_addr_t *a_addr)
{
    uint256_t l_balance_after = dap_ledger_calc_balance(a_ledger, a_addr, s_delegated_token_ticker);
    char *l_balanse_str = dap_chain_balance_print(l_balance_after);
    dap_test_msg("Balance = %s %s", l_balanse_str, s_delegated_token_ticker);
    DAP_DELETE(l_balanse_str);
    return l_balance_after;
}

int dap_ledger_test_add_new_datum (uint16_t a_datum_type, void* a_datum, size_t a_datum_size, dap_chain_t *a_chain, dap_chain_hash_fast_t *a_datum_hash)
{
    dap_chain_datum_t* l_new_datum = dap_chain_datum_create(a_datum_type, a_datum, a_datum_size);
    size_t l_new_datum_size = a_datum_size + sizeof(l_new_datum->header);
    int status = dap_chain_datum_add(a_chain, l_new_datum, l_new_datum_size, a_datum_hash, NULL);
    dap_assert(status == 0, "Test of transaction adding to ledger:");
    return status;
}

dap_hash_fast_t dap_ledger_test_add_tx(dap_chain_net_t *a_net, dap_chain_datum_tx_t *a_tx) 
{
    dap_chain_t *l_chain_main = dap_chain_net_get_chain_by_name(a_net, "test_chain_main");
    dap_assert(a_tx, "Test of creating tx:"); 
    size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
    dap_hash_fast_t l_hash = {};
    dap_hash_fast(a_tx, l_tx_size, &l_hash);
    dap_ledger_test_add_new_datum (DAP_CHAIN_DATUM_TX, a_tx, l_tx_size, l_chain_main, &l_hash);
    return l_hash;
}
    


void dap_ledger_test_datums_removing(dap_ledger_t *a_ledger, dap_hash_fast_t *a_prev_hash, dap_enc_key_t  *a_from_key, dap_chain_net_id_t a_net_id) 
{
    dap_print_module_name("dap_ledger_test_datums_removing");
    dap_cert_t *l_first_cert = dap_cert_generate_mem_with_seed("newCert", DAP_ENC_KEY_TYPE_SIG_PICNIC, "FMknbirh8*^#$RYU*H", 18);
    dap_chain_addr_t l_addr = {0};
    dap_chain_addr_fill_from_key(&l_addr, a_from_key, a_net_id);
    uint256_t l_balance_before = dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_chain_addr_t l_addr_first = {0};
    dap_chain_addr_fill_from_key(&l_addr_first, l_first_cert->enc_key, a_net_id);
    dap_chain_net_t *l_net = dap_chain_net_by_id(a_net_id);
    dap_chain_t *l_chain_main = dap_chain_net_get_chain_by_name(l_net, "test_chain_main");
    
    // Check common tx removing
    dap_chain_datum_tx_t *l_first_tx = dap_ledger_test_create_tx_full(a_from_key, a_prev_hash, &l_addr_first, dap_chain_uint256_from(1U), l_net->pub.ledger);
    dap_chain_hash_fast_t l_first_tx_hash = dap_ledger_test_add_tx(l_net, l_first_tx);

    dap_ledger_test_print_balance(a_ledger, &l_addr);

    dap_chain_datum_tx_t *l_second_tx = dap_ledger_test_create_tx_full(a_from_key, &l_first_tx_hash, &l_addr_first, dap_chain_uint256_from(1U), l_net->pub.ledger);
    dap_assert(l_second_tx, "Test of creating second tx:");  
    dap_chain_hash_fast_t l_second_tx_hash = {0};
    dap_hash_fast(l_second_tx, dap_chain_datum_tx_get_size(l_second_tx), &l_second_tx_hash);
    dap_assert(!dap_ledger_tx_add(a_ledger, l_second_tx, &l_second_tx_hash, false, NULL), "Test of second transaction adding to ledger:");
    dap_ledger_test_print_balance(a_ledger, &l_addr);

    // try to remove spent tx
    dap_assert(dap_ledger_tx_remove(a_ledger, l_first_tx, &l_first_tx_hash), "Test of removing spent transaction:");
    dap_assert(!dap_ledger_tx_remove(a_ledger, l_second_tx, &l_second_tx_hash), "Test of removing second transaction:");
    dap_assert(!dap_ledger_tx_remove(a_ledger, l_first_tx, &l_first_tx_hash), "Test of removing first transaction:");
    uint256_t l_balance_after = dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_before, l_balance_after), "Compare balance before creating transactions and after removing them. Must be equal:");

    // check cond tx removing 
    {
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_test_create_tx_cond(a_from_key, a_prev_hash,
                                                                       &l_addr_first, dap_chain_uint256_from(1U),a_ledger);
    dap_assert_PIF(l_cond_tx, "Test of creating conditional transaction:");  
    dap_chain_hash_fast_t l_cond_tx_hash = {0};
    dap_hash_fast(l_cond_tx, dap_chain_datum_tx_get_size(l_first_tx), &l_cond_tx_hash);
    dap_assert(!dap_ledger_tx_add(a_ledger, l_cond_tx, &l_cond_tx_hash, false, NULL), "Test of conditional transaction adding to ledger:");
    dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_assert(!dap_ledger_tx_remove(a_ledger, l_cond_tx, &l_cond_tx_hash), "Test of conditional transaction removing from ledger:");
    l_balance_after = dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_before, l_balance_after), "Compare balance before creating transactions and after removing them. Must be equal:");
    }

    // try to spend cond tx 
    {
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_test_create_tx_cond(a_from_key, a_prev_hash,&l_addr_first, dap_chain_uint256_from(2U),a_ledger);
    dap_assert_PIF(l_cond_tx, "Test of creating conditional transaction:"); 
    dap_hash_fast_t l_cond_tx_hash = {};
    dap_hash_fast(l_cond_tx, dap_chain_datum_tx_get_size(l_cond_tx), &l_cond_tx_hash);
    dap_assert(!dap_ledger_tx_add(a_ledger, l_cond_tx, &l_cond_tx_hash, false, NULL), "Test of conditional transaction adding to ledger:");
    dap_ledger_test_print_balance(a_ledger, &l_addr);

    dap_cert_t *l_cond_spender_cert = dap_cert_generate_mem_with_seed("newCert", DAP_ENC_KEY_TYPE_SIG_PICNIC, "FMknbirh8*^#$RYU*q", 18);
    dap_chain_addr_t l_cond_spender_addr = {0};
    dap_chain_addr_fill_from_key(&l_cond_spender_addr, l_cond_spender_cert->enc_key, a_net_id);
    uint256_t l_cond_spending_balance_before = dap_ledger_test_print_balance(a_ledger, &l_cond_spender_addr);
    dap_chain_datum_tx_t *l_cond_spendind_tx = dap_ledger_test_create_spend_tx_cond(a_from_key, &l_cond_tx_hash, l_cond_spender_cert->enc_key, dap_chain_uint256_from(1U),a_ledger);
    dap_chain_hash_fast_t l_spend_cond_tx_hash = {0};
    dap_hash_fast(l_cond_spendind_tx, dap_chain_datum_tx_get_size(l_cond_spendind_tx), &l_spend_cond_tx_hash);
    dap_assert(!dap_ledger_tx_add(a_ledger, l_cond_spendind_tx, &l_spend_cond_tx_hash, false, NULL), "Test adding of transaction spending to a conditional transaction  to ledger:");
    uint256_t l_cond_spending_balance_after = dap_ledger_test_print_balance(a_ledger, &l_cond_spender_addr);
    dap_assert(!compare256(l_cond_spending_balance_after, dap_chain_uint256_from(1U)), "Check balance after spending:");
    dap_ledger_test_print_balance(a_ledger, &l_cond_spender_addr);
    dap_assert(!dap_ledger_tx_remove(a_ledger, l_cond_spendind_tx, &l_spend_cond_tx_hash), "Test removing of transaction spending to a conditional transaction  to ledger:");
    l_cond_spending_balance_after = dap_ledger_test_print_balance(a_ledger, &l_cond_spender_addr);
    dap_assert(!compare256(l_cond_spending_balance_before, l_cond_spending_balance_after), "Test spender balance after removing:");
    dap_assert(!dap_ledger_tx_remove(a_ledger, l_cond_tx, &l_cond_tx_hash), "Test of conditional transaction removing from ledger:");
    l_balance_after = dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_before, l_balance_after), "Compare balance before creating transactions and after removing them. Must be equal:");
    }

    // try to return funds from conditional tx and delete this tx
    {
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_test_create_tx_cond(a_from_key, a_prev_hash, &l_addr_first, dap_chain_uint256_from(2U),a_ledger);
    dap_hash_fast_t l_cond_tx_hash = {};
    dap_hash_fast(l_cond_tx, dap_chain_datum_tx_get_size(l_cond_tx), &l_cond_tx_hash);
    dap_assert(!dap_ledger_tx_add(a_ledger, l_cond_tx, &l_cond_tx_hash, false, NULL), "Adding of cond transaction to ledger is");

    dap_cert_t *l_cond_spending_cert = dap_cert_generate_mem_with_seed("newCert", DAP_ENC_KEY_TYPE_SIG_PICNIC, "FMknbirh8*^#$RYU*q", 18);
    dap_chain_addr_t l_cond_spending_addr = {0};
    dap_chain_addr_fill_from_key(&l_cond_spending_addr, l_cond_spending_cert->enc_key, a_net_id);
    uint256_t l_cond_spending_balance_before = dap_ledger_test_print_balance(a_ledger, &l_cond_spending_addr);
    dap_chain_datum_tx_t *l_cond_returning_tx = dap_ledger_test_create_return_from_tx_cond(&l_cond_tx_hash, a_from_key ,a_ledger);
    dap_chain_hash_fast_t l_cond_returning_tx_hash = {0};
    dap_hash_fast(l_cond_returning_tx, dap_chain_datum_tx_get_size(l_cond_returning_tx), &l_cond_returning_tx_hash);
    int err_code = dap_ledger_tx_add(a_ledger, l_cond_returning_tx, &l_cond_returning_tx_hash, false, NULL);
    printf("err_code = %s\n", dap_ledger_check_error_str(err_code));
    dap_assert(!err_code, "Returning of funds from cond transaction is");
    uint256_t l_cond_spending_balance_after = dap_ledger_test_print_balance(a_ledger, &l_cond_spending_addr);
    dap_assert(compare256(l_cond_spending_balance_after, dap_chain_uint256_from(2U)), "Returning of funds from conditional tx from ledger testing");

    dap_assert(!dap_ledger_tx_remove(a_ledger, l_cond_returning_tx, &l_cond_returning_tx_hash), "Tx cond removing from ledger is ");
    l_cond_spending_balance_after = dap_ledger_test_print_balance(a_ledger, &l_cond_spending_addr);
    dap_assert(!compare256(l_cond_spending_balance_before, l_cond_spending_balance_after), "Removing conditional tx from ledger testing");

    dap_assert(!dap_ledger_tx_remove(a_ledger, l_cond_tx, &l_cond_tx_hash), "Tx cond removing from ledger is ");
    l_cond_spending_balance_after = dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_before, l_cond_spending_balance_after), "Removing conditional tx from ledger testing");
    }

    // check stake adding and removing
    {
    dap_chain_datum_tx_t *l_cond_tx = dap_ledger_test_create_stake_tx_cond(a_from_key, a_prev_hash, dap_chain_uint256_from(20U), a_ledger);
    dap_hash_fast_t l_cond_tx_hash = {};
    dap_hash_fast(l_cond_tx, dap_chain_datum_tx_get_size(l_cond_tx), &l_cond_tx_hash);
    int err_code = dap_ledger_tx_add(a_ledger, l_cond_tx, &l_cond_tx_hash, false, NULL);
    printf("err_code = %s\n", dap_ledger_check_error_str(err_code));
    dap_assert(!err_code, "Adding of stake cond transaction to ledger is");

    dap_assert(!dap_ledger_tx_remove(a_ledger, l_cond_tx, &l_cond_tx_hash), "Test of stake conditional transaction removing from ledger:");
    l_balance_after = dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_before, l_balance_after), "Compare balance before creating stake transactions and after removing them. Must be equal:")
    }

    // check stake and unstake adding and removing
    {
    // Create stake lock tx
    dap_chain_datum_tx_t *l_stake_cond_tx = dap_ledger_test_create_stake_tx_cond(a_from_key, a_prev_hash, dap_chain_uint256_from(20U), a_ledger);
    dap_hash_fast_t l_stake_cond_tx_hash = {};
    dap_hash_fast(l_stake_cond_tx, dap_chain_datum_tx_get_size(l_stake_cond_tx), &l_stake_cond_tx_hash);
    int err_code = dap_ledger_tx_add(a_ledger, l_stake_cond_tx, &l_stake_cond_tx_hash, false, NULL);
    printf("err_code = %s\n", dap_ledger_check_error_str(err_code));
    dap_assert(!err_code, "Adding of stake cond transaction to ledger is");
    sleep(3);
    // Create stake unlock tx
    uint256_t l_balance_before_unstaking = dap_ledger_test_print_balance(a_ledger, &l_addr);
    uint256_t l_balance_delegated_before_unstaking = dap_ledger_test_print_delegate_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_delegated_before_unstaking, dap_chain_uint256_from(2U)), "Compare delegated token balance before creating unstake transactions:")
    
    dap_chain_datum_tx_t *l_unstake_cond_tx = dap_ledger_test_create_unstake_tx_cond(a_from_key, &l_stake_cond_tx_hash, dap_chain_uint256_from(20U), a_ledger);
    dap_hash_fast_t l_unstake_cond_tx_hash = {};
    dap_hash_fast(l_unstake_cond_tx, dap_chain_datum_tx_get_size(l_unstake_cond_tx), &l_unstake_cond_tx_hash);
    err_code = dap_ledger_tx_add(a_ledger, l_unstake_cond_tx, &l_unstake_cond_tx_hash, false, NULL);
    printf("err_code = %s\n", dap_ledger_check_error_str(err_code));
    dap_assert(!err_code, "Adding of unstake cond transaction to ledger is");
    uint256_t l_balance_delegated_after_unstaking = dap_ledger_test_print_delegate_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_delegated_after_unstaking, uint256_0), "Compare delegated token balance after creating unstake transactions:")
    
    err_code = dap_ledger_tx_remove(a_ledger, l_unstake_cond_tx, &l_unstake_cond_tx_hash);
    printf("err_code = %s\n", dap_ledger_check_error_str(err_code));
    dap_assert(!err_code, "Test of unstake conditional transaction removing from ledger:");
    l_balance_after = dap_ledger_test_print_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_delegated_after_unstaking, uint256_0), "Compare delegated token balance after removing unstake transaction:")
    uint256_t l_balance_delegated_after_removing_unstaking = dap_ledger_test_print_delegate_balance(a_ledger, &l_addr);
    dap_assert(!compare256(l_balance_before_unstaking, l_balance_after), "Compare balance after creating unstake transactions and after removing them. Must be equal:")

    // Check delegation

    
    

    // Check rewards
    

    }

    // Check vote removing 
    {

    }

    // Check voting removing
    {

    }

    // Check exchanger
    {

    }


}

dap_hash_fast_t dap_ledger_test_double_spending(
    dap_ledger_t *a_ledger, dap_hash_fast_t *a_prev_hash, dap_enc_key_t  *a_from_key, dap_chain_addr_t a_addr_to, dap_chain_net_id_t a_net_id) {
    dap_print_module_name("dap_ledger_double_spending");
    dap_chain_datum_tx_t *l_first_tx = dap_ledger_test_create_tx(a_from_key, a_prev_hash,
                                                                       &a_addr_to, dap_chain_uint256_from(s_standard_value_tx - s_fee));
    dap_assert_PIF(l_first_tx, "Can't creating base transaction.");
    dap_chain_hash_fast_t l_first_tx_hash = {0};
    dap_hash_fast(l_first_tx, dap_chain_datum_tx_get_size(l_first_tx), &l_first_tx_hash);
    dap_assert_PIF(!dap_ledger_tx_add(a_ledger, l_first_tx, &l_first_tx_hash, false, NULL), "Can't add first transaction on ledger");
    //uint256_t l_balance = dap_ledger_calc_balance(a_ledger, &l_addr_first, s_token_ticker);
    // Second tx
    dap_chain_datum_tx_t *l_second_tx = dap_ledger_test_create_tx(a_from_key, a_prev_hash,
                                                                       &a_addr_to, dap_chain_uint256_from(s_standard_value_tx - s_fee));
    dap_chain_hash_fast_t l_second_tx_hash = {0};
    dap_hash_fast(l_second_tx, dap_chain_datum_tx_get_size(l_second_tx), &l_second_tx_hash);
    dap_assert_PIF(dap_ledger_tx_add(a_ledger, l_second_tx, &l_second_tx_hash, false, NULL), "Added second transaction on ledger");
    dap_pass_msg("The verification test is not able to make two normal transactions per one basic transaction.");
    return l_first_tx_hash; 
}

void dap_ledger_test_excess_supply(dap_ledger_t *a_ledger, dap_cert_t *a_cert, dap_chain_addr_t *a_addr){
    dap_print_module_name("dap_ledger_test_excess_supply");
    const char *l_token_ticker = "Test2";
    uint256_t l_value_first_emi = dap_chain_uint256_from(s_total_supply / 2);
    uint256_t l_value_second_emi = dap_chain_uint256_from(s_total_supply);
    size_t l_decl_size = 0;
    dap_chain_datum_token_t *l_decl = dap_ledger_test_create_datum_decl(a_cert, &l_decl_size, l_token_ticker,
                                                                              dap_chain_uint256_from(s_total_supply), NULL, 0, DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
    dap_assert_PIF(!dap_ledger_token_add(a_ledger, (byte_t *)l_decl, l_decl_size), "Adding token declaration to ledger.");
    dap_chain_datum_token_emission_t *l_femi = dap_chain_datum_emission_create(l_value_first_emi, l_token_ticker, a_addr);
    l_femi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_femi);
    dap_chain_hash_fast_t l_femi_hash = {0};
    dap_hash_fast(l_femi, dap_chain_datum_emission_get_size((byte_t*)l_femi), &l_femi_hash);
    dap_assert_PIF(!dap_ledger_token_emission_add(a_ledger, (byte_t*)l_femi,
                                                        dap_chain_datum_emission_get_size((byte_t*)l_femi),
                                                        &l_femi_hash), "Added first emission in ledger");
    //Second emi
    dap_chain_datum_token_emission_t *l_semi = dap_chain_datum_emission_create(l_value_second_emi, l_token_ticker, a_addr);
    l_semi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_semi);
    dap_chain_hash_fast_t l_semi_hash = {0};
    dap_hash_fast(l_semi, dap_chain_datum_emission_get_size((byte_t*)l_semi), &l_semi_hash);
    int res =dap_ledger_token_emission_add(a_ledger, (byte_t*)l_semi,
                                                        dap_chain_datum_emission_get_size((byte_t*)l_semi),
                                                        &l_semi_hash);
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
    l_container->str = dap_strdup(dap_chain_addr_to_str_static(l_container->addr));
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

        dap_assert_PIF(!dap_ledger_token_add(a_ledger, (byte_t *)l_decl, l_decl_size),
                "Can't added datum in ledger");
        //Check emission in not a white list
        dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_create(
                dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_3->addr);
        l_emi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi);
        dap_chain_hash_fast_t l_emi_hash = {0};
        dap_hash_fast(l_emi, dap_chain_datum_emission_get_size((uint8_t*)l_emi), &l_emi_hash);
        dap_assert(dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi, dap_chain_datum_emission_get_size((byte_t*)l_emi),
                                                            &l_emi_hash) != 0,
                       "Checking the impossibility of emission to an address not from the white list.");
        //Emission in white list
        dap_chain_datum_token_emission_t *l_emi_whi = dap_chain_datum_emission_create(
            dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_1->addr);
        l_emi_whi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi_whi);
        dap_chain_hash_fast_t l_emi_whi_hash = {0};
        dap_hash_fast(l_emi_whi, dap_chain_datum_emission_get_size((uint8_t*)l_emi_whi), &l_emi_whi_hash);
        dap_assert_PIF(!dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi_whi, dap_chain_datum_emission_get_size((byte_t*)l_emi_whi),
                                            &l_emi_whi_hash),
                       "Can't add emission in white address");
        dap_chain_datum_tx_t *l_btx_addr1 = dap_ledger_test_create_datum_base_tx(l_emi_whi, &l_emi_whi_hash,
                                                                                      *l_addr_1->addr, a_cert);
        dap_hash_fast_t l_btx_addr1_hash = {0};
        dap_hash_fast(l_btx_addr1, dap_chain_datum_tx_get_size(l_btx_addr1), &l_btx_addr1_hash);
        int l_ledger_add_code = dap_ledger_tx_add(a_ledger, l_btx_addr1, &l_btx_addr1_hash, false, NULL);
        char *l_ledger_tx_add_str = dap_strdup_printf("Can't add base tx in white address. Code: %d", l_ledger_add_code);
        dap_assert_PIF(!l_ledger_add_code, l_ledger_tx_add_str);
        DAP_DELETE(l_ledger_tx_add_str);
        dap_hash_fast_t l_tx_addr4_hash = {0};
        dap_chain_datum_tx_t *l_tx_to_addr4 = dap_ledger_test_create_tx(l_addr_1->enc_key, &l_btx_addr1_hash,
                                                                              l_addr_4->addr, dap_chain_uint256_from(s_total_supply/*-s_fee*/));
        dap_hash_fast(l_tx_to_addr4, dap_chain_datum_tx_get_size(l_tx_to_addr4), &l_tx_addr4_hash);
        dap_assert_PIF(!dap_ledger_tx_add(a_ledger, l_tx_to_addr4, &l_tx_addr4_hash, false, NULL),
                       "Can't add transaction to address from white list in ledger");
        dap_chain_datum_tx_t *l_tx_to_addr3 = dap_ledger_test_create_tx(l_addr_4->enc_key, &l_tx_addr4_hash,
                                                                              l_addr_3->addr, dap_chain_uint256_from(s_total_supply/*-s_fee*/));
        dap_hash_fast_t l_tx_addr3_hash = {0};
        dap_hash_fast(l_tx_to_addr3, dap_chain_datum_tx_get_size(l_tx_to_addr3), &l_tx_addr3_hash);
        int res_add_tx = dap_ledger_tx_add(a_ledger, l_tx_to_addr3, &l_tx_addr3_hash, false, NULL);
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
//        memcpy(l_datum_token_update->tsd_n_signs, l_tsd_update_total_size, dap_tsd_size(l_tsd_update_total_size));
//        l_offset += dap_tsd_size(l_tsd_update_total_size);
//        memcpy(l_datum_token_update->tsd_n_signs + l_offset, l_tsd_dis_flags, dap_tsd_size(l_tsd_dis_flags));
//        l_offset += dap_tsd_size(l_tsd_dis_flags);
//        dap_sign_t * l_sign = dap_cert_sign(a_cert, l_datum_token_update,
//                                           sizeof(*l_datum_token_update) - sizeof(uint16_t));
//        if (l_sign) {
//            size_t l_sign_size = dap_sign_get_size(l_sign);
//            l_datum_token_update = DAP_REALLOC(l_datum_token_update, sizeof(dap_chain_datum_token_t) + l_offset + l_sign_size);
//            memcpy(l_datum_token_update->tsd_n_signs + l_offset, l_sign, l_sign_size);
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

        dap_assert_PIF(!dap_ledger_token_add(a_ledger, (byte_t *)l_decl, l_decl_size),
                       "Can't added datum in ledger");
        //Check emission at addr in block list
        dap_chain_datum_token_emission_t *l_emi_block = dap_chain_datum_emission_create(
                dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_1->addr);
        l_emi_block = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi_block);
        dap_chain_hash_fast_t l_emi_block_hash = {0};
        dap_hash_fast(l_emi_block, dap_chain_datum_emission_get_size((uint8_t*)l_emi_block), &l_emi_block_hash);
        dap_assert(dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi_block, dap_chain_datum_emission_get_size((byte_t*)l_emi_block),
                                                            &l_emi_block_hash),
                       "Test for emission rejection to an address from the prohibited list.");
        //Check emission at addr
        dap_chain_datum_token_emission_t *l_emi = dap_chain_datum_emission_create(
                dap_chain_uint256_from(s_total_supply), l_token_ticker, l_addr_2->addr);
        l_emi = dap_chain_datum_emission_add_sign(a_cert->enc_key, l_emi);
        dap_chain_hash_fast_t l_emi_hash = {0};
        dap_hash_fast(l_emi, dap_chain_datum_emission_get_size((uint8_t*)l_emi), &l_emi_hash);
        dap_assert(!dap_ledger_token_emission_add(a_ledger, (byte_t*)l_emi, dap_chain_datum_emission_get_size((byte_t*)l_emi),
                                                           &l_emi_hash),
                       "Emission test for a non-blacklisted address.");
        dap_chain_datum_tx_t *l_btx_addr2 = dap_ledger_test_create_datum_base_tx(l_emi, &l_emi_hash,
                                                                                       *l_addr_2->addr, a_cert);
        dap_hash_fast_t l_btx_addr2_hash = {0};
        dap_hash_fast(l_btx_addr2, dap_chain_datum_tx_get_size(l_btx_addr2), &l_btx_addr2_hash);
        dap_assert_PIF(!dap_ledger_tx_add(a_ledger, l_btx_addr2, &l_btx_addr2_hash, false, NULL),
                       "Can't add base tx in white address");
        //Check tx in addr from block list
        dap_chain_datum_tx_t *l_tx_to_addr1 = dap_ledger_test_create_tx(l_addr_4->enc_key, &l_btx_addr2_hash,
                                                                              l_addr_1->addr, dap_chain_uint256_from(s_total_supply));
        dap_hash_fast_t l_tx_addr1_hash = {0};
        dap_hash_fast(l_tx_to_addr1, dap_chain_datum_tx_get_size(l_tx_to_addr1), &l_tx_addr1_hash);
        dap_assert(dap_ledger_tx_add(a_ledger, l_tx_to_addr1, &l_tx_addr1_hash, false, NULL), "Transfer test to a forbidden address.");
        //Check tx in addr from list
        dap_chain_datum_tx_t *l_tx_to_addr3 = dap_ledger_test_create_tx(l_addr_4->enc_key, &l_tx_addr1_hash,
                                                                              l_addr_3->addr, dap_chain_uint256_from(s_total_supply));
        dap_hash_fast_t l_tx_addr3_hash = {0};
        dap_hash_fast(l_tx_to_addr3, dap_chain_datum_tx_get_size(l_tx_to_addr3), &l_tx_addr3_hash);
        dap_assert(dap_ledger_tx_add(a_ledger, l_tx_to_addr3, &l_tx_addr3_hash, false, NULL), "Transfer test to a not forbidden address.");
    }
}

void dap_ledger_test_run(void){
    dap_set_appname("cellframe-node");
    dap_assert_PIF(dap_chain_cs_blocks_init() == 0, "Initialization of dap consensus block: ");
    dap_assert_PIF(dap_chain_cs_esbocs_init() == 0, "Initialization of esbocs: ");
    dap_assert_PIF(dap_chain_cs_dag_init() == 0, "Initialization of esbocs: ");
    dap_assert_PIF(dap_chain_cs_dag_poa_init() == 0, "Initialization of esbocs: ");
    dap_chain_net_srv_stake_lock_init();
    dap_chain_net_srv_stake_pos_delegate_init();
    dap_assert_PIF(!dap_chain_net_srv_init(), "Srv initializstion");
    
    dap_print_module_name("dap_ledger");
    uint16_t l_flags = 0;
    l_flags |= DAP_LEDGER_CHECK_TOKEN_EMISSION;
    dap_chain_net_test_init();
    dap_chain_net_id_t l_iddn = {.uint64 = 0};
    sscanf("0xFA0", "0x%16"DAP_UINT64_FORMAT_x, &l_iddn.uint64);
    dap_chain_net_t *l_net = dap_chain_net_by_id(l_iddn);
    dap_ledger_t *l_ledger = dap_ledger_create(l_net, l_flags);
    l_net->pub.ledger = l_ledger;

    dap_chain_t *l_chain_zero =  dap_chain_create(l_net->pub.name, "test_chain_zerochain", l_net->pub.id, (dap_chain_id_t){.uint64 = 0});
    dap_config_t l_cfg = {};
    dap_assert_PIF(dap_chain_cs_create(l_chain_zero, &l_cfg) == 0, "Chain cs dag_poa creating: ");
    DL_APPEND(l_net->pub.chains, l_chain_zero);

    dap_chain_t *l_chain_main =  dap_chain_create(l_net->pub.name, "test_chain_main", l_net->pub.id, (dap_chain_id_t){.uint64 = 1});
    dap_assert_PIF(dap_chain_cs_create(l_chain_main, &l_cfg) == 0, "Chain esbocs cs creating: ");
    DL_APPEND(l_net->pub.chains, l_chain_main);

    dap_assert_PIF(!dap_chain_net_decree_init(l_net), "Decree initialization:");

    char *l_seed_ph = "H58i9GJKbn91238937^#$t6cjdf";
    size_t l_seed_ph_size = strlen(l_seed_ph);
    dap_cert_t *l_cert = dap_cert_generate_mem_with_seed("testCert", DAP_ENC_KEY_TYPE_SIG_PICNIC, l_seed_ph, l_seed_ph_size);

    dap_assert_PIF(dap_ledger_test_create_reward_decree(l_chain_main, l_net->pub.id,  dap_chain_uint256_from(2), l_cert)==0, "Reward decree creating:");


    size_t l_token_decl_size = 0;
    dap_chain_datum_token_t *l_token_decl = dap_ledger_test_create_datum_decl(l_cert,
                                                                                    &l_token_decl_size, s_token_ticker,
                                                                                    dap_chain_uint256_from(s_total_supply), NULL, 0, DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
    dap_assert_PIF(l_token_decl || l_token_decl_size == 0, "Generate token declaration.");
    int l_check_added_decl_token = 0;
    l_check_added_decl_token = dap_ledger_token_add_check(l_ledger, (byte_t *)l_token_decl, l_token_decl_size);
    dap_assert_PIF(l_check_added_decl_token == 0, "Checking whether it is possible to add a token declaration to ledger.");
    dap_assert_PIF(!dap_ledger_token_add(l_ledger, (byte_t *)l_token_decl, l_token_decl_size), "Adding token declaration to ledger.");
	
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
    dap_assert_PIF(!dap_ledger_token_emission_add(l_ledger, (byte_t*)l_emi_sign, l_emi_size, &l_emi_hash), "Added emission in ledger");

    // Declarate delegated token
    dap_chain_datum_token_tsd_delegate_from_stake_lock_t l_tsd_section;
    dap_strncpy(l_tsd_section.ticker_token_from, s_token_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_tsd_section.emission_rate = dap_chain_coins_to_balance("0.1");//	TODO: 'm' 1:10 tokens
    dap_tsd_t * l_tsd = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK, l_tsd_section);
    l_token_decl = dap_ledger_test_create_datum_decl(l_cert, &l_token_decl_size, s_delegated_token_ticker,
                                                     uint256_0, (byte_t*)l_tsd, dap_tsd_size(l_tsd), DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
    dap_assert_PIF(l_token_decl || l_token_decl_size == 0, "Generate delegated token declaration.");
    l_check_added_decl_token = 0;
    l_check_added_decl_token = dap_ledger_token_add_check(l_ledger, (byte_t *)l_token_decl, l_token_decl_size);
    dap_assert_PIF(l_check_added_decl_token == 0, "Checking whether it is possible to add a token declaration to ledger.");
    dap_assert_PIF(!dap_ledger_token_add(l_ledger, (byte_t *)l_token_decl, l_token_decl_size), "Adding token declaration to ledger.");

    //first base tx
    dap_chain_datum_tx_t *l_base_tx = dap_ledger_test_create_datum_base_tx(l_emi_sign, &l_emi_hash, l_addr, l_cert);
    size_t l_base_tx_size = dap_chain_datum_tx_get_size(l_base_tx);
    dap_hash_fast_t l_hash_btx = {0};
    dap_hash_fast(l_base_tx, l_base_tx_size, &l_hash_btx);
    dap_assert_PIF(!dap_ledger_tx_add_check(l_ledger, l_base_tx, l_base_tx_size, &l_hash_btx), "Check can added base tx in ledger");
    dap_assert_PIF(!dap_ledger_tx_add(l_ledger, l_base_tx, &l_hash_btx, false, NULL), "Added base tx in ledger.");
    uint256_t l_balance_example = dap_chain_uint256_from(s_standard_value_tx);
    uint256_t l_balance = dap_ledger_calc_balance(l_ledger, &l_addr, s_token_ticker);
	uint256_t l_fee = dap_chain_uint256_from(s_fee);
	SUM_256_256(l_balance,l_fee,&l_balance);
    dap_assert_PIF(!compare256(l_balance, l_balance_example), "Checking the availability of the necessary balance "
                                                             "on the wallet after the first transaction.");
    dap_pass_msg("Validation of the declaration of the token, creation of an emission and a basic transaction using this in the ledger.");
    //second base tx
    dap_chain_datum_tx_t  *l_base_tx_second = dap_ledger_test_create_datum_base_tx(l_emi_sign, &l_emi_hash, l_addr, l_cert);
    size_t l_base_tx_size2 = dap_chain_datum_tx_get_size(l_base_tx_second);
    dap_hash_fast_t l_hash_btx_second = {0};
    dap_hash_fast(l_base_tx_second, l_base_tx_size2, &l_hash_btx_second);
    if (dap_ledger_tx_add_check(l_ledger, l_base_tx_second, l_base_tx_size2, &l_hash_btx_second)) {
        dap_pass_msg("Checking can added second base tx in ledger");
    }
    if (dap_ledger_tx_add(l_ledger, l_base_tx_second, &l_hash_btx_second, false, NULL)){
        dap_pass_msg("Checking for a failure to add a second base transaction for the same issue to the ledger.");
    } else {
        dap_fail("Checking for a failure to add a second base transaction for the same issue to the ledger.");
    }	

    dap_cert_t *l_first_cert = dap_cert_generate_mem_with_seed("newCert", DAP_ENC_KEY_TYPE_SIG_PICNIC, "FMknbirh8*^#$RYU*L", 18);
    dap_chain_addr_t l_addr_first = {0};
    dap_chain_addr_fill_from_key(&l_addr_first, l_first_cert->enc_key, l_iddn);
    dap_hash_fast_t l_first_tx_hash = dap_ledger_test_double_spending(l_ledger, &l_hash_btx, l_cert->enc_key, l_addr_first, l_iddn);
    dap_ledger_test_excess_supply(l_ledger, l_cert, &l_addr);
    //dap_ledger_test_datums_adding(l_ledger, &l_hash_btx, l_cert->enc_key, l_iddn);//check adding all types of datums into ledger
    dap_ledger_test_datums_removing(l_ledger, &l_first_tx_hash, l_first_cert->enc_key, l_iddn);//check removing all types of datums from ledger
    dap_ledger_test_write_back_list(l_ledger, l_cert, l_iddn);

    dap_print_module_name("Test token update with total_supply change for CF20 type.");
    size_t l_token_decl_for_update_size = 0;
    dap_chain_datum_token_t *l_token_decl_for_update = dap_ledger_test_create_datum_decl(l_cert,
                                                                                    &l_token_decl_for_update_size, "bTEST",
                                                                                    dap_chain_uint256_from(50000), NULL, 0, DAP_CHAIN_DATUM_TOKEN_FLAG_NONE);
    dap_assert_PIF(l_token_decl_for_update || l_token_decl_for_update_size == 0, "Generate token declaration.");
    int l_check_added_decl_token_for_update = 0;
    l_check_added_decl_token_for_update = dap_ledger_token_add_check(l_ledger, (byte_t *)l_token_decl_for_update, l_token_decl_for_update_size);
    dap_assert_PIF(l_check_added_decl_token_for_update == 0, "Checking whether it is possible to add a token declaration to ledger.");
    dap_assert_PIF(!dap_ledger_token_add(l_ledger, (byte_t *)l_token_decl_for_update, l_token_decl_for_update_size), "Adding token declaration to ledger.");
    {
        uint256_t l_smaller_value = dap_chain_uint256_from(30000);
        dap_tsd_t *l_tsd_smaller_value = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY,
                                                               l_smaller_value);
        byte_t *l_tsd_smaller_byte_t = (byte_t *) l_tsd_smaller_value;
        size_t l_tsd_smaller_size = dap_tsd_size(l_tsd_smaller_value);
        size_t l_token_upd_smaller_value_size = 0;
        dap_chain_datum_token_t *l_token_upd_smaller_value = dap_ledger_test_create_datum_update(l_cert,
                                                                                                 &l_token_upd_smaller_value_size,
                                                                                                 "bTEST",
                                                                                                 l_tsd_smaller_byte_t,
                                                                                                 l_tsd_smaller_size);
        int l_check_added_upd_token_smaller_value = dap_ledger_token_add_check(l_ledger,
                                                                               (byte_t *) l_token_upd_smaller_value,
                                                                               l_token_upd_smaller_value_size);
        dap_assert_PIF(l_check_added_upd_token_smaller_value != 0, "Token update with a smaller value passed check.");
        dap_assert_PIF(
                dap_ledger_token_add(l_ledger, (byte_t *) l_token_upd_smaller_value, l_token_upd_smaller_value_size),
                "Adding token update with a smaller value to ledger.");
        dap_pass_msg("The check that it is not possible to update a token with a smaller total_supply has passed.");
    }
    {
        uint256_t l_more_value = dap_chain_uint256_from(70000);
        dap_tsd_t *l_tsd_more_value = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY,
                                                               l_more_value);
        byte_t *l_tsd_more_byte_t = (byte_t *) l_tsd_more_value;
        size_t l_tsd_more_size = dap_tsd_size(l_tsd_more_value);
        size_t l_token_upd_more_value_size = 0;
        dap_chain_datum_token_t *l_token_upd_more_value = dap_ledger_test_create_datum_update(l_cert,
                                                                                                 &l_token_upd_more_value_size,
                                                                                                 "bTEST",
                                                                                                 l_tsd_more_byte_t,
                                                                                                 l_tsd_more_size);
        int l_check_added_upd_token_more_value = dap_ledger_token_add_check(l_ledger,
                                                                               (byte_t *) l_token_upd_more_value,
                                                                               l_token_upd_more_value_size);
        dap_assert_PIF(l_check_added_upd_token_more_value == 0, "Token update with a more value passed check.");
        dap_assert_PIF(
                !dap_ledger_token_add(l_ledger, (byte_t *) l_token_upd_more_value, l_token_upd_more_value_size),
                "Adding token update with a more value to ledger.");
        dap_pass_msg("Checking that the ability to update a token with a large total_supply is passed.");
    }
    {
        uint256_t l_zero_value = dap_chain_uint256_from(0);
        dap_tsd_t *l_tsd_zero_value = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY,
                                                               l_zero_value);
        byte_t *l_tsd_zero_byte_t = (byte_t *) l_tsd_zero_value;
        size_t l_tsd_zero_size = dap_tsd_size(l_tsd_zero_value);
        size_t l_token_upd_zero_value_size = 0;
        dap_chain_datum_token_t *l_token_upd_zero_value = dap_ledger_test_create_datum_update(l_cert,
                                                                                                 &l_token_upd_zero_value_size,
                                                                                                 "bTEST",
                                                                                                 l_tsd_zero_byte_t,
                                                                                                 l_tsd_zero_size);
        int l_check_added_upd_token_more_value = dap_ledger_token_add_check(l_ledger,
                                                                               (byte_t *) l_token_upd_zero_value,
                                                                               l_token_upd_zero_value_size);
        dap_assert_PIF(l_check_added_upd_token_more_value == 0, "Token update with a zero value total_supply passed check.");
        dap_assert_PIF(
                !dap_ledger_token_add(l_ledger, (byte_t *) l_token_upd_zero_value, l_token_upd_zero_value_size),
                "Adding token update with a zero value total_supply to ledger.");
        dap_pass_msg("Checking that the ability to update a token with a zero total_supply is passed.");
    }

    {
        uint256_t l_no_zero_value = dap_chain_uint256_from(1000);
        dap_tsd_t *l_tsd_no_zero_value = dap_tsd_create_scalar(DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY,
                                                               l_no_zero_value);
        byte_t *l_tsd_zero_byte_t = (byte_t *) l_tsd_no_zero_value;
        size_t l_tsd_zero_size = dap_tsd_size(l_tsd_no_zero_value);
        size_t l_token_upd_zero_value_size = 0;
        dap_chain_datum_token_t *l_token_upd_zero_value = dap_ledger_test_create_datum_update(l_cert,
                                                                                                 &l_token_upd_zero_value_size,
                                                                                                 "bTEST",
                                                                                                 l_tsd_zero_byte_t,
                                                                                                 l_tsd_zero_size);
        int l_check_added_upd_token_more_value = dap_ledger_token_add_check(l_ledger,
                                                                               (byte_t *) l_token_upd_zero_value,
                                                                               l_token_upd_zero_value_size);
        dap_assert_PIF(l_check_added_upd_token_more_value != 0, "Checks that the ability to update a token with a non-zero total_supply if the current total_supply is set to zero.");
        dap_assert_PIF(
                dap_ledger_token_add(l_ledger, (byte_t *) l_token_upd_zero_value, l_token_upd_zero_value_size),
                "Adding a token update with a non-zero total_supply value if the current total_supply is set to zero to the ledger.");
        dap_pass_msg("Checks that the ability to update a token with a non-zero total_supply if the current total_supply is set to zero is passed.");
    }

}
