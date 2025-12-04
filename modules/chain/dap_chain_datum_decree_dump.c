#include "dap_chain_datum_decree.h"
#include "dap_chain_policy.h"
#include "dap_json.h"
#include "dap_chain_common.h"
#include "dap_enc_base58.h"
#include "dap_tsd.h"

#define LOG_TAG "dap_chain_datum_decree_dump"

dap_chain_policy_t *dap_chain_datum_decree_get_policy(dap_chain_datum_decree_t *a_decree)
{
    if (!a_decree)
        return NULL;
    dap_tsd_t *l_tsd = dap_tsd_find(a_decree->data_n_signs, a_decree->header.data_size, DAP_CHAIN_DATUM_DECREE_TSD_TYPE_POLICY_EXECUTE);
    return (l_tsd  && dap_chain_policy_get_size((dap_chain_policy_t *)l_tsd->data) == l_tsd->size) ? (dap_chain_policy_t *)l_tsd->data : NULL;
}

void dap_chain_datum_decree_dump_json(dap_json_t *a_json_out, const void *a_data, size_t a_decree_size, const char *a_hash_out_type, int a_version)
{
    dap_chain_datum_decree_t *a_decree = (dap_chain_datum_decree_t *)a_data;
    char *l_type_str;
    switch(a_decree->header.type)
    {
        case DAP_CHAIN_DATUM_DECREE_TYPE_COMMON:
            l_type_str = "DECREE_TYPE_COMMON";
            break;
        case DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE:
            l_type_str = "DECREE_TYPE_SERVICE";
            break;
        default:
            l_type_str = "DECREE_TYPE_UNKNOWN";
    }
    dap_json_object_add_string(a_json_out, a_version == 1 ? "type" : "decree_type", l_type_str);
    const char *l_subtype_str = dap_chain_datum_decree_subtype_to_str(a_decree->header.sub_type);
    dap_json_object_add_string(a_json_out, "subtype", l_subtype_str);
    dap_json_object_add_string(a_json_out, a_version == 1 ? "TSD" : "tsd", "");
    dap_tsd_t *l_tsd; size_t l_tsd_size;
    dap_tsd_iter(l_tsd, l_tsd_size, a_decree->data_n_signs, a_decree->header.data_size) {
        if (a_version != 1)
            dap_json_object_add_string(a_json_out, "tsd_type", dap_chain_datum_decree_tsd_type_to_str(l_tsd->type));
        switch(l_tsd->type) {
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE:
            if (l_tsd->size > sizeof(uint256_t)){
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Value" : "value", "WRONG SIZE");
                break;
            }
            uint256_t l_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_value);
            const char *l_value_str = dap_uint256_to_char(l_value, NULL);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Value" : "value", l_value_str);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN:
        break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE:
            if (l_tsd->size > sizeof(uint256_t)){
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Fee" : "fee", "WRONG SIZE");
                break;
            }
            uint256_t l_fee_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_fee_value);
            const char *l_fee_value_str = dap_uint256_to_char(l_fee_value, NULL);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Fee" : "fee", l_fee_value_str);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER:
            if (l_tsd->size < sizeof(dap_pkey_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Owner fingerprint" : "owner_pkey_hash", "WRONG SIZE");
                break;
            }
            dap_pkey_t *l_owner_pkey = _dap_tsd_get_object(l_tsd, dap_pkey_t);
            dap_json_object_add_object(a_json_out, a_version == 1 ? "Owner fingerprint" : "owner_pkey_hash", dap_json_object_new_string(dap_get_data_hash_str(l_owner_pkey->pkey, l_owner_pkey->header.size).s));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER:
            if (l_tsd->size > sizeof(uint256_t)){
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Owner min" : "owner_min", "WRONG SIZE");
                break;
            }
            uint256_t l_owner_min = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_owner_min);
            const char *l_owner_min_str = dap_uint256_to_char(l_owner_min, NULL);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Owner min" : "owner_min", l_owner_min_str);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET:
            if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Wallet for fee" : "fee_wallet", "WRONG SIZE");
                break;
            }
            dap_chain_addr_t *l_addr_fee_wallet = _dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Wallet for fee" : "fee_wallet", dap_chain_addr_to_str_static(l_addr_fee_wallet));
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH:
            if (l_tsd->size > sizeof(dap_hash_fast_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Stake tx" : "stake_tx", "WRONG SIZE");
                break;
            }
            dap_hash_fast_t *l_stake_tx = _dap_tsd_get_object(l_tsd, dap_hash_fast_t);
            const char *l_stake_tx_hash = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(l_stake_tx)
                    : dap_chain_hash_fast_to_str_static(l_stake_tx);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Stake tx" : "stake_tx", l_stake_tx_hash);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE:
            if (l_tsd->size > sizeof(uint256_t)){
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Stake value" : "stake_value", "WRONG SIZE");
                break;
            }
            uint256_t l_stake_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_stake_value);
            const char *l_stake_value_str = dap_uint256_to_char(l_stake_value, NULL);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Stake value" : "stake_value", l_stake_value_str);
            break;
       case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR:
            if (l_tsd->size > sizeof(dap_chain_addr_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Signing addr" : "sig_addr", "WRONG SIZE");
                break;
            }
            dap_chain_addr_t *l_stake_addr_signing = _dap_tsd_get_object(l_tsd, dap_chain_addr_t);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Signing addr" : "sig_addr", dap_chain_addr_to_str_static(l_stake_addr_signing));
            dap_chain_hash_fast_t l_pkey_signing = l_stake_addr_signing->data.hash_fast;
            const char *l_pkey_signing_str = dap_strcmp(a_hash_out_type, "hex")
                    ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_signing)
                    : dap_chain_hash_fast_to_str_static(&l_pkey_signing);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Signing pkey fingerprint" : "sig_pkey_hash", l_pkey_signing_str);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR:
            if(l_tsd->size > sizeof(dap_chain_node_addr_t)){
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Node addr" : "node_addr", "WRONG SIZE");
                break;
            }
            dap_chain_node_addr_t *l_node_addr = _dap_tsd_get_object(l_tsd, dap_chain_node_addr_t);
            char l_buf[24];
            snprintf(l_buf, sizeof(l_buf), NODE_ADDR_FP_STR, NODE_ADDR_FP_ARGS(l_node_addr));
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Node addr" : "node_addr", l_buf);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE:
            if (l_tsd->size > sizeof(uint256_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Min value" : "min_value", "WRONG SIZE");
                break;
            }
            uint256_t l_min_value = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_min_value);
            const char *l_min_value_str = dap_uint256_to_char(l_min_value, NULL);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Min value": "min_value", l_min_value_str);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT:
            if (l_tsd->size > sizeof(uint256_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Min signers count" : "min_sig_count", "WRONG SIZE");
                break;
            }
            uint256_t l_min_signers_count = uint256_0;
            _dap_tsd_get_scalar(l_tsd, &l_min_signers_count);
            const char *l_min_signers_count_str = dap_uint256_to_char(l_min_signers_count, NULL);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Min signers count" : "min_sig_count", l_min_signers_count_str);
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST:
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING:
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Host address" : "host_addr", dap_tsd_get_string(l_tsd));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_ACTION:
            if (l_tsd->size != sizeof(uint8_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Action" : "action", "WRONG SIZE");
                break;
            }
            uint8_t l_action = 0;
            _dap_tsd_get_scalar(l_tsd, &l_action);
            dap_json_object_add_string(a_json_out, a_version == 1 ? "tAction" : "action", l_action ? "add (enable)" : "delete (disable)");
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGNATURE_TYPE:
            if (l_tsd->size != sizeof(uint32_t)) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "Signature type" : "sig_type", "WRONG SIZE");
                break;
            }
            uint32_t l_type = 0;
            _dap_tsd_get_scalar(l_tsd, &l_type);
            dap_sign_type_t l_sign_type = { .type = l_type };
            dap_json_object_add_string(a_json_out, a_version == 1 ? "Signature type" : "sig_type", dap_sign_type_to_str(l_sign_type));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_PKEY:
            if (l_tsd->size != dap_pkey_get_size((dap_pkey_t *)(l_tsd->data))) {
                dap_json_object_add_string(a_json_out, a_version == 1 ? "pkey type" : "pkey_type", "WRONG SIZE");
                break;
            }
            dap_json_object_add_object(a_json_out, a_version == 1 ? "pkey type" : "pkey_type", dap_json_object_new_string( dap_pkey_type_to_str(((dap_pkey_t *)(l_tsd->data))->header.type) ));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCK_NUM:
            if (l_tsd->size != sizeof(uint64_t)) {
                dap_json_object_add_string(a_json_out, "sig_type", "WRONG SIZE");
                break;
            }
            uint64_t l_num = 0;
            _dap_tsd_get_scalar(l_tsd, &l_num);
            dap_json_object_add_uint64(a_json_out, "sig_type", l_num);
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HARDFORK_CHANGED_ADDRS:
            if (l_tsd->size != sizeof(uint64_t)) {
                dap_json_object_add_string(a_json_out, "wallet_addr_pair", "WRONG SIZE");
                break;
            }
            dap_json_t *l_json_obj = NULL;
            if (!dap_strcmp(dap_tsd_get_string_const(l_tsd), DAP_TSD_CORRUPTED_STRING)) {
                l_json_obj = dap_json_parse_string(dap_tsd_get_string_const(l_tsd));
            } else {
                l_json_obj = dap_json_object_new_string("Can't parse json in Wallet_addr_pair");
            }
            dap_json_object_add_object(a_json_out, "wallet_addr_pair", l_json_obj);

        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_POLICY_EXECUTE:
            if (l_tsd->size != dap_chain_policy_get_size((dap_chain_policy_t *)(l_tsd->data))) {
                dap_json_object_add_string(a_json_out, "policy_type", "WRONG SIZE");
                break;
            }
            dap_json_object_add_object(a_json_out, "policy_type", dap_json_object_new_string( dap_chain_policy_to_str((dap_chain_policy_t *)(l_tsd->data))));
            break;
        case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCKGEN_PERIOD:
            if (l_tsd->size != sizeof(uint16_t)) {
                dap_json_object_add_object(a_json_out, "blockgen_period", dap_json_object_new_string("WRONG SIZE"));
                break;
            }
            uint16_t l_blockgen_period = 0;
            _dap_tsd_get_scalar(l_tsd, &l_blockgen_period);
            dap_json_object_add_object(a_json_out, "blockgen_period", dap_json_object_new_uint64(l_blockgen_period));
            break;
        default:
            if (a_version == 1)
                dap_json_object_add_string(a_json_out, "UNKNOWN_TYPE_TSD_SECTION", "");
            break;
        }
    }
    dap_chain_datum_decree_certs_dump_json(a_json_out, a_decree->data_n_signs + a_decree->header.data_size,
                                      a_decree->header.signs_size, a_hash_out_type, a_version);
}

