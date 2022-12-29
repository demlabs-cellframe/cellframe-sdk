#include "dap_json.h"

//#define dap_json_get_text(json, key) {}

const char* _dap_json_get_text(struct json_object *a_json, const char *a_key, const char *a_log_tag)
{
    if(!a_json || !a_key) {
        _log_it(a_log_tag, L_DEBUG, "An error occurred converting a JSON object to a string. Either the "
                                    "JSON object or its key is not specified.");
        return NULL;
    }
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json && json_object_is_type(l_json, json_type_string)) {
        // Read text
        return json_object_get_string(l_json);
    }
    _log_it(a_log_tag, L_DEBUG, "An error occurred converting a JSON object to a string. The object "
                                "found in JSON by \"%s\" key is not a string.", a_key);
    return NULL;
}

bool _dap_json_get_uint256(struct json_object *a_json, const char *a_key, uint256_t *a_out, const char *a_log_tag)
{
    const char *l_uint256_str = _dap_json_get_text(a_json, a_key, "_dap_json_get_uint256");
    if(!a_out || !l_uint256_str) {
        _log_it(a_log_tag, L_DEBUG, "There was an error converting JSON object to uint256_t. Unable to get string "
                                    "representation of number from JSON object or no out specified.");
        return false;
    }
    uint256_t l_value = dap_chain_balance_scan(l_uint256_str);
    if(!IS_ZERO_256(l_value)) {
        memcpy(a_out, &l_value, sizeof(uint256_t));
        return true;
    }
    _log_it(a_log_tag, L_DEBUG, "There was an error converting JSON object to uint256_t. Failed to get number in "
                               "uint256_t format from string representation of number.");
    return false;
}

bool _dap_json_get_int64(struct json_object *a_json, const char *a_key, int64_t *a_out, const char *a_log_tag)
{
    if(!a_json || !a_key || !a_out) {
        _log_it(a_log_tag, L_DEBUG, "There was an error converting JSON object to int64_t. One of the "
                                    "required arguments is NULL.");
        return false;
    }
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json) {
        if(json_object_is_type(l_json, json_type_int)) {
            // Read number
            *a_out = json_object_get_int64(l_json);
            return true;
        } else {
            _log_it(a_log_tag, L_DEBUG, "There was an error converting JSON object to int64_t. "
                                        "The key \"%s\" contains an object with a type other than int64_t.", a_key);
        }
    }else {
        _log_it(a_log_tag, L_DEBUG, "There was an error converting JSON object to int64_t. Key %s not "
                                    "found JSON object.", a_key);
    }

    return false;
}

bool _dap_json_get_unit(struct json_object *a_json, const char *a_key, dap_chain_net_srv_price_unit_uid_t *a_out, const char *a_log_tag)
{
    const char *l_unit_str = _dap_json_get_text(a_json, a_key, "_dap_json_get_unit");
    if(!l_unit_str || !a_out) {
        _log_it(a_log_tag, L_DEBUG, "There was an error converting JSON object "
                                    "to dap_chain_net_srv_price_unit_uid_t. Unable to get string "
                                    "representation of dap_chain_net_srv_price_unit_uid_t from JSON object or no out specified.");
        return false;
    }
    dap_chain_net_srv_price_unit_uid_t l_unit = dap_chain_net_srv_price_unit_uid_from_str(l_unit_str);
    if(l_unit.enm == SERV_UNIT_UNDEFINED) {
        _log_it(a_log_tag, L_DEBUG, "An error occurred while converting a JSON object to "
                                    "dap_chain_net_srv_price_unit_uid_t. Failed to determine which "
                                    "dap_chain_net_srv_price_unit_uid_t is specified in the JSON object.");
        return false;
    }
    a_out->enm = l_unit.enm;
    return true;
}

const dap_cert_t* _dap_json_get_cert(struct json_object *a_json, const char *a_key, const char *a_log_tag)
{
    const char *l_cert_name = _dap_json_get_text(a_json, a_key, "_dap_json_get_cert");
    if(l_cert_name) {
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
        return l_cert;
    }
    _log_it(a_log_tag, L_DEBUG, "The certificate with the name \"%s\" was not found.", l_cert_name);
    return NULL;
}

dap_chain_wallet_t* _dap_json_get_wallet(struct json_object *a_json, const char *a_key, const char *a_log_tag)
{
    dap_enc_key_t *l_enc_key = NULL;
    // From wallet
    const char *l_wallet_str = _dap_json_get_text(a_json, a_key, "_dap_json_get_wallet");
    if(l_wallet_str) {
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_config_get_item_str_default(g_config, "resources", "wallets_path", NULL));
        return l_wallet;
    }
    _log_it(a_log_tag, L_DEBUG, "The wallet named \"%s\" cannot be opened.", l_wallet_str);
    return NULL;
}

// service names: srv_stake, srv_vpn, srv_xchange
bool _dap_json_get_srv_uid(struct json_object *a_json, const char *a_key_service_id, const char *a_key_service, uint64_t *a_out, const char *a_log_tag)
{
    uint64_t l_srv_id;
    if(!a_out) {
        _log_it(a_log_tag, L_DEBUG, "Cannot get srv uid out argument is NULL.");
        return false;
    }
    // Read service id
    if(_dap_json_get_int64(a_json, a_key_service_id, (int64_t*) &l_srv_id, "_dap_json_get_srv_uid")) {
        *a_out = l_srv_id;
        return true;
    }
    else {
        // Read service as name
        const char *l_service = _dap_json_get_text(a_json, a_key_service, "_dap_json_get_srv_uid");
        if(l_service) {
            dap_chain_net_srv_t *l_srv = dap_chain_net_srv_get_by_name(l_service);
            // Select service manually, this can happen if the service is not initialized [function dap_chain_net_srv_add()]
            // likely the service is disabled in the settings
            if(!l_srv) {
                // service DAP_CHAIN_NET_SRV_STAKE_ID
                if(!dap_strcmp(l_service, "srv_stake")) {
                    *a_out = 0x13;
                    return true;
                }
                    // service DAP_CHAIN_NET_SRV_XCHANGE_ID
                else if(!dap_strcmp(l_service, "srv_stake")) {
                    *a_out = 0x02;
                    return true;
                }
                    // service DAP_CHAIN_NET_SRV_VPN_ID
                else if(!dap_strcmp(l_service, "srv_vpn")) {
                    *a_out = 0x01;
                    return true;
                }
                else
                    return false;
            }
            *a_out = l_srv->uid.uint64;
            return true;
        }
    }
    _log_it(a_log_tag, L_DEBUG, "Unable to get srv uid. The integer or name of the service is incorrect.");
    return false;
}

// Read pkey from wallet or cert
dap_pkey_t* _dap_json_get_pkey(struct json_object *a_json, const char *a_log_tag)
{
    dap_pkey_t *l_pub_key = NULL;
    // From wallet
    dap_chain_wallet_t *l_wallet = _dap_json_get_wallet(a_json, "wallet", "_dap_json_get_pkey");
    if(l_wallet) {
        l_pub_key = dap_chain_wallet_get_pkey(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
        if(l_pub_key) {
            return l_pub_key;
        }
    }
    // From cert
    const dap_cert_t *l_cert = _dap_json_get_cert(a_json, "cert", "_dap_json_get_pkey");
    if(l_cert) {
        l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
    }
    if (!l_pub_key) {
        _log_it(a_log_tag, L_DEBUG, "Failed to get public key from JSON object.");
    }
    return l_pub_key;
}
