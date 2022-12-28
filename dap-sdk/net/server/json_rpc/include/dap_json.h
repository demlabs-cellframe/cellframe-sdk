#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_net_srv.h"
#include <json.h>

//#define dap_json_get_text(json, key) {}

static const char* dap_json_get_text(struct json_object *a_json, const char *a_key)
{
    if(!a_json || !a_key)
        return NULL;
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json && json_object_is_type(l_json, json_type_string)) {
        // Read text
        return json_object_get_string(l_json);
    }
    return NULL;
}

static bool dap_json_get_uint256(struct json_object *a_json, const char *a_key, uint256_t *a_out)
{
    const char *l_uint256_str = dap_json_get_text(a_json, a_key);
    if(!a_out || !l_uint256_str)
        return false;
    uint256_t l_value = dap_chain_balance_scan(l_uint256_str);
    if(!IS_ZERO_256(l_value)) {
        memcpy(a_out, &l_value, sizeof(uint256_t));
        return true;
    }
    return false;
}

static bool dap_json_get_int64(struct json_object *a_json, const char *a_key, int64_t *a_out)
{
    if(!a_json || !a_key || !a_out)
        return false;
    struct json_object *l_json = json_object_object_get(a_json, a_key);
    if(l_json) {
        if(json_object_is_type(l_json, json_type_int)) {
            // Read number
            *a_out = json_object_get_int64(l_json);
            return true;
        }
    }
    return false;
}

static bool dap_json_get_unit(struct json_object *a_json, const char *a_key, dap_chain_net_srv_price_unit_uid_t *a_out)
{
    const char *l_unit_str = dap_json_get_text(a_json, a_key);
    if(!l_unit_str || !a_out)
        return false;
    dap_chain_net_srv_price_unit_uid_t l_unit = dap_chain_net_srv_price_unit_uid_from_str(l_unit_str);
    if(l_unit.enm == SERV_UNIT_UNDEFINED)
        return false;
    a_out->enm = l_unit.enm;
    return true;
}

static const dap_cert_t* dap_json_get_cert(struct json_object *a_json, const char *a_key)
{
    const char *l_cert_name = dap_json_get_text(a_json, a_key);
    if(l_cert_name) {
        dap_cert_t *l_cert = dap_cert_find_by_name(l_cert_name);
        return l_cert;
    }
    return NULL;
}

static dap_chain_wallet_t* dap_json_get_wallet(struct json_object *a_json, const char *a_key)
{
    dap_enc_key_t *l_enc_key = NULL;
    // From wallet
    const char *l_wallet_str = dap_json_get_text(a_json, a_key);
    if(l_wallet_str) {
        dap_chain_wallet_t *l_wallet = dap_chain_wallet_open(l_wallet_str, dap_config_get_item_str_default(g_config, "resources", "wallets_path", NULL));
        return l_wallet;
    }
    return NULL;
}

// service names: srv_stake, srv_vpn, srv_xchange
static bool dap_json_get_srv_uid(struct json_object *a_json, const char *a_key_service_id, const char *a_key_service, uint64_t *a_out)
{
    uint64_t l_srv_id;
    if(!a_out)
        return false;
    // Read service id
    if(dap_json_get_int64(a_json, a_key_service_id, (int64_t*) &l_srv_id)) {
        *a_out = l_srv_id;
        return true;
    }
    else {
        // Read service as name
        const char *l_service = dap_json_get_text(a_json, a_key_service);
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
    return false;
}

// Read pkey from wallet or cert
static dap_pkey_t* dap_json_get_pkey(struct json_object *a_json)
{
    dap_pkey_t *l_pub_key = NULL;
    // From wallet
    dap_chain_wallet_t *l_wallet = dap_json_get_wallet(a_json, "wallet");
    if(l_wallet) {
        l_pub_key = dap_chain_wallet_get_pkey(l_wallet, 0);
        dap_chain_wallet_close(l_wallet);
        if(l_pub_key) {
            return l_pub_key;
        }
    }
    // From cert
    const dap_cert_t *l_cert = dap_json_get_cert(a_json, "cert");
    if(l_cert) {
        l_pub_key = dap_pkey_from_enc_key(l_cert->enc_key);
    }
    return l_pub_key;
}
