#pragma once
#include "dap_common.h"
#include "dap_pkey.h"
#include "dap_chain_common.h"
#include "dap_chain_net_srv.h"
#include <json.h>

#define dap_json_get_text(json, key) _dap_json_get_text(json, key, LOG_TAG)
const char* _dap_json_get_text(struct json_object *a_json, const char *a_key, const char *a_log_tag);

#define dap_json_get_uint256(json, key, out) _dap_json_get_uint256(json, key, out, LOG_TAG)
bool _dap_json_get_uint256(struct json_object *a_json, const char *a_key, uint256_t *a_out, const char *a_log_tag);

#define dap_json_get_int64(json, key, out) _dap_json_get_int64(json, key, out, LOG_TAG)
bool _dap_json_get_int64(struct json_object *a_json, const char *a_key, int64_t *a_out, const char *a_log_tag);

#define dap_json_get_unit(json, key, out) _dap_json_get_unit(json, key, out, LOG_TAG)
bool _dap_json_get_unit(struct json_object *a_json, const char *a_key, dap_chain_net_srv_price_unit_uid_t *a_out, const char *a_log_tag);

#define dap_json_get_cert(json, key) _dap_json_get_cert(json, key, LOG_TAG)
const dap_cert_t* _dap_json_get_cert(struct json_object *a_json, const char *a_key, const char *a_log_tag);

#define dap_json_get_wallet(json, key) _dap_json_get_wallet(json, key, LOG_TAG)
dap_chain_wallet_t* _dap_json_get_wallet(struct json_object *a_json, const char *a_key, const char *a_log_tag);

// service names: srv_stake, srv_vpn, srv_xchange
#define dap_json_get_srv_uid(json, key_service_id, key_service, out) \
_dap_json_get_srv_uid(json, key_service_id, key_service, out, LOG_TAG)
bool _dap_json_get_srv_uid(struct json_object *a_json, const char *a_key_service_id,
        const char *a_key_service, uint64_t *a_out, const char *a_log_tag);

// Read pkey from wallet or cert
#define dap_json_get_pkey(json) _dap_json_get_pkey(json, LOG_TAG)
dap_pkey_t* _dap_json_get_pkey(struct json_object *a_json, const char *a_log_tag);

