/*
 * Authors:
 * Dmitriy A. Gearasimov <kahovski@gmail.com>
 * DeM Labs Inc.   https://demlabs.net
 * DeM Labs Open source community https://github.com/demlabsinc
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Distributed Applications Platform) the open source project

    DAP (Distributed Applications Platform) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#include <stdio.h>
#include <string.h>
#include "dap_strfuncs.h"
#include "dap_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_token.h"
#include "dap_uuid.h"
#include "dap_enc_base58.h"

#define LOG_TAG "dap_chain_datum_token"

struct datum_token_flag_struct {
    const char *key;
    uint32_t val;
};

static const struct datum_token_flag_struct s_flags_table[] = {
    { "NO_FLAGS",                       DAP_CHAIN_DATUM_TOKEN_FLAG_NONE },
    { "ALL_BLOCKED",                    DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED },
    { "ALL_FROZEN",                     DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN },
    { "ALL_ALLOWED",                    DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED },
    { "ALL_UNFROZEN",                   DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN },
    { "STATIC_ALL",                     DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_ALL },
    { "STATIC_FLAGS",                   DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_FLAGS },
    { "STATIC_PERMISSIONS_ALL",         DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_ALL },
    { "STATIC_PERMISSIONS_DATUM_TYPE",  DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_DATUM_TYPE },
    { "STATIC_PERMISSIONS_TX_SENDER",   DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_SENDER },
    { "STATIC_PERMISSIONS_TX_RECEIVER", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_RECEIVER },
    { "ALL_SENDER_BLOCKED",             DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED },
    { "ALL_SENDER_FROZEN",              DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN },
    { "ALL_SENDER_ALLOWED",             DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED },
    { "ALL_SENDER_UNFROZEN",            DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN },
    { "ALL_RECEIVER_BLOCKED",           DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED },
    { "ALL_RECEIVER_FROZEN",            DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN },
    { "ALL_RECEIVER_ALLOWED",           DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED },
    { "ALL_RECEIVER_UNFROZEN",          DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN }
};

/**
 * @brief dap_chain_datum_token_tsd_get
 * @param a_token
 * @param a_token_size
 * @return
 */
dap_tsd_t* dap_chain_datum_token_tsd_get(dap_chain_datum_token_t *a_token, size_t a_token_size)
{
    if (a_token_size < sizeof(dap_chain_datum_token_t)){
        log_it(L_WARNING, "Token size %lu < %lu header size, corrupted token datum", a_token_size, sizeof(dap_chain_datum_token_t));
        return NULL;
    }
    return (dap_tsd_t*)a_token->tsd_n_signs;
}

dap_chain_datum_token_t *dap_chain_datum_token_read(const byte_t *a_token_serial, size_t *a_token_size)
{
    dap_return_val_if_fail(a_token_serial && a_token_size, NULL);
    if (*a_token_size < sizeof(dap_chain_datum_token_old_t)) {
        log_it(L_WARNING, "Too small token size %zu", *a_token_size);
        return NULL;
    }
    dap_chain_datum_token_old_t *l_token_old = (dap_chain_datum_token_old_t *)a_token_serial;
    size_t l_token_tsd_n_signs_size = *a_token_size - sizeof(dap_chain_datum_token_old_t);
    size_t l_token_size = dap_chain_datum_token_is_old(l_token_old->type) ? l_token_tsd_n_signs_size + sizeof(dap_chain_datum_token_t)
                                                                         : *a_token_size;
    dap_chain_datum_token_t *l_token = DAP_NEW_Z_SIZE(dap_chain_datum_token_t, l_token_size);
    if (!l_token) {
        log_it(L_CRITICAL, c_error_memory_alloc);
        return NULL;
    }
    switch (l_token_old->type) {

    case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE: {
        *l_token = (dap_chain_datum_token_t) {
                .type       = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL,
                .subtype    = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE,
                .header_simple.decimals = l_token_old->header_simple.decimals,
        };    
    } break;

    case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL: {
        *l_token = (dap_chain_datum_token_t) {
                .type       = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL,
                .subtype    = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE,
                .header_private_decl.flags          = l_token_old->header_private_decl.flags,
                .header_private_decl.tsd_total_size = l_token_old->header_private_decl.tsd_total_size,
                .header_private_decl.decimals       = l_token_old->header_private_decl.decimals
        };
    } break;

    case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE: {
        *l_token = (dap_chain_datum_token_t) {
                .type       = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE,
                .subtype    = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE,
                .header_private_update.flags            = l_token_old->header_private_update.flags,
                .header_private_update.tsd_total_size   = l_token_old->header_private_update.tsd_total_size,
                .header_private_update.decimals         = l_token_old->header_private_update.decimals
        };
    } break;

    case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL: {
        *l_token = (dap_chain_datum_token_t) {
                .type       = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL,
                .subtype    = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE,
                .header_native_decl.flags           = l_token_old->header_native_decl.flags,
                .header_native_decl.tsd_total_size  = l_token_old->header_native_decl.tsd_total_size,
                .header_native_decl.decimals        = l_token_old->header_native_decl.decimals
        };
    } break;

    case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE: {
        *l_token = (dap_chain_datum_token_t) {
                .type       = DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE,
                .subtype    = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE,
                .header_native_update.flags             = l_token_old->header_native_update.flags,
                .header_native_update.tsd_total_size    = l_token_old->header_native_update.tsd_total_size,
                .header_native_update.decimals          = l_token_old->header_native_update.decimals
        };
    } break;

    case DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC: {
        *l_token = (dap_chain_datum_token_t) {
                .type       = DAP_CHAIN_DATUM_TOKEN_TYPE_DECL,
                .subtype    = DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC,
                .header_public.flags            = l_token_old->header_public.flags,
                .header_public.premine_supply   = l_token_old->header_public.premine_supply,
                .header_public.premine_address  = l_token_old->header_public.premine_address
        };
    } break;

    case DAP_CHAIN_DATUM_TOKEN_TYPE_DECL:
    case DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE:
        if (*a_token_size < sizeof(dap_chain_datum_token_t)) {
            log_it(L_WARNING, "Too small token size %zu", *a_token_size);
            DAP_DELETE(l_token);
            return NULL;
        }
        return memcpy(l_token, a_token_serial, l_token_size);

    default:
        log_it(L_NOTICE, "Unknown token type '%d' read", ((dap_chain_datum_token_t*)a_token_serial)->type);
        DAP_DELETE(l_token);
        return NULL;
    }

    l_token->version = 2;
    l_token->signs_valid = l_token_old->signs_valid;
    l_token->signs_total = l_token_old->signs_total;
    l_token->total_supply = l_token_old->total_supply;
    dap_strncpy(l_token->ticker, l_token_old->ticker, DAP_CHAIN_TICKER_SIZE_MAX);
    if (l_token_tsd_n_signs_size)
        memcpy(l_token->tsd_n_signs, l_token_old->tsd_n_signs, l_token_tsd_n_signs_size);
    *a_token_size = l_token_size;
    return l_token;
}

/**
 * @brief dap_chain_datum_token_flag_from_str
 * @param a_str
 * @return
 */
uint32_t dap_chain_datum_token_flag_from_str(const char *a_str)
{
    if (a_str == NULL)
        return DAP_CHAIN_DATUM_TOKEN_FLAG_NONE;
    for (uint16_t i = 0; i < sizeof(s_flags_table) / sizeof(struct datum_token_flag_struct); i++)
        if (strcmp(s_flags_table[i].key, a_str) == 0)
            return s_flags_table[i].val;
    return DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED;
}

/**
 * @brief dap_chain_datum_token_flags_dump_to_json
 * @param json_obj_out
 * @param a_flags
 */
void dap_chain_datum_token_flags_dump_to_json(json_object * json_obj_out, uint16_t a_flags)
{
    if (!a_flags) {
        json_object_object_add(json_obj_out, "flags", json_object_new_string(dap_chain_datum_token_flag_to_str(DAP_CHAIN_DATUM_TOKEN_FLAG_NONE)));
        return;
    }
    json_object *l_array_flags = json_object_new_array();
    for (uint16_t i = 0; BIT(i) <= DAP_CHAIN_DATUM_TOKEN_FLAG_MAX; i++)
        if (a_flags & BIT(i))
            json_object_array_add(l_array_flags, json_object_new_string(dap_chain_datum_token_flag_to_str(BIT(i))));
    json_object_object_add(json_obj_out, "flags", l_array_flags);
}

/**
 * @brief dap_chain_datum_token_certs_dump
 * @param a_str_out
 * @param a_tsd_n_signs
 * @param a_certs_size
 */
void dap_chain_datum_token_certs_dump(dap_string_t * a_str_out, byte_t * a_tsd_n_signs, size_t a_certs_size, const char *a_hash_out_type)
{
    dap_string_append_printf(a_str_out, "signatures: ");
    if (!a_certs_size) {
        dap_string_append_printf(a_str_out, "<NONE>\n");
        return;
    }

    dap_string_append_printf(a_str_out, "\n");

    size_t l_offset = 0;
    for (int i = 1; l_offset < (a_certs_size); i++) {
        dap_sign_t *l_sign = (dap_sign_t *) (a_tsd_n_signs + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            dap_string_append_printf(a_str_out, "<CORRUPTED - 0 size signature>\n");
            break;
        }

        if (l_sign->header.sign_size > a_certs_size)
        {
            dap_string_append_printf(a_str_out, "<CORRUPTED - signature size is greater than a_certs_size>\n");
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            dap_string_append_printf(a_str_out, "<CORRUPTED - can't calc hash>\n");
            continue;
        }

        const char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                ? dap_enc_base58_encode_hash_to_str_static(&l_pkey_hash)
                : dap_chain_hash_fast_to_str_static(&l_pkey_hash);

        dap_string_append_printf(a_str_out, "%d) %s, %s, %u bytes\n", i, l_hash_str,
                                 dap_sign_type_to_str(l_sign->header.type), l_sign->header.sign_size);
    }
}

/**
 * @brief dap_chain_datum_token_certs_dump_to_json
 * @param a_json_obj_out
 * @param a_tsd_n_signs
 * @param a_certs_size
 */
void dap_chain_datum_token_certs_dump_to_json(json_object *a_json_obj_out, byte_t * a_tsd_n_signs, size_t a_certs_size, const char *a_hash_out_type)
{
    json_object_object_add(a_json_obj_out, "Signatures", json_object_new_string(""));
    if (!a_certs_size) {
        json_object_object_add(a_json_obj_out, "status", json_object_new_string("<NONE>"));
        return;
    }

    size_t l_offset = 0;
    json_object * json_arr_seg = json_object_new_array();
    for (int i = 1; l_offset < (a_certs_size); i++) {
        json_object * l_json_obj_out = json_object_new_object();
        dap_sign_t *l_sign = (dap_sign_t *) (a_tsd_n_signs + l_offset);
        l_offset += dap_sign_get_size(l_sign);
        if (l_sign->header.sign_size == 0) {
            json_object_object_add(l_json_obj_out, "status", json_object_new_string("<CORRUPTED - 0 size signature>"));
            break;
        }

        if (l_sign->header.sign_size > a_certs_size)
        {
            json_object_object_add(l_json_obj_out, "status", json_object_new_string("<CORRUPTED - signature size is greater than a_certs_size>"));
            continue;
        }

        dap_chain_hash_fast_t l_pkey_hash = {0};
        if (dap_sign_get_pkey_hash(l_sign, &l_pkey_hash) == false) {
            json_object_object_add(l_json_obj_out, "status", json_object_new_string("<CORRUPTED - can't calc hash>"));
            continue;
        }

        char *l_hash_str = dap_strcmp(a_hash_out_type, "hex")
                               ? dap_enc_base58_encode_hash_to_str(&l_pkey_hash)
                               : dap_chain_hash_fast_to_str_new(&l_pkey_hash);

        json_object_object_add(l_json_obj_out, "line", json_object_new_int(i));
        json_object_object_add(l_json_obj_out, "hash", json_object_new_string(l_hash_str));
        json_object_object_add(l_json_obj_out, "sign_type", json_object_new_string(dap_sign_type_to_str(l_sign->header.type)));
        json_object_object_add(l_json_obj_out, "bytes", json_object_new_int(l_sign->header.sign_size));
        json_object_array_add(json_arr_seg, l_json_obj_out);
        DAP_DEL_Z(l_hash_str);
    }
    json_object_object_add(a_json_obj_out, "status", json_arr_seg);
}

/*                              Token emission section                          */

dap_chain_datum_token_emission_t *dap_chain_datum_emission_create(uint256_t a_value, const char *a_ticker, dap_chain_addr_t *a_addr)
{
    dap_chain_datum_token_emission_t *l_emission = DAP_NEW_Z(dap_chain_datum_token_emission_t);
    if (!l_emission) {
        log_it(L_CRITICAL, "%s", c_error_memory_alloc);
        return NULL;
    }
    l_emission->hdr.version = 3;
    l_emission->hdr.value = a_value;
    strncpy(l_emission->hdr.ticker, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    l_emission->hdr.type = DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH;
    l_emission->hdr.address = *a_addr;
    dap_uuid_generate_nonce(&l_emission->hdr.nonce, DAP_CHAIN_DATUM_NONCE_SIZE);
    return l_emission;
}

size_t dap_chain_datum_emission_get_size(uint8_t *a_emission_serial)
{
    size_t l_ret = 0;
    dap_chain_datum_token_emission_t *l_emission = (dap_chain_datum_token_emission_t *)a_emission_serial;
    if (l_emission->hdr.version == 0) {
        l_ret = sizeof(struct dap_chain_emission_header_v0);
    } else {
        l_ret = sizeof(l_emission->hdr);
    }
    if (l_emission->hdr.type == DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH) {
        uint64_t l_size = *(uint64_t *)(a_emission_serial + l_ret);
        l_ret += l_size;
    }
    l_ret += sizeof(l_emission->data);
    return l_ret;
}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_read(byte_t *a_emission_serial, size_t *a_emission_size)
{
    const size_t l_old_hdr_size = sizeof(struct dap_chain_emission_header_v0);
    dap_return_val_if_fail(a_emission_serial && a_emission_size && *a_emission_size >= l_old_hdr_size, NULL);

    dap_chain_datum_token_emission_t *l_emission = NULL;
    if (((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.version == 0) {
        size_t l_emission_size = *a_emission_size;
        size_t l_add_size = sizeof(l_emission->hdr) - l_old_hdr_size;
        l_emission = DAP_NEW_Z_SIZE(dap_chain_datum_token_emission_t, l_emission_size + l_add_size);
        if (!l_emission) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return NULL;
        }
        l_emission->hdr.version = 2;
        memcpy(l_emission, a_emission_serial, l_old_hdr_size);
        memcpy((byte_t *)l_emission + sizeof(l_emission->hdr),
               a_emission_serial + l_old_hdr_size,
               (uint32_t)(l_emission_size - l_old_hdr_size));
        l_emission->hdr.value = dap_chain_uint256_from(
                    ((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.value64);
        l_emission_size += l_add_size;
        if (l_emission->hdr.type == DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH)
            l_emission->data.type_auth.tsd_n_signs_size = l_emission_size - sizeof(dap_chain_datum_token_emission_t);
        (*a_emission_size) = l_emission_size;
    } else {
        if (((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.version == 1) {
            l_emission->hdr.value = dap_chain_uint256_from(
                        ((dap_chain_datum_token_emission_t *)a_emission_serial)->hdr.value64);
            l_emission->hdr.version = 2;
        }
        if (*a_emission_size < sizeof(dap_chain_datum_token_emission_t)) {
            log_it(L_WARNING, "Size of emission is %zu, less than header size %zu",
                                        *a_emission_size, sizeof(dap_chain_datum_token_emission_t));
            return NULL;
        }
        l_emission = DAP_DUP_SIZE(a_emission_serial, *a_emission_size);
        if (!l_emission) {
            log_it(L_CRITICAL, "%s", c_error_memory_alloc);
            return NULL;
        }
    }
    return l_emission;
}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_add_tsd(dap_chain_datum_token_emission_t *a_emission, int a_type, size_t a_size, void *a_data)
{
    if (!a_emission || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH)
        return NULL;
    dap_tsd_t *l_tsd = dap_tsd_create(a_type, a_data, a_size);
    size_t l_tsd_size = sizeof(dap_tsd_t) + a_size;
    size_t l_emission_size = dap_chain_datum_emission_get_size((uint8_t *)a_emission);
    dap_chain_datum_token_emission_t *l_emission = DAP_REALLOC(a_emission, l_emission_size + l_tsd_size);
    memcpy(l_emission->tsd_n_signs + l_emission->data.type_auth.tsd_total_size, l_tsd, l_tsd_size);
    DAP_DELETE(l_tsd);
    l_emission->data.type_auth.tsd_total_size += l_tsd_size;
    l_emission->data.type_auth.tsd_n_signs_size += l_tsd_size;
    return l_emission;
}

byte_t *dap_chain_emission_get_tsd(dap_chain_datum_token_emission_t *a_emission, int a_type, size_t *a_size)
{
    if (!a_emission || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH ||
            a_emission->data.type_auth.tsd_total_size == 0)
        return NULL;
    dap_tsd_t *l_tsd = NULL;
    if (!(l_tsd = dap_tsd_find(a_emission->tsd_n_signs, a_emission->data.type_auth.tsd_total_size, a_type))) {
        return NULL;
    } else {
        if (a_size)
            *a_size = l_tsd->size;
    }
    return l_tsd->data;
}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_add_sign(dap_enc_key_t *a_sign_key, dap_chain_datum_token_emission_t *a_emission)
{
    if (!a_emission || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH)
        return NULL;

    size_t l_signs_count = a_emission->data.type_auth.signs_count;
    size_t l_old_signs_size = a_emission->data.type_auth.tsd_n_signs_size;

    if (a_emission->data.type_auth.tsd_n_signs_size > a_emission->data.type_auth.tsd_total_size)
    {
        size_t l_pub_key_size = 0;
        dap_sign_t *l_sign = (dap_sign_t *)(a_emission->tsd_n_signs + a_emission->data.type_auth.tsd_total_size);
        uint8_t *l_pub_key = dap_enc_key_serialize_pub_key(a_sign_key, &l_pub_key_size);
        for (int i = 0; i < a_emission->data.type_auth.signs_count; i++) {
            if (l_sign->header.sign_pkey_size == l_pub_key_size &&
                    !memcmp(l_sign->pkey_n_sign, l_pub_key, l_pub_key_size))
                return a_emission;  // this sign already exists
            l_sign = (dap_sign_t *)((byte_t *)l_sign + dap_sign_get_size(l_sign));
        }
        DAP_DELETE(l_pub_key);
    }
    a_emission->data.type_auth.signs_count = 0;
    a_emission->data.type_auth.tsd_n_signs_size = 0;
    dap_sign_t *l_new_sign = dap_sign_create(a_sign_key, a_emission, sizeof(dap_chain_datum_token_emission_t) + a_emission->data.type_auth.tsd_total_size, 0);
    if (!l_new_sign)
        return NULL;
    size_t l_emission_size = dap_chain_datum_emission_get_size((uint8_t *)a_emission);
    size_t l_sign_size = dap_sign_get_size(l_new_sign);
    dap_chain_datum_token_emission_t *l_ret = DAP_REALLOC(a_emission, l_emission_size + l_old_signs_size + l_sign_size);
    memcpy(l_ret->tsd_n_signs + l_old_signs_size, l_new_sign, l_sign_size);
    DAP_DELETE(l_new_sign);
    l_old_signs_size += l_sign_size;
    l_signs_count++;
    l_ret->data.type_auth.tsd_n_signs_size = l_old_signs_size;
    l_ret->data.type_auth.signs_count = l_signs_count;
    return l_ret;
}

dap_chain_datum_token_emission_t *dap_chain_datum_emission_append_sign(dap_sign_t  *a_sign, dap_chain_datum_token_emission_t *a_emission)
{
    if (!a_emission || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH)
        return NULL;

    if (!a_sign)
        return NULL;

    if (a_emission->data.type_auth.tsd_n_signs_size > a_emission->data.type_auth.tsd_total_size)
    {
        dap_sign_t *l_sign = (dap_sign_t *)(a_emission->tsd_n_signs + a_emission->data.type_auth.tsd_total_size);
        for (int i = 0; i < a_emission->data.type_auth.signs_count; i++) {
            if (l_sign->header.sign_pkey_size == a_sign->header.sign_pkey_size &&
                !memcmp(l_sign->pkey_n_sign, a_sign->pkey_n_sign, l_sign->header.sign_pkey_size)) {

                log_it(L_ERROR, "such singature present");
                return a_emission;  // this sign already exists
            }
            l_sign = (dap_sign_t *)((byte_t *)l_sign + dap_sign_get_size(l_sign));
        }
    }

    size_t l_emission_size = dap_chain_datum_emission_get_size((uint8_t *)a_emission);
    dap_chain_datum_token_emission_t *l_ret = DAP_REALLOC(a_emission, l_emission_size + dap_sign_get_size(a_sign));
    size_t l_sign_size = dap_sign_get_size(a_sign);
    memcpy(l_ret->tsd_n_signs + l_ret->data.type_auth.tsd_n_signs_size, a_sign, l_sign_size);
    
    l_ret->data.type_auth.tsd_n_signs_size += l_sign_size;
    l_ret->data.type_auth.signs_count++;
    return l_ret;
}


dap_sign_t *dap_chain_datum_emission_get_signs(dap_chain_datum_token_emission_t *a_emission, size_t *a_signs_count) {
    if (!a_emission || !a_signs_count || a_emission->hdr.type != DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH) {
        log_it(L_ERROR, "Parameters must be not-null!");
        return NULL;
    }
    if (!a_emission->data.type_auth.signs_count || a_emission->data.type_auth.tsd_n_signs_size <= a_emission->data.type_auth.tsd_total_size) {
        *a_signs_count = 0;
        log_it(L_INFO, "No signes found");
        return NULL;
    }
    size_t l_expected_size = a_emission->data.type_auth.tsd_n_signs_size - a_emission->data.type_auth.tsd_total_size, l_actual_size = 0;
    /* First sign */
    dap_sign_t *l_sign = (dap_sign_t*)(a_emission->tsd_n_signs + a_emission->data.type_auth.tsd_total_size);
    size_t l_count, l_sign_size;
    for (l_count = 0, l_sign_size = 0; l_count < a_emission->data.type_auth.signs_count && (l_sign_size = dap_sign_get_size(l_sign)); ++l_count) {
        if (!dap_sign_verify_size(l_sign, l_sign_size)) {
            break;
        }
        l_actual_size += l_sign_size;
        l_sign = (dap_sign_t *)((byte_t *)l_sign + l_sign_size);
    }
    if ((l_expected_size != l_actual_size) || (l_count < a_emission->data.type_auth.signs_count)) {
        log_it(L_CRITICAL, "Malformed signs, only %lu of %hu are present (%lu != %lu)", l_count, a_emission->data.type_auth.signs_count,
               l_actual_size, l_expected_size);
    }
    dap_sign_t *l_ret = DAP_NEW_Z_SIZE(dap_sign_t, l_actual_size);
    if (!l_ret) {
        log_it(L_CRITICAL, "Out of memory!");
        return NULL;
    }
    *a_signs_count = dap_min(l_count, a_emission->data.type_auth.signs_count);
    memcpy(l_ret, a_emission->tsd_n_signs + a_emission->data.type_auth.tsd_total_size, l_actual_size);
    return l_ret;
}

