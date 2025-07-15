/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
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

#include <string.h>
#include <ctype.h>
#include <errno.h>
#ifdef DAP_OS_WINDOWS
#include <time.h>
#endif
#include "dap_chain_common.h"
#include "dap_chain_net.h"
#include "dap_chain_ledger.h"
#include "dap_chain_datum_tx_items.h"
#include "dap_global_db.h"
#include "dap_chain_datum.h"
#include "json.h"
#include "dap_enc_base58.h"

#define LOG_TAG "dap_chain_common"

const dap_chain_net_srv_uid_t c_dap_chain_net_srv_uid_null = {0};
const dap_chain_cell_id_t c_dap_chain_cell_id_null = {0};
const dap_chain_addr_t c_dap_chain_addr_blank = {0};

/**
 * @brief dap_chain_hash_to_str
 * @param a_hash
 * @param a_str
 * @param a_str_max
 * @return
 */
size_t dap_chain_hash_slow_to_str( dap_chain_hash_slow_t *a_hash, char *a_str, size_t a_str_max )
{
    const size_t c_hash_str_size = sizeof(*a_hash) * 2 + 1 /*trailing zero*/+ 2 /* heading 0x */;

    if (a_str_max < c_hash_str_size) {
        log_it(L_ERROR, "String for hash too small, need %zu but have only %zu", c_hash_str_size, a_str_max);
        return 0;
    }
    size_t i;
    dap_strncpy(a_str, "0x", 2);
    size_t l_pos = 2;
    for (i = 0; i < sizeof(a_hash->raw) && l_pos <= a_str_max; ++i)
        l_pos += snprintf( a_str + i * 2 + 2, a_str_max - l_pos, "%02x", a_hash->raw[i] );

    return strlen(a_str);
}

/**
 * @brief dap_chain_addr_to_str_static
 * @param a_addr
 * @return
 */
dap_chain_addr_str_t dap_chain_addr_to_str_static_(const dap_chain_addr_t *a_addr)
{
    dap_return_val_if_pass(!a_addr, (dap_chain_addr_str_t){ "null" });
    dap_chain_addr_str_t res;
    if (dap_chain_addr_is_blank(a_addr))
        return strcpy((char*)&res, "null"), res;
    dap_enc_base58_encode(a_addr, sizeof(dap_chain_addr_t), (char*)&res);
    return res;
}

/**
 * @brief s_addr_from_str
 * @param [out] a_addr - pointer to addr fill
 * @param [in] a_str - string with one addr
 * @return 0 if pass, other if error
 */
static int s_addr_from_str(dap_chain_addr_t *a_addr, const char *a_str)
{
    dap_return_val_if_pass(!a_addr || !a_str || !a_str[0], -1);
    if (!dap_strcmp(a_str, "null") || !dap_strcmp(a_str, "0")) {
        memset(a_addr, 0, sizeof(dap_chain_addr_t));
        return 0;
    }
    int l_ret = 0;
    size_t l_ret_size = DAP_ENC_BASE58_DECODE_SIZE(strlen(a_str));
    dap_chain_addr_t *l_addr_cur = DAP_NEW_Z_SIZE_RET_VAL_IF_FAIL(dap_chain_addr_t, l_ret_size, -2);
    if (dap_enc_base58_decode(a_str, l_addr_cur) == sizeof(dap_chain_addr_t) && !dap_chain_addr_check_sum(l_addr_cur)) {
        memcpy(a_addr, l_addr_cur, sizeof(dap_chain_addr_t));
    } else {
        l_ret = -3;
    }
    DAP_DELETE(l_addr_cur);
    return l_ret;
}

/**
 * @brief dap_chain_str_to_addr
 * @param a_str - string with one addr
 * @return pointer to dap_chain_addr_t if pass, if not - NULL
 */
dap_chain_addr_t *dap_chain_addr_from_str(const char *a_str)
{
    dap_chain_addr_t *l_ret = DAP_NEW_Z_RET_VAL_IF_FAIL(dap_chain_addr_t, NULL);
    if (s_addr_from_str(l_ret, a_str)) {
        DAP_DELETE(l_ret);
        return NULL;
    }
    return l_ret;
}


/**
 * @brief parce addrs string div by ',', alloc memory to addrs
 * @param a_addr_str - ddrs string div by ','
 * @param a_addr - pointer to memory alloc
 * @return addr count
 */
size_t dap_chain_addr_from_str_array(const char *a_addr_str, dap_chain_addr_t **a_addr)
{
    dap_return_val_if_pass(!a_addr_str || !a_addr, 0);
    size_t l_count = dap_str_symbol_count(a_addr_str, ',') + 1;
    dap_chain_addr_t *l_addr = DAP_NEW_Z_COUNT_RET_VAL_IF_FAIL(dap_chain_addr_t, l_count, 0);
    char **l_addr_str_array = dap_strsplit(a_addr_str, ",", l_count);
    if (!l_addr_str_array) {
        DAP_DELETE(l_addr);
        return 0;
    }
    for (size_t i = 0; i < l_count; ++i) {
        if (s_addr_from_str(l_addr + i, l_addr_str_array[i])) {
            DAP_DELETE(l_addr);
            dap_strfreev(l_addr_str_array);
            return 0;
        }
    }
    dap_strfreev(l_addr_str_array);
    *a_addr = l_addr;
    return l_count;
}

bool dap_chain_addr_is_blank(const dap_chain_addr_t *a_addr)
{
    return dap_chain_addr_compare(a_addr, &c_dap_chain_addr_blank);
}

/**
 * @brief dap_chain_net_srv_uid_from_str
 * @param a_net_str
 * @return
 */
dap_chain_net_srv_uid_t dap_chain_net_srv_uid_from_str( const char * a_net_srv_uid_str)
{
    dap_chain_net_srv_uid_t l_ret={{0}};
    size_t l_net_srv_uid_str_len = strlen( a_net_srv_uid_str);
    if (l_net_srv_uid_str_len >2){
        a_net_srv_uid_str+=2;
        l_net_srv_uid_str_len-=2;
        if (l_net_srv_uid_str_len == sizeof (l_ret)/2 ){
            size_t l_pos =0;
            char l_byte[3];
            while(l_net_srv_uid_str_len){

                // Copy two characters for bytes
                memcpy(l_byte,a_net_srv_uid_str,2);
                l_byte[2]='\0';

                // Read byte chars
                unsigned int l_bytechar;
                if ( sscanf(l_byte,"%02x", &l_bytechar) != 1)
                    if( sscanf(l_byte,"%02X", &l_bytechar) != 1 )
                        break;
                l_ret.raw[l_pos] = l_bytechar;
                // Update pos
                l_pos++;
                // Reduce in two steps to not to break if input will have bad input
                l_net_srv_uid_str_len-=1;
                if(l_net_srv_uid_str_len)
                    l_net_srv_uid_str_len-=1;
            }
        }else
            log_it(L_WARNING,"Wrong input string \"%s\" not recognized as network id", a_net_srv_uid_str);
    }
    return  l_ret;
}



/**
 * @brief dap_chain_addr_fill_from_key
 * @param a_addr
 * @param a_key
 * @param a_net_id
 * @return
 */
int dap_chain_addr_fill_from_key(dap_chain_addr_t *a_addr, dap_enc_key_t *a_key, dap_chain_net_id_t a_net_id)
{
    dap_sign_type_t l_type = dap_sign_type_from_key_type(a_key->type);
    size_t l_pub_key_data_size;
    uint8_t *l_pub_key_data = dap_enc_key_serialize_pub_key(a_key, &l_pub_key_data_size);
    if (!l_pub_key_data) {
        log_it(L_ERROR,"Can't fill address from key, its empty");
        return -1;
    }
    dap_chain_hash_fast_t l_hash_public_key;
    // serialized key -> key hash
    dap_hash_fast(l_pub_key_data, l_pub_key_data_size, &l_hash_public_key);
    dap_chain_addr_fill(a_addr, l_type, &l_hash_public_key, a_net_id);
    DAP_DELETE(l_pub_key_data);
    return 0;
}

int dap_chain_addr_fill_from_sign(dap_chain_addr_t *a_addr, dap_sign_t *a_sign, dap_chain_net_id_t a_net_id)
{
    dap_hash_fast_t l_sign_pkey_hash;
    if (!dap_sign_get_pkey_hash(a_sign, &l_sign_pkey_hash))
        return -1;
    dap_chain_addr_fill(a_addr, a_sign->header.type, &l_sign_pkey_hash, a_net_id);
    return 0;
}

/**
 * @brief dap_chain_addr_fill
 * @param a_addr
 * @param a_type
 * @param a_pkey_hash
 * @param a_net_id
 * @return
 */
void dap_chain_addr_fill(dap_chain_addr_t *a_addr, dap_sign_type_t a_type, dap_chain_hash_fast_t *a_pkey_hash, dap_chain_net_id_t a_net_id)
{
    if(!a_addr || !a_pkey_hash)
        return;
    a_addr->addr_ver = DAP_CHAIN_ADDR_VERSION_CURRENT;
    a_addr->net_id.uint64 = a_net_id.uint64;
    a_addr->sig_type.raw = a_type.raw;
    memcpy(a_addr->data.hash, a_pkey_hash, sizeof(dap_chain_hash_fast_t));
    // calc checksum
    dap_hash_fast(a_addr, sizeof(dap_chain_addr_t) - sizeof(dap_chain_hash_fast_t), &a_addr->checksum);
}

/**
 * @brief dap_chain_addr_check_sum
 * @param a_addr
 * @return 0 - Ok, otherwise - Invalid a_addr or checksum
 */
int dap_chain_addr_check_sum(const dap_chain_addr_t *a_addr)
{
    if(!a_addr)
        return -1;
    if (dap_chain_addr_is_blank(a_addr))
        return 0;
    dap_chain_hash_fast_t l_checksum;
    // calc checksum
    dap_hash_fast(a_addr, sizeof(dap_chain_addr_t) - sizeof(dap_chain_hash_fast_t), &l_checksum);
    return memcmp(a_addr->checksum.raw, l_checksum.raw, sizeof(l_checksum.raw));
}

void dap_chain_set_offset_limit_json(json_object * a_json_obj_out, size_t *a_start, size_t *a_and, size_t a_limit, size_t a_offset, size_t a_and_count, bool a_last)
{
    json_object* json_obj_lim = json_object_new_object();
    *a_and = a_and_count;
    if (a_offset > 0) {
        if ((a_last) && (a_and_count > a_offset)) {
            *a_and = a_and_count - a_offset;
        } else {
            *a_start = a_offset;
        }
        json_object_object_add(json_obj_lim, "offset", json_object_new_uint64(a_offset));
    }
    if (a_limit > 0) {
        if (a_last && (a_and_count > a_limit)) {
            *a_start = *a_and - a_limit;            
        }
        else {
            *a_and = *a_start + a_limit;
        }
        json_object_object_add(json_obj_lim, "limit", json_object_new_uint64(a_limit));
    }
    else
        json_object_object_add(json_obj_lim, "limit", json_object_new_string("unlimit"));
    json_object_array_add(a_json_obj_out, json_obj_lim);
}



/**
 * @brief Write filtered datum (transaction) to GDB if it matches type DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED and public key
 * 
 * This function checks if the provided transaction:
 * - Has conditional output of type DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED
 * - Contains the specified public key hash in its signatures (TX_ITEM_TYPE_SIG)
 * 
 * If both conditions are met, the transaction is written to the specified GDB group as datum.
 * 
 * @param a_tx - transaction to check and potentially write
 * @param a_pkey_hash - public key hash to filter by (must match signature public key hash)
 * @param a_gdb_group - GDB group name to write filtered datum to
 * @return 1 if datum written, 0 if not matching criteria, negative value on error:
 *         -1: invalid arguments
 *         -2: failed to create datum from transaction
 *         -3: failed to write to GDB
 * 
 * @example
 * // Example usage during chain loading:
 * dap_hash_fast_t l_pkey_hash;
 * dap_chain_hash_fast_from_str("0x1234567890abcdef...", &l_pkey_hash);
 * int l_result = dap_chain_write_wallet_shared_datum_by_pkey(l_tx, &l_pkey_hash, "filtered.wallet_shared");
 * if (l_result == 1) {
 *     log_it(L_INFO, "Wallet shared datum written");
 * }
 */
int dap_chain_write_wallet_shared_datum_by_pkey(dap_chain_datum_tx_t *a_tx, const dap_hash_fast_t *a_pkey_hash, const char *a_gdb_group)
{
	dap_return_val_if_fail(a_tx && a_pkey_hash && a_gdb_group, -1);
	
	// Check if transaction has wallet shared condition output
	int l_out_idx = 0;
	dap_chain_tx_out_cond_t *l_cond_out = dap_chain_datum_tx_out_cond_get(a_tx, 
		DAP_CHAIN_TX_OUT_COND_SUBTYPE_WALLET_SHARED, &l_out_idx);
	
	if (!l_cond_out)
		return 0; // Transaction doesn't have wallet shared condition output
		
	// Check if transaction contains our public key hash in signatures
	bool l_pkey_found = false;
	
	// Parse transaction signatures to find public key hashes
	byte_t *l_item;
	size_t l_item_size;
	TX_ITEM_ITER_TX(l_item, l_item_size, a_tx) {
		if (*l_item == TX_ITEM_TYPE_SIG) {
			dap_chain_tx_sig_t *l_tx_sig = (dap_chain_tx_sig_t *)l_item;
			dap_sign_t *l_sign = dap_chain_datum_tx_item_sign_get_sig(l_tx_sig);
			if (l_sign) {
				dap_hash_fast_t l_current_pkey_hash;
				if (dap_sign_get_pkey_hash(l_sign, &l_current_pkey_hash)) {
                    log_it(L_DEBUG, "l_current_pkey_hash: %s", dap_hash_fast_to_str_static(&l_current_pkey_hash));
					if (dap_hash_fast_compare(a_pkey_hash, &l_current_pkey_hash)) {
						l_pkey_found = true;
						break; // Found matching public key hash, stop searching
					}
				}
			}
		}
	}
	
	if (!l_pkey_found)
		return 0; // Transaction doesn't contain the specified public key
	
	// Create datum from transaction
	size_t l_tx_size = dap_chain_datum_tx_get_size(a_tx);
	dap_chain_datum_t *l_datum = dap_chain_datum_create(DAP_CHAIN_DATUM_TX, a_tx, l_tx_size);
	if (!l_datum) {
		log_it(L_ERROR, "Failed to create datum from transaction");
		return -2;
	}
	
	// Calculate datum hash for key
	dap_chain_hash_fast_t l_datum_hash;
	dap_chain_datum_calc_hash(l_datum, &l_datum_hash);
	char *l_datum_hash_str = dap_chain_hash_fast_to_str_new(&l_datum_hash);
	
	// Write datum to GDB
	int l_res = dap_global_db_set_sync(a_gdb_group, l_datum_hash_str, 
		l_datum, dap_chain_datum_size(l_datum), false);
	
	if (l_res == DAP_GLOBAL_DB_RC_SUCCESS) {
		log_it(L_NOTICE, "Wallet shared datum %s written to GDB group %s", 
			l_datum_hash_str, a_gdb_group);
		DAP_DELETE(l_datum_hash_str);
		DAP_DELETE(l_datum);
		return 1; // Successfully written
	} else {
		log_it(L_WARNING, "Failed to write wallet shared datum %s to GDB group %s, code %d", 
			l_datum_hash_str, a_gdb_group, l_res);
		DAP_DELETE(l_datum_hash_str);
		DAP_DELETE(l_datum);
		return -3; // Failed to write
	}
}

