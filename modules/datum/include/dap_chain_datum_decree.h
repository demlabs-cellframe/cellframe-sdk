/*
 * Authors:
 * Frolov Daniil <daniil.frolov@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Copyright  (c) 2020, All rights reserved.

 This file is part of CellFrame SDK the open source project

    CellFrame SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    CellFrame SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any CellFrame SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once

#include "dap_chain_common.h"
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_time.h"
#include "dap_list.h"
#include "dap_cert.h"
#include <stdint.h>

#define DAP_CHAIN_DATUM_DECREE_VERSION  0

// Governance decree
typedef struct dap_chain_datum_decree {
    uint16_t decree_version;
    struct {
        dap_time_t ts_created;
        uint16_t type;
        union {
            dap_chain_srv_uid_t srv_id;
            struct {
                dap_chain_net_id_t net_id;
                dap_chain_id_t chain_id;
                dap_chain_cell_id_t cell_id;
            } DAP_ALIGN_PACKED common_decree_params;
        } DAP_ALIGN_PACKED;
        uint16_t sub_type;
        uint32_t data_size;
        uint32_t signs_size;
    } DAP_ALIGN_PACKED header;
    byte_t data_n_signs[];
} DAP_ALIGN_PACKED dap_chain_datum_decree_t;

DAP_STATIC_INLINE size_t dap_chain_datum_decree_get_size(dap_chain_datum_decree_t *a_datum_decree)
{
    return sizeof(*a_datum_decree) + a_datum_decree->header.data_size + a_datum_decree->header.signs_size;
}

// Decree types
#define DAP_CHAIN_DATUM_DECREE_TYPE_COMMON                                  0x0001
#define DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE                                 0x0002

// Common decree subtypes
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE                           0x0001
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS                        0x0002
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN                    0x0003
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE                 0x0005
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE              0x0006
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE               0x0007
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT    0x0008
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN                           0x0009
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN                         0x000A
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD                        0x000B
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT                    0x000C
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS          0x000D
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE         0x000E
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK                      0x000F
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE             0x0010 

// DECREE TSD types
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE                               0x0100
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN                                0x0101
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE                                 0x0102
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER                               0x0103
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER                           0x0104
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET                          0x0106
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH                                0x0107
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE                         0x0108
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR                  0x0109
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR                           0x0110
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE                     0x0111
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT             0x0112
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST                                0x0113
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING                              0x0115
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_ACTION                              0x010A
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGNATURE_TYPE                      0x010B
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCK_NUM                           0x010C
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_PKEY                          0x010D 


#ifdef __cplusplus
extern "C" {
#endif


DAP_STATIC_INLINE const char *dap_chain_datum_decree_subtype_to_str(uint16_t a_decree_subtype)
{
    switch(a_decree_subtype) {
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE:
        return "DECREE_COMMON_SUBTYPE_FEE";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS:
        return "DECREE_COMMON_SUBTYPE_OWNERS";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN:
        return "DECREE_COMMON_SUBTYPE_OWNERS_MIN";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE:
        return "DECREE_COMMON_SUBTYPE_STAKE_APPROVE";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE:
        return "DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE:
        return "DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT:
        return "COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN:
        return "DECREE_COMMON_SUBTYPE_BAN";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN:
        return "DECREE_COMMON_SUBTYPE_UNBAN";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD:
        return "DECREE_COMMON_SUBTYPE_REWARD";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT:
        return "DECREE_COMMON_SUBTYPE_VALIDATOR_MAX_WEIGHT";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS:
        return "DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE:
        return "DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE:
        return "DECREE_COMMON_SUBTYPE_STAKE_UPDATE";
    case DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK:
        return "DECREE_COMMON_SUBTYPE_HARDFORK";
    default:
        return "DECREE_SUBTYPE_UNKNOWN";
    }
}

DAP_STATIC_INLINE uint16_t dap_chain_datum_decree_type_from_str(const char *a_decree_type)
{
    if (!dap_strcmp(a_decree_type, "fee")){
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE;
    } else if (!dap_strcmp(a_decree_type, "owners")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS;
    } else if (!dap_strcmp(a_decree_type, "owners_min")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN;
    } else if (!dap_strcmp(a_decree_type, "stake_approve")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE;
    } else if (!dap_strcmp(a_decree_type, "stake_invalidate")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE;
    } else if (!dap_strcmp(a_decree_type, "min_value")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE;
    } else if (!dap_strcmp(a_decree_type, "min_validators_count")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT;
    } else if (!dap_strcmp(a_decree_type, "ban")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_BAN;
    } else if (!dap_strcmp(a_decree_type, "unban")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_UNBAN;
    } else if (!dap_strcmp(a_decree_type, "reward")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_REWARD;
    } else if (!dap_strcmp(a_decree_type, "validator_max_weight")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_MAX_WEIGHT;
    } else if (!dap_strcmp(a_decree_type, "emergency_validators")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_EMERGENCY_VALIDATORS;
    } else if (!dap_strcmp(a_decree_type, "check_signs_structure")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_CHECK_SIGNS_STRUCTURE;
    } else if (!dap_strcmp(a_decree_type, "stake_update")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_PKEY_UPDATE;
    } else if (!dap_strcmp(a_decree_type, "hardfork_prepare")) {
        return DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_HARDFORK;
    } else {
        return 0;
    }
}

DAP_STATIC_INLINE const char *dap_chain_datum_decree_tsd_type_to_str(uint16_t a_decree_tsd_type) {
    switch (a_decree_tsd_type) {
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_VALUE";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HASH";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_NODE_ADDR";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_HOST";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING:
        return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STRING";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_ACTION:
         return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_ACTION";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGNATURE_TYPE:
         return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGNATURE_TYPE";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_PKEY:
         return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_PKEY";
    case DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCK_NUM:
         return "DAP_CHAIN_DATUM_DECREE_TSD_TYPE_BLOCK_NUM";
    default:
        return "DECREE_TSD_TYPE_UNKNOWN";
    }
}

dap_chain_datum_decree_t *dap_chain_datum_decree_new(dap_chain_net_id_t a_net_id, dap_chain_id_t a_chain_id,
                                                     dap_chain_cell_id_t a_cell_id, size_t a_total_tsd_size);
/**
 * @brief dap_chain_datum_decree_get_signs
 * @param decree pointer to decree
 * @param num_of_signs pointer to num of signs buffer. Total
 *                      number of signs will be write to this buffer
 * @return pointer to signs
 */
dap_sign_t *dap_chain_datum_decree_get_signs(dap_chain_datum_decree_t *decree, size_t *size_of_signs);

/**
 * @brief dap_chain_datum_decree_get_fee gets fee value from decree
 * @param a_decree pointer to decree
 * @param a_fee_value pointer to fee value buffer
 * @return result code
 */
int dap_chain_datum_decree_get_fee(dap_chain_datum_decree_t *a_decree, uint256_t *a_fee_value);

/**
 * @brief dap_chain_datum_decree_get_fee gets fee wallet from decree
 * @param a_decree pointer to decree
 * @param a_fee_value pointer to fee wallet addr buffer
 * @return result code
 */
int dap_chain_datum_decree_get_fee_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_fee_wallet);

/**
 * @brief dap_chain_datum_decree_get_owners get list of owners certificates
 * @param a_decree pointer to decree
 * @param a_owners_num pointer to total number of owners buffer
 * @return dap_list_t with owners keys in dap_pkey_t format
 */
dap_list_t *dap_chain_datum_decree_get_owners(dap_chain_datum_decree_t *a_decree, uint16_t *a_owners_num);

/**
 * @brief dap_chain_datum_decree_get_min_owners get minimum number of owners
 * @param a_decree pointer to decree
 * @param a_owners_num pointer to minimum number of owners buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_min_owners(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_owners_num);

/**
 * @brief dap_chain_datum_decree_get_tx_hash get stake tx hash
 * @param a_decree pointer to decree
 * @param a_tx_hash pointer to tx hash buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_hash(dap_chain_datum_decree_t *a_decree, dap_hash_fast_t *a_tx_hash);

/**
 * @brief dap_chain_datum_decree_get_stake_value get stake value
 * @param a_decree pointer to decree
 * @param a_stake_value pointer to stake value buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_stake_value);


/**
 * @brief dap_chain_datum_decree_get_stake_value get stake value
 * @param a_decree pointer to decree
 * @param a_stake_value pointer to stake value buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_value);

/**
 * @brief dap_chain_datum_decree_get_stake_signing_addr get signing address
 * @param a_decree pointer to decree
 * @param a_signing_addr pointer to signing address buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_signing_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_signing_addr);

/**
 * @brief dap_chain_datum_decree_get_node_addr get signer node address
 * @param a_decree pointer to decree
 * @param a_node_addr pointer to signer node address buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_node_addr(dap_chain_datum_decree_t *a_decree, dap_chain_node_addr_t *a_node_addr);

/**
 * @brief dap_chain_datum_decree_get_stake_min_value get minimum stake value
 * @param a_decree pointer to decree
 * @param a_min_value pointer to min stake value buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_min_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_value);

/**
 * @brief dap_chain_datum_decree_get_stake_min_signers_count get minimum signers count
 * @param a_decree pointer to decree
 * @param a_min_signers_count pointer to min signer count buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_min_signers_count(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_signers_count);
int dap_chain_datum_decree_get_action(dap_chain_datum_decree_t *a_decree, uint8_t *a_action);
int dap_chain_datum_decree_get_signature_type(dap_chain_datum_decree_t *a_decree, uint32_t *a_signature_type);
int dap_chain_datum_decree_get_ban_addr(dap_chain_datum_decree_t *a_decree, const char **a_addr);
dap_pkey_t *dap_chain_datum_decree_get_pkey(dap_chain_datum_decree_t *a_decree);
int dap_chain_datum_decree_get_atom_num(dap_chain_datum_decree_t *a_decree, uint64_t *a_atom_num);

/**
 * @breif dap_chain_datum_decree_dump Dump information about decree
 * @param a_str_out pointer to output text buffer
 * @param a_decree pointer to decree
 * @param a_decree_size size data
 * @param a_hash_out_type
 */
void dap_chain_datum_decree_dump(dap_string_t *a_str_out, dap_chain_datum_decree_t *a_decree, size_t a_decree_size, const char *a_hash_out_type);

/**
 * @breif dap_chain_datum_decree_dump Dump information about decree
 * @param a_obj_out pointer to output json object
 * @param a_decree pointer to decree
 * @param a_decree_size size data
 * @param a_hash_out_type
 */
void dap_chain_datum_decree_dump_json(json_object  *a_obj_out, dap_chain_datum_decree_t *a_decree, size_t a_decree_size, const char *a_hash_out_type);

/**
 * @brief dap_chain_datum_decree_certs_dump compose decree signatures output string
 * @param a_str_out pointer to output text buffer
 * @param a_tsd_n_signs pointer to signs decree section
 * @param a_certs_size size of decree signatures
 */
void dap_chain_datum_decree_certs_dump(dap_string_t * a_str_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type);

void dap_chain_datum_decree_certs_dump_json(json_object * a_json_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type);

/**
 * @brief dap_chain_datum_decree_sign_in_cycle
 * sign data (datum_decree) by certificates (1 or more)
 * successful count of signes return in l_sign_counter
 * @param l_certs - array with certificates loaded from dcert file
 * @param l_datum_token - updated pointer for l_datum_token variable after realloc
 * @param l_certs_count - count of certificate
 * @param l_datum_data_offset - offset of datum
 * @param l_sign_counter - counter of successful data signing operation
 * @return dap_chain_datum_token_t*
 */
dap_chain_datum_decree_t* dap_chain_datum_decree_sign_in_cycle(dap_cert_t ** a_certs, dap_chain_datum_decree_t *a_datum_decree,
                                                  size_t a_certs_count, size_t *a_total_sign_count);


#ifdef __cplusplus
}
#endif