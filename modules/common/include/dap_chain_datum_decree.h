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
#include "dap_tsd.h"
#include <stdint.h>

#define DAP_CHAIN_DATUM_DECREE_VERSION  0

// Governance decree
typedef struct dap_chain_datum_decree {
    uint16_t decree_version;
    struct {
        dap_time_t ts_created;
        uint16_t type;
        union {
            dap_chain_net_srv_uid_t srv_id;
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
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_TON_SIGNERS_MIN               0x0004
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_APPROVE                 0x0005
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_INVALIDATE              0x0006
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALUE               0x0007
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_STAKE_MIN_VALIDATORS_COUNT    0x0008

// DECREE TSD types
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN                                0x0101
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE                                 0x0102
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER                               0x0103
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER                           0x0104
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE_WALLET                          0x0106
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_TX_HASH                       0x0107
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_VALUE                         0x0108
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNING_ADDR                  0x0109
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_SIGNER_NODE_ADDR              0x0110
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_VALUE                     0x0111
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_STAKE_MIN_SIGNERS_COUNT             0x0112

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
int dap_chain_datum_decree_get_min_owners(dap_chain_datum_decree_t *a_decree, uint16_t *a_min_owners_num);

/**
 * @brief dap_chain_datum_decree_get_tx_hash get stake tx hash
 * @param a_decree pointer to decree
 * @param a_tx_hash pointer to tx hash buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_tx_hash(dap_chain_datum_decree_t *a_decree, dap_hash_fast_t *a_tx_hash);

/**
 * @brief dap_chain_datum_decree_get_stake_value get stake value
 * @param a_decree pointer to decree
 * @param a_stake_value pointer to stake value buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_value(dap_chain_datum_decree_t *a_decree, uint256_t *a_stake_value);

/**
 * @brief dap_chain_datum_decree_get_stake_signing_addr get signing address
 * @param a_decree pointer to decree
 * @param a_signing_addr pointer to signing address buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_signing_addr(dap_chain_datum_decree_t *a_decree, dap_chain_addr_t *a_signing_addr);

/**
 * @brief dap_chain_datum_decree_get_stake_signer_node_addr get signer node address
 * @param a_decree pointer to decree
 * @param a_node_addr pointer to signer node address buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_stake_signer_node_addr(dap_chain_datum_decree_t *a_decree, dap_chain_node_addr_t *a_node_addr);

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

/**
 * @brief dap_chain_datum_decree_certs_dump compose decree signatures output string
 * @param a_str_out pointer to output text buffer
 * @param a_data_n_tsd pointer to signs decree section
 * @param a_certs_size size of decree signatures
 */
void dap_chain_datum_decree_certs_dump(dap_string_t * a_str_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type);
