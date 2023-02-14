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

// Decree types
#define DAP_CHAIN_DATUM_DECREE_TYPE_COMMON                      0x0001
#define DAP_CHAIN_DATUM_DECREE_TYPE_SERVICE                     0x0002

// Action on the decree
// Create from scratch, reset all previous values
#define DAP_CHAIN_DATUM_DECREE_ACTION_CREATE                    0x0001
#define DAP_CHAIN_DATUM_DECREE_ACTION_UPDATE                    0x0002
#define DAP_CHAIN_DATUM_DECREE_ACTION_DELETE                    0x0003

// Common decree subtypes
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_FEE               0x0001
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS            0x0002
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_OWNERS_MIN        0x0003
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_TON_SIGNERS       0x0004
#define DAP_CHAIN_DATUM_DECREE_COMMON_SUBTYPE_TON_SIGNERS_MIN   0x0005

// DECREE TSD types
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_SIGN                    0x0001
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_FEE                     0x0002
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_OWNER                   0x0003
#define DAP_CHAIN_DATUM_DECREE_TSD_TYPE_MIN_OWNER               0x0004
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
 * @brief dap_chain_datum_decree_get_owners get list of owners certificates
 * @param a_decree pointer to decree
 * @param a_owners_num pointer to total number of owners buffer
 * @return dap_list_t with owners keys in dap_pkey_t format
 */
dap_list_t *dap_chain_datum_decree_get_owners(dap_chain_datum_decree_t *a_decree, uint256_t *a_owners_num);

/**
 * @brief dap_chain_datum_decree_get_min_owners get minimum number of owners
 * @param a_decree pointer to decree
 * @param a_owners_num pointer to minimum number of owners buffer
 * @return result code. 0 - success
 */
int dap_chain_datum_decree_get_min_owners(dap_chain_datum_decree_t *a_decree, uint256_t *a_min_owners_num);

/**
 * @brief dap_chain_datum_decree_certs_dump compose decree signatures output string
 * @param a_str_out pointer to output text buffer
 * @param a_data_n_tsd pointer to signs decree section
 * @param a_certs_size size of decree signatures
 */
void dap_chain_datum_decree_certs_dump(dap_string_t * a_str_out, byte_t * a_signs, size_t a_certs_size, const char *a_hash_out_type);
