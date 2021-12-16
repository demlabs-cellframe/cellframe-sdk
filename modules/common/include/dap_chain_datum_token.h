/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * CellFrame       https://cellframe.net
 * Sources         https://gitlab.demlabs.net/cellframe
 * Copyright  (c) 2017-2019
 * All rights reserved.

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
#include "dap_hash.h"
#include "dap_sign.h"

#include "dap_string.h"
#include "dap_tsd.h"
#include "dap_strfuncs.h"

// Token declaration
typedef struct dap_chain_datum_token{
    uint16_t type;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    union {
        // Simple private token declaration. Useful for 100% premined emission without any plays with token and owners after that
        struct {
            uint64_t total_supply; // Could be zero if unlimited
            uint16_t signs_valid; // Emission auth signs
            uint16_t signs_total; // Emission auth signs
        } DAP_ALIGN_PACKED header_private;
        // Private token declarations, with flags, manipulations and updates
        struct {
            uint16_t flags; // Token declaration flags
            size_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
        } DAP_ALIGN_PACKED header_private_decl;
        // Private token update
        struct {
            uint16_t padding;
            size_t tsd_total_size; // Data size section with extended values in key-length-value list.
        } DAP_ALIGN_PACKED header_private_update;
        // Public token declaration
        struct {
            uint128_t total_supply;
            uint128_t premine_supply;
            dap_chain_addr_t premine_address;
            uint32_t flags;
        } DAP_ALIGN_PACKED header_public;
    };
    byte_t data_n_tsd[]; // Signs and/or types-size-data sections
} DAP_ALIGN_PACKED dap_chain_datum_token_t;

// Token declaration type
// Simple private token decl
#define DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE        0x0001
// Extended declaration of privatetoken with in-time control
#define DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL   0x0002
// Token update
#define DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE 0x0003
// Open token with now ownership
#define DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC          0x0004


// Macros for token flags
/// ------- Global section flags --------
// No any flags
#define DAP_CHAIN_DATUM_TOKEN_FLAG_NONE                                    0x0000
// Blocked all permissions, usefull issue it by default and then allow what you want to allow
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED                             0x0001
// Allowed all permissions if not blocked them. Be careful with this mode
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED                             0x0002
// All permissions are temprorary frozen
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN                              0x0003
// Unfrozen permissions
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN                            0x0004

// Blocked all permissions, usefull issue it by default and then allow what you want to allow
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED                             0x0011
// Allowed all permissions if not blocked them. Be careful with this mode
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED                             0x0012
// All permissions are temprorary frozen
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN                              0x0013
// Unfrozen permissions
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN                            0x0014

//  Maximal flag
#define DAP_CHAIN_DATUM_TOKEN_FLAG_MAX                                     0x0014

#define DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED                               0xffff

extern const char *c_dap_chain_datum_token_flag_str[];

#define dap_chain_datum_token_flag_to_str(a) (if (a<=DAP_CHAIN_DATUM_TOKEN_FLAG_MAX) c_dap_chain_datum_token_flag_str[a]; else "OUT_OF_RANGE")

/**
 * @brief dap_chain_datum_token_flag_from_str
 * @param a_str
 * @return
 */
static inline uint16_t dap_chain_datum_token_flag_from_str(const char* a_str)
{
    if (a_str == NULL)
        return DAP_CHAIN_DATUM_TOKEN_FLAG_NONE;

    for (uint16_t i = DAP_CHAIN_DATUM_TOKEN_FLAG_NONE; i <=DAP_CHAIN_DATUM_TOKEN_FLAG_MAX; i++ ){
        if ( strcmp( a_str, c_dap_chain_datum_token_flag_str[i]) == 0 )
            return i;
    }
    return DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED;
}

/// ------ Static configured flags
// No token manipulations after declarations at all. Token declares staticly and can't variabed after
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_ALL                              0x0010

// No token manipulations after declarations with flags.
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_FLAGS                            0x0011

// No all permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_ALL                  0x0012

// No datum type permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_DATUM_TYPE           0x0013

// No tx sender permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_SENDER            0x0014

// No tx receiver permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_RECEIVER          0x0015

/// -------- General tsd types ----
// Flags set/unsed
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS           0x0001
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS         0x0002

// Total supply limits
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY        0x0003

// Set total signs count value to set to be valid
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID   0x0004

// Remove owner signature by pkey fingerprint
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_REMOVE  0x0005

// Add owner signature's pkey fingerprint
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_ADD     0x0006




/// ------- Permissions list flags, grouped by update-remove-clear operations --------
// Blocked datum types list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD          0x0007
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE       0x0008
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_CLEAR        0x0009


// Allowed datum types list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD          0x0010
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE       0x0011
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_CLEAR        0x0012


//Allowed tx receiver addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD          0x0014
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE       0x0015
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_CLEAR        0x0016

//Blocked tx receiver addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD          0x0017
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE       0x0018
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_CLEAR        0x0019


//Allowed tx sender addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD          0x0020
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE       0x0021
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_CLEAR        0x0022

//Blocked tx sender addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD          0x0023
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE       0x0024
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_CLEAR        0x0025

#define DAP_CHAIN_DATUM_NONCE_SIZE                                    64

struct DAP_ALIGN_PACKED dap_chain_emission_header_v0 {
    uint8_t version;
    uint8_t type; // Emission Type
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_addr_t address; // Emission holder's address
    uint64_t value;
};

// Token emission
typedef struct dap_chain_datum_token_emission{
    struct  {
        uint8_t version;
        uint8_t type; // Emission Type
        char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        dap_chain_addr_t address; // Emission holder's address
        union {
            uint64_t value;
            uint256_t value256;
        };
        uint8_t nonce[DAP_CHAIN_DATUM_NONCE_SIZE];
    } DAP_ALIGN_PACKED hdr;
    union {
        struct {
            dap_chain_addr_t addr;
            int flags;
            uint64_t lock_time;
        } DAP_ALIGN_PACKED type_presale;
        struct {
            uint64_t value_start;// Default value. Static if nothing else is defined
            char value_change_algo_codename[32];
        } DAP_ALIGN_PACKED type_atom_owner;
        struct {
            char codename[32];
        } DAP_ALIGN_PACKED type_algo;
        struct {
            uint16_t signs_count;
            byte_t  signs[];
        } DAP_ALIGN_PACKED type_auth;// Signs if exists
    } data;
} DAP_ALIGN_PACKED dap_chain_datum_token_emission_t;

// Different emissions type
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED         0x00
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH              0x01
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO              0x02
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER        0x03
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT    0x04
extern const char *c_dap_chain_datum_token_emission_type_str[];

/// TDS op funcs
///

dap_tsd_t* dap_chain_datum_token_tsd_get(dap_chain_datum_token_t * a_token,  size_t a_token_size);
void dap_chain_datum_token_flags_dump(dap_string_t * a_str_out, uint16_t a_flags);
void dap_chain_datum_token_certs_dump(dap_string_t * a_str_out, byte_t * a_data_n_tsd, size_t a_certs_size);
dap_sign_t ** dap_chain_datum_token_simple_signs_parse(dap_chain_datum_token_t * a_datum_token, size_t a_datum_token_size, size_t *a_signs_count, size_t * a_signs_valid);
dap_chain_datum_token_emission_t *dap_chain_datum_emission_read(byte_t *a_emission_serial, size_t *a_emission_size);
size_t dap_chain_datum_emission_get_size(uint8_t *a_emission_serial);
