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
#include "json_object.h"


#define DAP_CHAIN_DATUM_NONCE_SIZE                                          64
// Token declaration
typedef struct dap_chain_datum_token_old {
    uint16_t type;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint16_t signs_valid; // Emission auth signs
    uint256_t total_supply;
    union {
        // Simple token declaration. Useful for 100% premined emission without any plays with token and owners after that
        struct {
             uint16_t decimals;
        } DAP_ALIGN_PACKED header_simple;
        // Private token declarations, with flags, manipulations and updates
        struct {
            uint16_t flags; // Token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_private_decl;
        //native tokens
        struct {
            uint16_t flags; // Token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_native_decl;
        // Private token update
        struct {
            uint16_t flags; // Token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_private_update;
        // native token update
        struct {
            uint16_t flags; // Token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_native_update;
        // Public token declaration
        struct {
            uint32_t flags;
            uint256_t premine_supply;
            dap_chain_addr_t premine_address;
        } DAP_ALIGN_PACKED header_public;
        byte_t header[256]; // For future changes
    };
    uint16_t signs_total; // Emission auth signs
    byte_t tsd_n_signs[]; // Signs and/or types-size-data sections
} DAP_ALIGN_PACKED dap_chain_datum_token_old_t;

// Token declaration
typedef struct dap_chain_datum_token {
    uint16_t type;
    uint16_t version;
    uint16_t subtype;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    uint16_t signs_valid; // Emission auth signs
    uint16_t signs_total; // Emission auth signs
    uint256_t total_supply;
    union {
        // Simple token declaration. Useful for 100% premined emission without any plays with token and owners after that
        struct {
             uint16_t decimals;
        } DAP_ALIGN_PACKED header_simple;
        // Private token declarations, with flags, manipulations and updates
        struct {
            uint16_t flags; // Token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_private_decl;
        //native tokens
        struct {
            uint16_t flags; // Token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_native_decl;
        // Private token update
        struct {
            uint16_t padding; // OLD token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_private_update;
        // native token update
        struct {
            uint16_t padding; // OLD Token declaration flags
            uint64_t tsd_total_size; // Data size section with values in key-length-value list trailing the signs section
            uint16_t decimals;
        } DAP_ALIGN_PACKED header_native_update;
        // Public token declaration
        struct {
            uint32_t flags;
            uint256_t premine_supply;
            dap_chain_addr_t premine_address;
        } DAP_ALIGN_PACKED header_public;
        byte_t header[192]; // For future changes
    };
    uint8_t nonce[DAP_CHAIN_DATUM_NONCE_SIZE];
    byte_t tsd_n_signs[]; // Signs and/or types-size-data sections
} DAP_ALIGN_PACKED dap_chain_datum_token_t;

typedef struct dap_chain_datum_token_tsd_delegate_from_stake_lock {
    byte_t      ticker_token_from[DAP_CHAIN_TICKER_SIZE_MAX];
    uint256_t   emission_rate;  // In "coins", 1^18 == 1.0
    byte_t      padding[4];     // Some free space for future
} DAP_ALIGN_PACKED dap_chain_datum_token_tsd_delegate_from_stake_lock_t;

// Old token declaration & update types
// Simple private token decl
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE               0x0005
// Extended declaration of privatetoken with in-time control
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL         0x0006
// Token update
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE       0x0007
// Open token with no ownership
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC               0x0008
// Native token type
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL          0x0009
// Token update
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE        0x000A


// New datum types with versioning and subtypes.
// Declaration token
#define DAP_CHAIN_DATUM_TOKEN_TYPE_DECL                     0x0010
// Updated token
#define DAP_CHAIN_DATUM_TOKEN_TYPE_UPDATE                   0x0011
// Subtypes
// Simple private token decl
#define DAP_CHAIN_DATUM_TOKEN_SUBTYPE_SIMPLE                0x0001
// Extended declaration of privatetoken with in-time control
#define DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PRIVATE               0x0002
// Native token
#define DAP_CHAIN_DATUM_TOKEN_SUBTYPE_NATIVE                0x0003
// Open token with no ownership
#define DAP_CHAIN_DATUM_TOKEN_SUBTYPE_PUBLIC                0x0004


// Macros for token flags
/// ------- Global section flags --------
// No any flags
#define DAP_CHAIN_DATUM_TOKEN_FLAG_NONE                                     0x0000
// Blocked all permissions, usefull issue it by default and then allow what you want to allow
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED                       BIT(1)
// Allowed all permissions if not blocked them. Be careful with this mode
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED                       BIT(2)
// All permissions are temprorary frozen
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN                        BIT(3)
// Unfrozen permissions
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN                      BIT(4)

// Blocked all permissions, usefull issue it by default and then allow what you want to allow
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED                     BIT(5)
// Allowed all permissions if not blocked them. Be careful with this mode
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED                     BIT(6)
// All permissions are temprorary frozen
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN                      BIT(7)
// Unfrozen permissions
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN                    BIT(8)

/// ------ Static configured flags
// No token manipulations after declarations at all. Token declares staticly and can't variabed after
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_ALL                               BIT(9)

// No token manipulations after declarations with flags.
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_FLAGS                             BIT(10)

// No all permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_ALL                   BIT(11)

// No datum type permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_DATUM_TYPE            BIT(12)

// No tx sender permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_SENDER             BIT(13)

// No tx receiver permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_RECEIVER           BIT(14)

//  Maximal flag
#define DAP_CHAIN_DATUM_TOKEN_FLAG_MAX                                      BIT(15)

#define DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED                                0xffff

DAP_STATIC_INLINE const char *dap_chain_datum_token_flag_to_str(uint32_t a_flag)
{
    switch (a_flag) {
    case DAP_CHAIN_DATUM_TOKEN_FLAG_NONE: return "NONE";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED: return "ALL_SENDER_BLOCKED";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED: return "ALL_SENDER_ALLOWED";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN: return "ALL_SENDER_FROZEN";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN: return "ALL_SENDER_UNFROZEN";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED: return "ALL_RECEIVER_BLOCKED";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED: return "ALL_RECEIVER_ALLOWED";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN: return "ALL_RECEIVER_FROZEN";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN: return "ALL_RECEIVER_UNFROZEN";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_ALL: return "STATIC_ALL";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_FLAGS: return "STATIC_FLAGS";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_ALL: return "STATIC_PERMISSIONS_ALL";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_DATUM_TYPE: return "STATIC_PERMISSIONS_DATUM_TYPE";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_SENDER: return "TATIC_PERMISSIONS_TX_SENDER";
    case DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_RECEIVER: return "STATIC_PERMISSIONS_TX_RECEIVER";
    default: return "UNKNOWN FLAG OR FLAGS GROUP";
    }
}

uint32_t dap_chain_datum_token_flag_from_str(const char *a_str);

/// -------- General tsd types ----
// Flags set/unsed
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS                            0x0001
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS                          0x0002

// Total supply limit
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY                         0x0026

// Set total signs count value to set to be valid
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SIGNS_VALID                    0x0004

// Remove owner signature by pkey fingerprint
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_REMOVE                   0x0005

// Add owner signature's pkey fingerprint
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_PKEYS_ADD                      0x0006

// Emission for delegated token
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DELEGATE_EMISSION_FROM_STAKE_LOCK	0x0027

// Description token
#define DAP_CHAIN_DATUM_TOKEN_TSD_TOKEN_DESCRIPTION                         0x0028

/// ------- Permissions list flags, grouped by update-remove-clear operations --------
// Blocked datum types list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_ADD               0x0007
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_REMOVE            0x0008
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_BLOCKED_CLEAR             0x0009


// Allowed datum types list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_ADD               0x0010
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_REMOVE            0x0011
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_DATUM_TYPE_ALLOWED_CLEAR             0x0012


//Allowed tx receiver addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_ADD              0x0014
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_REMOVE           0x0015
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_ALLOWED_CLEAR            0x0016

//Blocked tx receiver addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_ADD              0x0017
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_REMOVE           0x0018
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_RECEIVER_BLOCKED_CLEAR            0x0019


//Allowed tx sender addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_ADD                0x0020
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_REMOVE             0x0021
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_ALLOWED_CLEAR              0x0022

//Blocked tx sender addres list add, remove or clear
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_ADD                0x0023
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_REMOVE             0x0024
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TX_SENDER_BLOCKED_CLEAR              0x0025


// Get delegated ticker
DAP_STATIC_INLINE int dap_chain_datum_token_get_delegated_ticker(char *a_buf, const char *a_ticker)
{
    if (!a_buf || !a_ticker)
        return -1;
    *a_buf = 'm';
    dap_strncpy(a_buf + 1, a_ticker, DAP_CHAIN_TICKER_SIZE_MAX - 1);
    return 0;
}

DAP_STATIC_INLINE bool dap_chain_datum_token_is_old(uint8_t a_type)
{
    return a_type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE
           || a_type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL
           || a_type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE
           || a_type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_DECL
           || a_type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_NATIVE_UPDATE
           || a_type == DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC;
}

/*                              Token emission section                          */

struct DAP_ALIGN_PACKED dap_chain_emission_header_v0 {
    uint8_t version;
    uint8_t type; // Emission Type
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    dap_chain_addr_t address; // Emission holder's address
    uint64_t value;
};

// Token emission
typedef struct dap_chain_datum_token_emission {
    struct  {
        uint8_t version;
        uint8_t type;               // Emission Type
        char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
        dap_chain_addr_t address;   // Emission holder's address
        union {
            uint64_t value64;       // Deprecated
            uint256_t value;
        } DAP_ALIGN_PACKED;
        uint8_t nonce[DAP_CHAIN_DATUM_NONCE_SIZE];
    } DAP_ALIGN_PACKED hdr;
    union {
        struct {
            dap_chain_addr_t addr;
            int flags;
            uint64_t lock_time;
        } DAP_ALIGN_PACKED type_presale;
        struct {
            uint64_t value_start;   // Default value. Static if nothing else is defined
            char value_change_algo_codename[32];
        } DAP_ALIGN_PACKED type_atom_owner;
        struct {
            char codename[32];
        } DAP_ALIGN_PACKED type_algo;
        struct {
            uint64_t tsd_n_signs_size;
            uint64_t tsd_total_size;
            uint16_t signs_count;
        } DAP_ALIGN_PACKED type_auth;
        byte_t free_space[128];     // For future changes
    } DAP_ALIGN_PACKED data;
    byte_t tsd_n_signs[];           // TSD sections and signs if any
} DAP_ALIGN_PACKED dap_chain_datum_token_emission_t;

// Different emissions type
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED         0x00
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH              0x01
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO              0x02
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER        0x03
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT    0x04

// TSD sections with emission additional params for AUTH type
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_UNKNOWN           0x0000
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_TIMESTAMP         0x0001
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_ADDRESS           0x0002
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_VALUE             0x0003
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_CONTRACT          0x0004
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_NET_ID            0x0005
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_BLOCK_NUM         0x0006
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_TOKEN_SYM         0x0007
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_OUTER_TX_HASH     0x0008
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_SOURCE            0x0009
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_SOURCE_SUBTYPE    0x000A
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_DATA              0x000B
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_SENDER            0x000C
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_TOKEN_ADDRESS     0x000D
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_SIGNATURS         0x000E
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_UNIQUE_ID         0x000F
#define DAP_CHAIN_DATUM_EMISSION_TSD_TYPE_BASE_TX_HASH      0x0010

#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_STAKING "STAKING"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_STAKING_STAKE_CROSSCHAIN "CONTRACT"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_STAKING_STAKE_CROSSCHAINV2 "CONTRACT_NFT"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_STAKING_HARVEST "HARVEST"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_STAKING_ADDLIQ "ADDLIQ"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_STAKING_EMSFIX "EMSFIX"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_STAKING_BONUS "BONUS"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_STAKING_UNSTAKE_FINALIZATION "UNSTAKE"

#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_BRIDGE "BRIDGE"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_TRANSFER "TO_WALLET"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_COMMISSION_OLD "COMISSION"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_COMMISSION "COMMISSION"
#define DAP_CHAIN_DATUM_TOKEN_EMISSION_SOURCE_SUBTYPE_BRIDGE_CROSSCHAIN "CROSSCHAIN"

DAP_STATIC_INLINE const char *dap_chain_datum_emission_type_str(uint8_t a_type)
{
    switch (a_type) {
    case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_AUTH: return "AUTH";
    case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ALGO: return "ALGO";
    case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_ATOM_OWNER: return "OWNER";
    case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_SMART_CONTRACT: return "SMART_CONTRACT";
    case DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_UNDEFINED:
    default: return "UNDEFINED";
    }
}

/// TDS op funcs
dap_tsd_t* dap_chain_datum_token_tsd_get(dap_chain_datum_token_t * a_token,  size_t a_token_size);
void dap_chain_datum_token_flags_dump_to_json(json_object * json_obj_out, const char *a_key, uint16_t a_flags);
void dap_chain_datum_token_certs_dump(dap_string_t * a_str_out, byte_t * a_tsd_n_signs, size_t a_certs_size, const char *a_hash_out_type);
void dap_chain_datum_token_certs_dump_to_json(json_object *a_json_obj_out, byte_t * a_tsd_n_signs, size_t a_certs_size, const char *a_hash_out_type);
dap_chain_datum_token_t *dap_chain_datum_token_read(const byte_t *a_token_serial, size_t *a_token_size);

dap_chain_datum_token_emission_t *dap_chain_datum_emission_create(uint256_t a_value, const char *a_ticker, dap_chain_addr_t *a_addr);
dap_chain_datum_token_emission_t *dap_chain_datum_emission_add_tsd(dap_chain_datum_token_emission_t *a_emission, int a_type, size_t a_size, void *a_data);
byte_t *dap_chain_emission_get_tsd(dap_chain_datum_token_emission_t *a_emission, int a_type, size_t *a_size);
dap_chain_datum_token_emission_t *dap_chain_datum_emission_read(byte_t *a_emission_serial, size_t *a_emission_size);
size_t dap_chain_datum_emission_get_size(uint8_t *a_emission_serial);
dap_chain_datum_token_emission_t *dap_chain_datum_emission_add_sign(dap_enc_key_t *a_sign_key, dap_chain_datum_token_emission_t *a_emission);
dap_chain_datum_token_emission_t *dap_chain_datum_emission_append_sign(dap_sign_t  *a_sign, dap_chain_datum_token_emission_t *a_emission);

dap_sign_t *dap_chain_datum_emission_get_signs(dap_chain_datum_token_emission_t *a_emission, size_t *a_signs_count);
// 256 TYPE
bool dap_chain_datum_token_is_old(uint8_t a_type);
