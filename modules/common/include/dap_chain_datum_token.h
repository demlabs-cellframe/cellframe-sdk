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
typedef struct dap_chain_datum_token_old {
    uint16_t type;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    union {
        struct {
            uint64_t total_supply;
            uint16_t signs_valid;
            uint16_t signs_total;
        } DAP_ALIGN_PACKED header_private;
        struct {
            uint16_t flags;
            size_t tsd_total_size;
        } DAP_ALIGN_PACKED header_private_decl;
        struct {
            uint16_t padding;
            size_t tsd_total_size;
        } DAP_ALIGN_PACKED header_private_update;
        struct {
            uint128_t total_supply;
            uint128_t premine_supply;
            dap_chain_addr_t premine_address;
            uint32_t flags;
        } DAP_ALIGN_PACKED header_public;
    };
    byte_t data_n_tsd[];
} DAP_ALIGN_PACKED dap_chain_datum_token_old_t;


// Token declaration
typedef struct dap_chain_datum_token{
    uint16_t type;
    char ticker[DAP_CHAIN_TICKER_SIZE_MAX];
    union {
        // Simple private token declaration. Useful for 100% premined emission without any plays with token and owners after that
        struct {
            union {
                uint64_t total_supply; // Could be zero if unlimited
                uint256_t total_supply_256;
            };
            union {
                uint64_t current_supply; // Could be zero if unlimited
                uint256_t current_supply_256;
            };
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
            union {
                uint128_t total_supply;
                uint256_t total_supply_256;
            };
            union {
                uint128_t premine_supply;
                uint256_t premine_supply_256;
            };
            dap_chain_addr_t premine_address;
            uint32_t flags;
        } DAP_ALIGN_PACKED header_public;
        byte_t free_space[256]; // For future changes
    };
    byte_t data_n_tsd[]; // Signs and/or types-size-data sections
} DAP_ALIGN_PACKED dap_chain_datum_token_t;

// Token declaration type
// Simple private token decl
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_SIMPLE           0x0001
// Extended declaration of privatetoken with in-time control
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_DECL     0x0002
// Token update
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PRIVATE_UPDATE   0x0003
// Open token with now ownership
#define DAP_CHAIN_DATUM_TOKEN_TYPE_OLD_PUBLIC           0x0004

// 256
// Simple private token decl
#define DAP_CHAIN_DATUM_TOKEN_TYPE_SIMPLE               0x0005
// Extended declaration of privatetoken with in-time control
#define DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_DECL         0x0006
// Token update
#define DAP_CHAIN_DATUM_TOKEN_TYPE_PRIVATE_UPDATE       0x0007
// Open token with now ownership
#define DAP_CHAIN_DATUM_TOKEN_TYPE_PUBLIC               0x0008


// Macros for token flags
/// ------- Global section flags --------
// No any flags
#define DAP_CHAIN_DATUM_TOKEN_FLAG_NONE                                           0x0000
// Blocked all permissions, usefull issue it by default and then allow what you want to allow
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED                             1 << 1
// Allowed all permissions if not blocked them. Be careful with this mode
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED                             1 << 2
// All permissions are temprorary frozen
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN                              1 << 3
// Unfrozen permissions
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN                            1 << 4

// Blocked all permissions, usefull issue it by default and then allow what you want to allow
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED                             1 << 5
// Allowed all permissions if not blocked them. Be careful with this mode
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED                             1 << 6
// All permissions are temprorary frozen
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN                              1 << 7
// Unfrozen permissions
#define DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN                            1 << 8

/// ------ Static configured flags
// No token manipulations after declarations at all. Token declares staticly and can't variabed after
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_ALL                              1 << 9

// No token manipulations after declarations with flags.
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_FLAGS                            1 << 10

// No all permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_ALL                  1 << 11

// No datum type permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_DATUM_TYPE           1 << 12

// No tx sender permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_SENDER            1 << 13

// No tx receiver permissions lists manipulations after declarations
#define DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_RECEIVER          1 << 14

//  Maximal flag
#define DAP_CHAIN_DATUM_TOKEN_FLAG_MAX                                     1 << 15

#define DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED                               0xffff

extern const char *c_dap_chain_datum_token_flag_str[];

#define dap_chain_datum_token_flag_to_str(a) ((a<=DAP_CHAIN_DATUM_TOKEN_FLAG_MAX) ? c_dap_chain_datum_token_flag_str[a] : "OUT_OF_RANGE")


// /**
//  * @brief dap_chain_datum_token_flag_from_str
//  * @param a_str
//  * @return
//  */
// static inline uint16_t dap_chain_datum_token_flag_from_str(const char* a_str)
// {
//     if (a_str == NULL)
//         return DAP_CHAIN_DATUM_TOKEN_FLAG_NONE;

//     for (uint16_t i = DAP_CHAIN_DATUM_TOKEN_FLAG_NONE; i <=DAP_CHAIN_DATUM_TOKEN_FLAG_MAX; i++ ){
//         if ( strcmp( a_str, c_dap_chain_datum_token_flag_str[i]) == 0 )
//             return i;
//     }
//     return DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED;
// }

/// -------- General tsd types ----
// Flags set/unsed
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_SET_FLAGS           0x0001
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_UNSET_FLAGS         0x0002

// Total supply limits
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY        0x0003 // 128
#define DAP_CHAIN_DATUM_TOKEN_TSD_TYPE_TOTAL_SUPPLY_256    0x0026 // 256

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

typedef struct { char *key; uint64_t val; } t_datum_token_flag_struct;

// new__
static t_datum_token_flag_struct s_flags_table[] = {
    { "NO_FLAGS", DAP_CHAIN_DATUM_TOKEN_FLAG_NONE}, 
    { "ALL_BLOCKED", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED}, 
    { "ALL_FROZEN", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN }, 
    { "ALL_ALLOWED", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED},
    { "ALL_UNFROZEN", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN | DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN }, 
    { "STATIC_ALL", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_ALL},
    { "STATIC_FLAGS", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_FLAGS }, 
    { "STATIC_PERMISSIONS_ALL", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_ALL }, 
    { "STATIC_PERMISSIONS_DATUM_TYPE", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_DATUM_TYPE }, 
    { "STATIC_PERMISSIONS_TX_SENDER", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_SENDER },
    { "STATIC_PERMISSIONS_TX_RECEIVER", DAP_CHAIN_DATUM_TOKEN_FLAG_STATIC_PERMISSIONS_TX_RECEIVER },
    { "ALL_SENDER_BLOCKED", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_BLOCKED}, 
    { "ALL_SENDER_FROZEN", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_FROZEN}, 
    { "ALL_SENDER_ALLOWED", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_ALLOWED},
    { "ALL_SENDER_UNFROZEN", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_SENDER_UNFROZEN}, 
    { "ALL_RECEIVER_BLOCKED", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_BLOCKED}, 
    { "ALL_RECEIVER_FROZEN", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_FROZEN }, 
    { "ALL_RECEIVER_ALLOWED", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_ALLOWED},
    { "ALL_RECEIVER_UNFROZEN", DAP_CHAIN_DATUM_TOKEN_FLAG_ALL_RECEIVER_UNFROZEN }, 
};


#define NKEYS (sizeof(s_flags_table)/sizeof(t_datum_token_flag_struct))

static inline int s_flag_code_from_str(const char *key)
{
    uint64_t i;
    for (i=0; i < NKEYS; i++) {
        t_datum_token_flag_struct sym = s_flags_table[i];
        if (strcmp(s_flags_table[i].key, key) == 0)
            return s_flags_table[i].val;
    }

    return DAP_CHAIN_DATUM_TOKEN_FLAG_UNDEFINED;
}

static inline char* s_flag_str_from_code(uint64_t code)
{
    uint64_t i;
    uint64_t flags_count = 0;

    for (i=0; i < NKEYS; i++) {
        t_datum_token_flag_struct sym = s_flags_table[i];
        if (s_flags_table[i].val == code)
            return s_flags_table[i].key;
    }

    // split multiple flags in string

    char* s_multiple_flag = "";

    for (i=0; i < NKEYS; i++) {
        t_datum_token_flag_struct sym = s_flags_table[i];
        if ((s_flags_table[i].val & code) > 0)
        {
            flags_count += 1;
            if (flags_count > 1)
                s_multiple_flag = dap_strjoin(";", s_multiple_flag, s_flags_table[i].key, (char*)NULL);
            else
                s_multiple_flag = dap_strjoin(NULL, s_multiple_flag, s_flags_table[i].key, (char*)NULL);
        }         
    }

    char* s_no_flags = "NO FLAGS";

    if (flags_count > 0)
        return s_multiple_flag;
    else
        return s_no_flags;
}

/**
 * @brief dap_chain_datum_token_flag_from_str
 * @param a_str
 * @return
 */
static inline char* dap_chain_datum_str_token_flag_from_code(uint64_t code)
{   
    return s_flag_str_from_code(code);
}

/**
 * @brief dap_chain_datum_token_flag_from_str
 * @param a_str
 * @return
 */
static inline uint16_t dap_chain_datum_token_flag_from_str(const char* a_str)
{
    if (a_str == NULL)
        return DAP_CHAIN_DATUM_TOKEN_FLAG_NONE;
    
    return s_flag_code_from_str(a_str);
}

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
            uint256_t value_256;
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
// 256
// #define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_UNDEFINED         0x05
// #define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_AUTH              0x06
// #define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_ALGO              0x07
// #define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_ATOM_OWNER        0x08
// #define DAP_CHAIN_DATUM_TOKEN_EMISSION_TYPE_256_SMART_CONTRACT    0x09
extern const char *c_dap_chain_datum_token_emission_type_str[];

/// TDS op funcs
dap_tsd_t* dap_chain_datum_token_tsd_get(dap_chain_datum_token_t * a_token,  size_t a_token_size);
void dap_chain_datum_token_flags_dump(dap_string_t * a_str_out, uint16_t a_flags);
void dap_chain_datum_token_certs_dump(dap_string_t * a_str_out, byte_t * a_data_n_tsd, size_t a_certs_size);
dap_sign_t ** dap_chain_datum_token_simple_signs_parse(dap_chain_datum_token_t * a_datum_token, size_t a_datum_token_size, size_t *a_signs_count, size_t * a_signs_valid);
dap_chain_datum_token_t *dap_chain_datum_token_read(byte_t *a_token_serial, size_t *a_token_size);
dap_chain_datum_token_emission_t *dap_chain_datum_emission_read(byte_t *a_emission_serial, size_t *a_emission_size);
size_t dap_chain_datum_emission_get_size(uint8_t *a_emission_serial);

// 256 TYPE
bool dap_chain_datum_token_is_old(uint8_t a_type);
