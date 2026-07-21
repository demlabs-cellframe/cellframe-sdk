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

#pragma once

#include <stddef.h>
#include "dap_cert.h"
#include "dap_cert_file.h"
#include "dap_chain_common.h"
#include "dap_chain_wallet.h"
#include "dap_serialize.h"

#define DAP_CHAIN_WALLETS_FILE_SIGNATURE (uint64_t)0x1a167bef15feea18


enum    {
    DAP_WALLET$K_TYPE_PLAIN              = 0,                               /* 0x00 - uncompressed and unencrypted */
    DAP_WALLET$K_TYPE_GOST89             = 1,                               /* Encrypted with the GOST 89 (V1/V2 legacy) */
    DAP_WALLET$K_TYPE_CHACHA20_POLY1305  = 2,                               /* Encrypted with ChaCha20-Poly1305 AEAD (V3) */
};

enum    {
    DAP_WALLET$K_VER_1 = 1,                                                 /* Unprotected / legacy insecure password */
    DAP_WALLET$K_VER_2 = 2,                                                 /* Protected: GOST + raw password (master-compatible) */
    DAP_WALLET$K_VER_3 = 3,                                                 /* Protected: ChaCha20-Poly1305 AEAD + SHA3-256(password||salt(wallet_name)) */
};


enum    {
    DAP_WALLET$K_CERT = 1,                                                  /* Cert record type */
    DAP_WALLET$K_MAGIC = 2,                                                 /* Record is magic sequence */
};


typedef struct dap_chain_wallet_n_pass {
    uint16_t    name_len;                                                   /* Length of the follows wallet's name string */
    char        name[DAP_WALLET$SZ_NAME + 1];
    uint16_t    pass_len;                                                   /* Length of the follows wallet's password string */
    char        pass[DAP_WALLET$SZ_PASS + 1];

    struct timespec exptm;                                                  /* A time of expiration of the record
                                                                              need RE-Activation steps */

    dap_ht_handle_t hh;
} dap_chain_wallet_n_pass_t;

/*
 * Cert record prefix on disk (8 bytes LE): uint32 type | uint32 cert_raw_size.
 * Two uint32 are naturally 8B with or without packing — one type for wire + memory.
 */
typedef struct dap_chain_wallet_cert_hdr {
    uint32_t type;                                                          /* See DAP_WALLET$K_CERT/MAGIC ...constants */
    uint32_t cert_raw_size;                                                 /* Certificate size */
} dap_chain_wallet_cert_hdr_t;
_Static_assert(sizeof(dap_chain_wallet_cert_hdr_t) == 8,
               "wallet cert_hdr size must stay 8 bytes");

typedef struct dap_chain_wallet_cert {
    dap_chain_wallet_cert_hdr_t header;
    dap_cert_file_t cert_raw;                                               /* Raw certs data */
} dap_chain_wallet_cert_t;

/*
 * Wallet file fixed prefix on disk (23 bytes LE), then name[name_len], then certs:
 *   uint64 signature | uint32 version | uint8 type | uint64 padding | uint16 name_len
 *
 * Runtime I/O uses dap_serialize on dap_chain_wallet_t:
 *   signature/padding — FLAG_CONST (wire only);
 *   version/type/name_len — fields of dap_chain_wallet_t.
 * Unpack does not memset the wallet (partial schema into a live object).
 */
#define DAP_CHAIN_WALLET_FILE_FIXED_WIRE_SIZE \
    (sizeof(uint64_t) + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint64_t) + sizeof(uint16_t))
_Static_assert(DAP_CHAIN_WALLET_FILE_FIXED_WIRE_SIZE == 23,
               "wallet file fixed wire size must stay 23 bytes");

#define DAP_CHAIN_WALLET_FILE_FIXED_MAGIC 0xCF5FF028U
#define DAP_CHAIN_WALLET_CERT_HDR_MAGIC       0xCF5CCE78U
#define DAP_CHAIN_WALLET_CERT_HDR_WIRE_SIZE   sizeof(dap_chain_wallet_cert_hdr_t)

/* Backward-compatible aliases */
#define DAP_CHAIN_WALLET_FILE_HDR_FIXED_WIRE_SIZE DAP_CHAIN_WALLET_FILE_FIXED_WIRE_SIZE
#define DAP_CHAIN_WALLET_FILE_HDR_FIXED_MAGIC     DAP_CHAIN_WALLET_FILE_FIXED_MAGIC

extern const dap_serialize_field_t g_dap_chain_wallet_file_fields[];
extern const dap_serialize_schema_t g_dap_chain_wallet_file_schema;
extern const dap_serialize_field_t g_dap_chain_wallet_cert_hdr_fields[];
extern const dap_serialize_schema_t g_dap_chain_wallet_cert_hdr_schema;

static inline int dap_chain_wallet_file_pack(const dap_chain_wallet_t *a_wallet,
                                             uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_wallet || a_wire_size < DAP_CHAIN_WALLET_FILE_FIXED_WIRE_SIZE) return -1;
    dap_serialize_result_t r = dap_serialize_to_buffer_raw(
        &g_dap_chain_wallet_file_schema, a_wallet, a_wire, a_wire_size, NULL);
    return r.error_code;
}
static inline int dap_chain_wallet_file_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                               dap_chain_wallet_t *a_wallet)
{
    if (!a_wallet || a_wire_size < DAP_CHAIN_WALLET_FILE_FIXED_WIRE_SIZE) return -1;
    /* raw = no memset: only version/type/name_len are written; CONST verifies sig/pad */
    dap_deserialize_result_t r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_wallet_file_schema, a_wire, a_wire_size, a_wallet, NULL);
    return r.error_code;
}
static inline int dap_chain_wallet_cert_hdr_pack(const dap_chain_wallet_cert_hdr_t *a_hdr,
                                                 uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_hdr || a_wire_size < DAP_CHAIN_WALLET_CERT_HDR_WIRE_SIZE) return -1;
    dap_serialize_result_t r = dap_serialize_to_buffer_raw(
        &g_dap_chain_wallet_cert_hdr_schema, a_hdr, a_wire, a_wire_size, NULL);
    return r.error_code;
}
static inline int dap_chain_wallet_cert_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size,
                                                   dap_chain_wallet_cert_hdr_t *a_hdr)
{
    if (!a_hdr || a_wire_size < DAP_CHAIN_WALLET_CERT_HDR_WIRE_SIZE) return -1;
    dap_deserialize_result_t r = dap_deserialize_from_buffer_raw_zero(
        &g_dap_chain_wallet_cert_hdr_schema, a_wire, a_wire_size, a_hdr, NULL);
    return r.error_code;
}

typedef struct dap_chain_wallet_internal
{
                char    file_name[MAX_PATH];
                size_t  certs_count;
            dap_cert_t  **certs;
} dap_chain_wallet_internal_t;

#define DAP_CHAIN_WALLET_INTERNAL(a) (a ? (dap_chain_wallet_internal_t *) a->_internal : NULL)
#define DAP_CHAIN_WALLET_INTERNAL_LOCAL(a) dap_chain_wallet_internal_t * l_wallet_internal = DAP_CHAIN_WALLET_INTERNAL(a)
#define DAP_CHAIN_WALLET_INTERNAL_LOCAL_NEW(a) dap_chain_wallet_internal_t * l_wallet_internal = DAP_NEW_Z(dap_chain_wallet_internal_t); a->_internal = l_wallet_internal
