/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Ltd   https://demlabs.net
 * Copyright  (c) 2017
 * All rights reserved.

 This file is part of DAP SDK the open source project

    DAP SDK is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP SDK is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP SDK based project.  If not, see <http://www.gnu.org/licenses/>.
*/
#pragma once
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_hash.h"
#include "dap_cert.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_datum_hashtree_roots.h"

#define DAP_CHAIN_BLOCK_SIGNATURE 0xDA05BF8E
#define DAP_CHAIN_BLOCK_ID_SIZE 4


typedef union dap_chain_block_typeid{
    uint8_t data[DAP_CHAIN_BLOCK_ID_SIZE];
} DAP_ALIGN_PACKED dap_chain_block_typeid_t;

/**
  * @struct dap_chain_block_hdr
  * @brief Block header
  */
typedef struct dap_chain_block_hdr{
    uint32_t signature; /// @param signature @brief Magic number, always equels to DAP_CHAIN_BLOCK_SIGNATURE
    int32_t version; /// @param version @brief block version (be carefull, signed value, as Bitcoin has)
    dap_chain_cell_id_t cell_id; /// Cell id
    dap_chain_id_t chain_id; /// Chain id
    dap_chain_time_t ts_created; /// @param timestamp @brief Block create time timestamp
    uint16_t meta_count; // Meta values number
    uint16_t datum_count; // Datums's count
    dap_chain_hash_fast_t merkle;
    uint32_t meta_n_datum_n_signs_size; // Meta&Datum&Signs section size
} DAP_ALIGN_PACKED dap_chain_block_hdr_t;

// Metadata item
typedef struct dap_chain_block_meta{
    struct {
        uint8_t type; /// Meta type
        uint16_t data_size;   /// Data size trailing the section
    } DAP_ALIGN_PACKED hdr;
    byte_t data[]; /// Section's data
} DAP_ALIGN_PACKED dap_chain_block_meta_t;

// Block metadata types

#define DAP_CHAIN_BLOCK_META_GENESIS           0x01
#define DAP_CHAIN_BLOCK_META_PREV              0x10
#define DAP_CHAIN_BLOCK_META_ANCHOR            0x11
#define DAP_CHAIN_BLOCK_META_LINK              0x12
#define DAP_CHAIN_BLOCK_META_NONCE             0x20
#define DAP_CHAIN_BLOCK_META_NONCE2            0x21
#define DAP_CHAIN_BLOCK_META_MERKLE            0x30


/**
 * @struct dap_chain_block
 * @brief The dap_chain_block struct
 */
typedef struct  dap_chain_block{
    dap_chain_block_hdr_t hdr;
    uint8_t meta_n_datum_n_sign[]; // Here are: metadata, datum sections and verificator signatures
} DAP_ALIGN_PACKED dap_chain_block_t;

// Init module
int dap_chain_block_init();
// Deinit module
void dap_chain_block_deinit();

// Create new block
dap_chain_block_t *dap_chain_block_new(dap_chain_hash_fast_t *a_prev_block, size_t *a_block_size);

// Add metadata in block
size_t dap_chain_block_meta_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, uint8_t a_meta_type, const void * a_data, size_t a_data_size);

// Add datum in block
size_t dap_chain_block_datum_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_chain_datum_t * a_datum, size_t a_datum_size);
size_t dap_chain_block_datum_del_by_hash(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_chain_hash_fast_t* a_datum_hash);

// Add sign in block
size_t dap_chain_block_sign_add(dap_chain_block_t ** a_block_ptr, size_t a_block_size, dap_enc_key_t *a_key);
dap_sign_t *dap_chain_block_sign_get ( dap_chain_block_t * a_block_ptr, size_t a_block_size, uint16_t a_sign_num );
size_t dap_chain_block_get_signs_count(dap_chain_block_t * a_block, size_t a_block_size);
size_t dap_chain_block_get_sign_offset(dap_chain_block_t *a_block, size_t a_block_size);

// Create and return datums list
dap_chain_datum_t** dap_chain_block_get_datums(dap_chain_block_t * a_block, size_t a_block_size,size_t * a_datums_count );

// Create and return meta parameters  list
dap_chain_block_meta_t** dap_chain_block_get_meta(dap_chain_block_t * a_block, size_t a_block_size,size_t * a_meta_count );

void dap_chain_block_meta_extract(dap_chain_block_meta_t ** a_meta, size_t a_meta_count,
                                    dap_chain_hash_fast_t * a_block_prev_hash,
                                    dap_chain_hash_fast_t * a_block_anchor_hash,
                                    dap_chain_hash_fast_t *a_merkle,
                                    dap_chain_hash_fast_t ** a_block_links,
                                    size_t *a_block_links_count,
                                    bool * a_is_genesis,
                                    uint64_t *a_nonce,
                                    uint64_t *a_nonce2
                                  );

