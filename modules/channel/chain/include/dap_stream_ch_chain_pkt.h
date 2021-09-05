/*
 * Authors:
 * Dmitriy A. Gearasimov <gerasimov.dmitriy@demlabs.net>
 * DeM Labs Inc.   https://demlabs.net
 * Kelvin Project https://github.com/kelvinblockchain
 * Copyright  (c) 2017-2018
 * All rights reserved.

 This file is part of DAP (Deus Applications Prototypes) the open source project

    DAP (Deus Applicaions Prototypes) is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    DAP is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with any DAP based project.  If not, see <http://www.gnu.org/licenses/>.
**/
#pragma once

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>

#include "dap_common.h"
#include "dap_proc_thread.h"
#include "dap_chain_common.h"
#include "dap_chain_datum.h"
#include "dap_chain_cs.h"

#include "dap_stream_ch.h"

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN                     0x01
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB                 0x11

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_CHAIN               0x20
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB           0x21
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_FIRST_GLOBAL_DB_GROUP     0x31

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS               0x02
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB            0x12
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_ALL                  0x22

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS             0x03
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB          0x13
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL                0x23
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB_GROUP    0x33

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS_RVRS          0x04
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB_RVRS       0x14


#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_REQ         0x05
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_TSD         0x15
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_START       0x25
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS             0x35
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_CHAINS_END         0x45

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_REQ      0x06
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_TSD      0x16
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_START    0x26
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB          0x36
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_GLOBAL_DB_END      0x46

#define DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR                     0xff

// TSD sections
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_TSD_PROTO        0x0001   // Protocol version
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_TSD_COUNT        0x0002   // Items count
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_TSD_HASH_LAST    0x0003   // Hash of last(s) item
#define DAP_STREAM_CH_CHAIN_PKT_TYPE_UPDATE_TSD_HASH_FIRST   0x0004   // Hash of first(s) item

typedef enum dap_stream_ch_chain_state{
    CHAIN_STATE_IDLE=0,
    CHAIN_STATE_UPDATE_GLOBAL_DB_REMOTE, // Downloadn GDB hashtable from remote
    CHAIN_STATE_UPDATE_GLOBAL_DB, // Update GDB hashtable to remote
    CHAIN_STATE_SYNC_GLOBAL_DB,
    CHAIN_STATE_UPDATE_CHAINS_REMOTE, // Update chains hashtable from remote
    CHAIN_STATE_UPDATE_CHAINS, // Update chains hashtable to remote
    CHAIN_STATE_SYNC_CHAINS,
    CHAIN_STATE_SYNC_ALL
} dap_stream_ch_chain_state_t;


typedef struct dap_stream_ch_chain_update_element{
    dap_hash_fast_t hash;
    uint32_t size;
} DAP_ALIGN_PACKED dap_stream_ch_chain_update_element_t;

typedef struct dap_stream_ch_chain_sync_request{
    dap_chain_node_addr_t node_addr; // Requesting node's address
    dap_chain_hash_fast_t hash_from;
    dap_chain_hash_fast_t hash_to;   // unused
    uint64_t id_start;
    uint64_t id_end;                 // unused
} DAP_ALIGN_PACKED dap_stream_ch_chain_sync_request_t;


typedef struct dap_stream_ch_chain_pkt_hdr{
    union{
        struct{
            uint8_t version;
            uint8_t padding[7];
        } DAP_ALIGN_PACKED;
        uint64_t ext_id;
    }DAP_ALIGN_PACKED;
    dap_chain_net_id_t net_id;
    dap_chain_id_t chain_id;
    dap_chain_cell_id_t cell_id;
}  DAP_ALIGN_PACKED dap_stream_ch_chain_pkt_hdr_t;

typedef struct dap_stream_ch_chain_pkt{
    dap_stream_ch_chain_pkt_hdr_t hdr;
    uint8_t data[];
} DAP_ALIGN_PACKED dap_stream_ch_chain_pkt_t;

static const char* c_dap_stream_ch_chain_pkt_type_str[]={
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_CHAIN",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_GLOBAL_DB",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_CHAINS",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_GLOBAL_DB",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_ALL] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNC_ALL",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_CHAINS",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_GLOBAL_DB",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_SYNCED_ALL",
    [DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR] = "DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR"

};

dap_stream_ch_chain_state_t dap_stream_ch_chain_pkt_type_to_dap_stream_ch_chain_state(char a_state);

size_t dap_stream_ch_chain_pkt_write_unsafe(dap_stream_ch_t *a_ch, uint8_t a_type, uint64_t a_net_id,
                                            uint64_t a_chain_id, uint64_t a_cell_id,
                                            const void * a_data, size_t a_data_size);

size_t dap_stream_ch_chain_pkt_write_mt(dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type, uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size);

size_t dap_stream_ch_chain_pkt_write_inter(dap_proc_thread_t * a_thread, dap_stream_worker_t *a_worker, dap_stream_ch_uuid_t a_ch_uuid, uint8_t a_type,uint64_t a_net_id,
                                        uint64_t a_chain_id, uint64_t a_cell_id,
                                        const void * a_data, size_t a_data_size);

/**
 * @brief dap_stream_ch_chain_pkt_write_error_unsafe
 * @param a_ch
 * @param a_net_id
 * @param a_chain_id
 * @param a_cell_id
 * @param a_err_string_format
 * @return
 */
inline static size_t dap_stream_ch_chain_pkt_write_error_unsafe(dap_stream_ch_t *a_ch, uint64_t a_net_id,
                                                  uint64_t a_chain_id, uint64_t a_cell_id, const char * a_err_string_format,... )
{
    va_list l_va;
    char * l_str;
    va_start(l_va, a_err_string_format);
    int l_size = vsnprintf(NULL,0,a_err_string_format,l_va);
    if(l_size >0){
        l_size++;
        l_str = DAP_NEW_S_SIZE(char, l_size);
        vsnprintf(l_str,l_size,a_err_string_format,l_va);
        va_end(l_va);
        return  dap_stream_ch_chain_pkt_write_unsafe( a_ch, DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR, a_net_id, a_chain_id, a_cell_id, l_str,l_size );
    }else{
        va_end(l_va);
        return 0;
    }
}

/**
 * @brief dap_stream_ch_chain_pkt_write_error_inter
 * @param a_thread
 * @param a_stream_worker
 * @param a_ch
 * @param a_net_id
 * @param a_chain_id
 * @param a_cell_id
 * @param a_err_string_format
 * @return
 */
inline static size_t dap_stream_ch_chain_pkt_write_error_inter(dap_proc_thread_t * a_thread, dap_stream_worker_t * a_stream_worker,  dap_stream_ch_uuid_t a_ch_uuid,
                                                               uint64_t a_net_id, uint64_t a_chain_id, uint64_t a_cell_id, const char * a_err_string_format,... )
{
    va_list l_va;
    char * l_str;
    va_start(l_va, a_err_string_format);
    int l_size = vsnprintf(NULL,0,a_err_string_format,l_va);
    if(l_size >0){
        l_size++;
        l_str = DAP_NEW_S_SIZE(char, l_size);
        vsnprintf(l_str,l_size,a_err_string_format,l_va);
        va_end(l_va);
        return  dap_stream_ch_chain_pkt_write_inter(a_thread, a_stream_worker, a_ch_uuid, DAP_STREAM_CH_CHAIN_PKT_TYPE_ERROR, a_net_id, a_chain_id, a_cell_id, l_str,l_size );
    }else{
        va_end(l_va);
        return 0;
    }
}
