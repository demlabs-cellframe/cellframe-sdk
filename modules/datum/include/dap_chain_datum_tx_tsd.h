#pragma once

#include <stddef.h>
#include "dap_common.h"
#include "dap_serialize.h"
#include "dap_chain_common.h"
#include "dap_tsd.h"

#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TICKER         0xf001
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TX_HASH        0xf002
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_PKEY_HASH      0xf003
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_EVENT_DATA     0xf004
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_TRACKER        0xf0fa
#define DAP_CHAIN_DATUM_TX_TSD_TYPE_HARDFORK_VOTING_HASH    0xf0fe

typedef struct dap_chain_tx_tsd {
    struct {
        dap_chain_tx_item_type_t type;
        uint64_t size DAP_ALIGNED(8);
    } DAP_PACKED header;
    byte_t tsd[];
} DAP_PACKED dap_chain_tx_tsd_t;

/** Wire size of @ref dap_chain_tx_tsd_t::header (packed; FAM @c tsd not included). */
#define DAP_CHAIN_TX_TSD_HDR_WIRE_SIZE sizeof(((dap_chain_tx_tsd_t *)0)->header)
_Static_assert(DAP_CHAIN_TX_TSD_HDR_WIRE_SIZE == 16, "dap_chain_tx_tsd_t header wire layout");

#define DAP_CHAIN_TX_TSD_HDR_SERIALIZE_MAGIC 0xCF5FEEDDU

/**
 * @brief Naturally aligned layout matching the on-wire @ref dap_chain_tx_tsd_t::header field sequence.
 */
typedef struct dap_chain_tx_tsd_hdr_mem {
    dap_chain_tx_item_type_t type;
    uint8_t wire_pad_before_size[7];
    uint64_t size;
} dap_chain_tx_tsd_hdr_mem_t;

extern const dap_serialize_field_t g_dap_chain_tx_tsd_hdr_fields[];
extern const size_t g_dap_chain_tx_tsd_hdr_field_count;
extern const dap_serialize_schema_t g_dap_chain_tx_tsd_hdr_schema;

static inline int dap_chain_tx_tsd_hdr_pack(const dap_chain_tx_tsd_hdr_mem_t *a_mem, uint8_t *a_wire, size_t a_wire_size)
{
    if (!a_mem || !a_wire || a_wire_size < DAP_CHAIN_TX_TSD_HDR_WIRE_SIZE)
        return -1;
    dap_serialize_result_t l_r = dap_serialize_to_buffer_raw(
        &g_dap_chain_tx_tsd_hdr_schema, a_mem, a_wire, a_wire_size, NULL);
    return l_r.error_code;
}

static inline int dap_chain_tx_tsd_hdr_unpack(const uint8_t *a_wire, size_t a_wire_size, dap_chain_tx_tsd_hdr_mem_t *a_mem)
{
    if (!a_wire || !a_mem || a_wire_size < DAP_CHAIN_TX_TSD_HDR_WIRE_SIZE)
        return -1;
    dap_deserialize_result_t l_r = dap_deserialize_from_buffer_raw(
        &g_dap_chain_tx_tsd_hdr_schema, a_wire, a_wire_size, a_mem, NULL);
    return l_r.error_code;
}

