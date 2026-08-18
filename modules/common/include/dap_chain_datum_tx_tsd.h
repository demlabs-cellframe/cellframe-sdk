#pragma once

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_tsd.h"

/**
 * @brief TSD types for transaction metadata
 * @note TX TSD types (0x00A0-0x00FF) reserved for transaction-level metadata
 *       to avoid conflicts with token TSD (0x0001-0x002F) and voting TSD (0x01-0x09)
 */
#define DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE                     0x00A1  ///< Arbitrage transaction marker
#define DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE_LOCK                0x00A2  ///< Arbitrage lock: stores unlock pubkey hash (root node)

typedef struct dap_chain_tx_tsd {
    struct {
        dap_chain_tx_item_type_t type;
        uint64_t size DAP_ALIGNED(8);
    } DAP_PACKED header;
    byte_t tsd[];
} DAP_PACKED dap_chain_tx_tsd_t;

