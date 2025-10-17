#pragma once

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_tsd.h"

/**
 * @brief TSD types for transaction metadata
 */
#define DAP_CHAIN_TX_TSD_TYPE_ARBITRAGE                     0x0001  ///< Arbitrage transaction marker

typedef struct dap_chain_tx_tsd {
    struct {
        dap_chain_tx_item_type_t type;
        uint64_t size DAP_ALIGNED(8);
    } DAP_PACKED header;
    byte_t tsd[];
} DAP_PACKED dap_chain_tx_tsd_t;

