#pragma once

#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_datum_tx.h"
#include "dap_tsd.h"

typedef struct dap_chain_tx_tsd {
    struct {
        dap_chain_tx_item_type_t type;
        size_t size;
    } header;
    byte_t tsd[];
} DAP_ALIGN_PACKED dap_chain_tx_tsd_t;
