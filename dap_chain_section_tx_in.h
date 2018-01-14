#pragma once

#include <stdint.h>
#include "dap_common.h"
#include "dap_chain_common.h"
#include "dap_chain_section_tx.h"
/**
  * @struct dap_chain_tx_item
  * @brief Sections belongs to heading tx section, with inputs, outputs and others tx relatated items
  */

typedef struct dap_chain_tx_in{
    struct {
        dap_chain_tx_item_type_t type:8; /// @param    type            @brief Transaction item type
        dap_chain_hash_t tx_prev_hash; /// @param tx_prev_hash    @brief Hash of the previous transaction
        uint32_t tx_out_prev_idx; ///      @param   tx_prev_idx     @brief Previous tx_out index
        dap_chain_sig_type_t sig_type:16; /// Signature type
        uint32_t sig_size; /// Signature size
    } header; /// Only header's hash is used for verification
    uint32_t seq_no; /// Sequence number, out of the header so could be changed during reorganization
    uint8_t sig[]; /// @param sig @brief raw signatura dat
} DAP_ALIGN_PACKED dap_chain_tx_in_t;
