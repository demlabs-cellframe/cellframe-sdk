#ifndef _DAP_CHAIN_BLOCK_ROOTS_H_
#define _DAP_CHAIN_BLOCK_ROOTS_H_

#include "dap_common.h"
#include "dap_chain_common.h"

/**
  * @struct dap_chain_block_roots
  * @brief Hash tree roots for block
  */
typedef struct dap_chain_block_roots{
    dap_chain_hash_t main;
    dap_chain_hash_t txs;
    dap_chain_hash_t txs_pending;
    dap_chain_hash_t txs_requests;
    dap_chain_hash_t contract_code;
    dap_chain_hash_t contract_data;
} DAP_ALIGN_PACKED dap_chain_block_roots_t;

#endif

