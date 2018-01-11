#ifndef _DAP_CHAIN_BLOCK_ROOTS_H_
#define _DAP_CHAIN_BLOCK_ROOTS_H_

#include "dap_common.h"
#include "dap_chain_common.h"

/**
  * @struct dap_chain_block_roots_v1
  * @brief Hash tree roots for block, version 1
  */
typedef struct dap_chain_block_roots_v1{
    dap_chain_hash_t main;
} DAP_ALIGN_PACKED dap_chain_block_roots_v1_t;

/**
  * @struct dap_chain_block_roots_v2
  * @brief Hash tree roots for block, version 2
  */
typedef struct dap_chain_block_roots_v2{
    dap_chain_hash_t main;
    dap_chain_hash_t txs;
} DAP_ALIGN_PACKED dap_chain_block_roots_v2_t;

typedef dap_chain_block_roots_v2_t dap_chain_block_roots_t;

#endif

