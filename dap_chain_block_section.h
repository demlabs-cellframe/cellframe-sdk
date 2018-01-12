/**
  * @struct dap_chain_block_section
  * @brief section inside the block
  */
#ifndef _DAP_CHAIN_BLOCK_SECTION_H_
#define  _DAP_CHAIN_BLOCK_SECTION_H_
#include <stdint.h>
#include "dap_common.h"
#include "dap_math_ops.h"
#include "dap_chain_common.h"

/// First section that must be in any block, with hash tree roots
#define DAP_CHAIN_BLOCK_SECTION_ROOTS 0xffff

/// End section, means all the rest of the block is empty
#define DAP_CHAIN_BLOCK_SECTION_END 0x0000

/// Transaction section
#define DAP_CHAIN_BLOCK_SECTION_TX 0x0100

/// Smart contract: EVM code section
#define DAP_CHAIN_BLOCK_SECTION_EVM_CODE 0x0200

/// Smart contract: EVM data section
#define DAP_CHAIN_BLOCK_SECTION_EVM_DATA 0x0201

/// Public key
#define DAP_CHAIN_BLOCK_SECTION_PKEY 0x0300

/// Coin: gold
#define DAP_CHAIN_BLOCK_SECTION_COIN_GOLD 0xff00

/// Coin: copper
#define DAP_CHAIN_BLOCK_SECTION_COIN_COPPER 0xff01

/// Coin: silver
#define DAP_CHAIN_BLOCK_SECTION_COIN_SILVER 0xff02


typedef struct dap_chain_block_section{
    struct{
        uint16_t type; // Section type
        uint32_t size; // section size
    } header;
    uint8_t data[]; // data
} DAP_ALIGN_PACKED dap_chain_block_section_t;

#endif
